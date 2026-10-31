// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/ldap/schema"
	"github.com/hashicorp/hcl/v2"
)

// testdataPath is a committed file, as an HCL string can hold it.
func testdataPath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return hclPath(p)
}

// exampleConfig is a site with both schema files, a schema block, and every
// case of a declared class: carried with its superclass (ann), left off for a
// missing MUST (ben), not declared at all (cat), and on a group (staff).
func exampleConfig(t *testing.T, extra string) string {
	return fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }

schema_files = [%q, %q]

schema {
  attribute_type "exampleLocker" {
    oid      = "1.3.6.1.4.1.99999.5.1"
    desc     = "a locker number"
    equality = "caseIgnoreMatch"
    syntax   = "1.3.6.1.4.1.1466.115.121.1.15"
  }
  object_class "exampleLockerHolder" {
    oid  = "1.3.6.1.4.1.99999.6.1"
    kind = "auxiliary"
    may  = ["exampleLocker"]
  }
}

user "ann" {
  password       = "x"
  object_classes = ["exampleStaff", "exampleLockerHolder", "exampleOccupant"]
  attributes = {
    sn                = "Ann"
    exampleEmployeeId = "E-1"
    exampleBadge      = "B-1"
    exampleLocker     = "L-7"
    exampleOffice     = "A-101"
  }
}
user "ben" {
  password       = "x"
  object_classes = ["exampleStaff"]
  attributes     = { exampleBadge = "B-2" }
}
user "cat" {
  password   = "x"
  attributes = { exampleBadge = "B-3" }
}
group "staff" {
  members        = ["ann", "ben"]
  object_classes = ["exampleGroup"]
  attributes     = { gidNumber = "100", exampleCampus = "Palaiseau" }
}
%s`, testdataPath(t, "example.schema"), testdataPath(t, "example.ldif"), extra)
}

// openBody loads a configuration and opens it, as startup and check do.
func openBody(t *testing.T, body string) (*server, error) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err != nil {
		return nil, err
	}
	srv, err := open(cfg, io.Discard)
	if srv != nil {
		t.Cleanup(func() { srv.Close() })
	}
	return srv, err
}

// lineOf is the 1-based line of the first occurrence of needle in body.
func lineOf(t *testing.T, body, needle string) int {
	t.Helper()
	i := strings.Index(body, needle)
	if i < 0 {
		t.Fatalf("%q is not in the configuration", needle)
	}
	return strings.Count(body[:i], "\n") + 1
}

func entryOf(t *testing.T, p publication, name string, group bool) *entry {
	t.Helper()
	for _, e := range p.all {
		if e.name == name && e.group == group {
			return e
		}
	}
	t.Fatalf("no entry for %s", name)
	return nil
}

func attrValues(e *entry, attr string) []string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, attr) {
			var out []string
			for _, v := range a.Values {
				out = append(out, string(v))
			}
			return out
		}
	}
	return nil
}

// The publication itself: who carries which declared class, with which
// superclasses, and what was kept and dropped because of it.
func TestDeclaredClassesArePublished(t *testing.T) {
	srv, err := openBody(t, exampleConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	p := srv.publish()

	// ann: exampleStaff brings examplePerson, its superclass, BEFORE it
	// (RFC 4512 §3.3), and every attribute those classes allow is kept.
	ann := entryOf(t, p, "ann", false)
	if ann.invalid != nil {
		t.Fatalf("ann is not published: %v", ann.invalid)
	}
	want := "top person organizationalPerson inetOrgPerson uidObject examplePerson exampleStaff exampleLockerHolder exampleOccupant"
	if got := strings.Join(attrValues(ann, "objectClass"), " "); got != want {
		t.Errorf("ann's objectClass is %q, want %q", got, want)
	}
	for _, a := range []string{"exampleEmployeeId", "exampleBadge", "exampleLocker", "exampleOffice"} {
		if attrValues(ann, a) == nil {
			t.Errorf("ann was published without %s, which a declared class allows", a)
		}
	}
	if len(ann.dropped) != 0 || len(ann.leftOff) != 0 {
		t.Errorf("ann lost something: dropped %v, left off %v", ann.dropped, ann.leftOff)
	}

	// ben: exampleStaff MUST exampleEmployeeId, which ben has not. He stays
	// published, without the class -- nor examplePerson, which only came with
	// it -- and his exampleBadge is then dropped like any attribute no class
	// of his allows. Both are said.
	ben := entryOf(t, p, "ben", false)
	if ben.invalid != nil {
		t.Fatalf("ben is not published: %v", ben.invalid)
	}
	if got := strings.Join(attrValues(ben, "objectClass"), " "); got != "top account uidObject" {
		t.Errorf("ben's objectClass is %q, want the class left off", got)
	}
	if len(ben.leftOff) != 1 || ben.leftOff[0].class != "exampleStaff" || strings.Join(ben.leftOff[0].missing, ",") != "exampleEmployeeId" {
		t.Errorf("ben's left-off classes: %+v", ben.leftOff)
	}
	if len(ben.dropped) != 1 || ben.dropped[0].name != "exampleBadge" {
		t.Errorf("ben's dropped attributes: %+v", ben.dropped)
	}

	// cat declares nothing: her exampleBadge is dropped, as before this
	// release. A class is never inferred from an attribute.
	cat := entryOf(t, p, "cat", false)
	if got := strings.Join(attrValues(cat, "objectClass"), " "); got != "top account uidObject" {
		t.Errorf("cat's objectClass is %q: a class was inferred from her attributes", got)
	}
	if len(cat.dropped) != 1 || cat.dropped[0].name != "exampleBadge" {
		t.Errorf("cat's dropped attributes: %+v", cat.dropped)
	}

	// The group carries its declared class beside posixGroup.
	staff := entryOf(t, p, "staff", true)
	if got := strings.Join(attrValues(staff, "objectClass"), " "); got != "top posixGroup exampleGroup" {
		t.Errorf("staff's objectClass is %q", got)
	}
	if attrValues(staff, "exampleCampus") == nil {
		t.Errorf("staff was published without exampleCampus")
	}
}

// What the site added is served at cn=Subschema, and the entries are read
// back by OpenLDAP's own client.
func TestDeclaredClassesSeenByLDAPSearch(t *testing.T) {
	bin := needLDAPSearch(t)
	r := start(t, exampleConfig(t, ""))

	out := readerSearch(t, bin, r, "-b", "cn=Subschema", "-s", "base", "(objectClass=subschema)", "*", "+")
	contains(t, out,
		"objectClasses: ( 1.3.6.1.4.1.99999.2.2 NAME 'exampleStaff'",
		"objectClasses: ( 1.3.6.1.4.1.99999.4.1 NAME 'exampleOccupant'",
		"objectClasses: ( 1.3.6.1.4.1.99999.6.1 NAME 'exampleLockerHolder'",
		"attributeTypes: ( 1.3.6.1.4.1.99999.1.1 NAME 'exampleBadge'",
	)

	out = readerSearch(t, bin, r, "-LLL", "-b", "ou=people,dc=example,dc=org", "(uid=ann)")
	contains(t, out, "objectClass: examplePerson", "objectClass: exampleStaff", "objectClass: exampleLockerHolder",
		"objectClass: exampleOccupant", "exampleEmployeeId: E-1", "exampleBadge: B-1", "exampleLocker: L-7", "exampleOffice: A-101")

	// A filter on a declared class finds who carries it, and nobody else.
	out = readerSearch(t, bin, r, "-b", "ou=people,dc=example,dc=org", "(objectClass=examplePerson)", "uid")
	contains(t, out, "uid: ann", "numEntries: 1")

	for _, who := range []string{"ben", "cat"} {
		out = readerSearch(t, bin, r, "-LLL", "-b", "ou=people,dc=example,dc=org", "(uid="+who+")")
		if strings.Contains(out, "exampleBadge") || strings.Contains(out, "examplePerson") {
			t.Errorf("%s was published with a class or an attribute nothing declares for them:\n%s", who, out)
		}
	}
	out = readerSearch(t, bin, r, "-LLL", "-b", "ou=groups,dc=example,dc=org", "(cn=staff)")
	contains(t, out, "objectClass: exampleGroup", "exampleCampus: Palaiseau")

	contains(t, r.out.String(),
		"schema: "+testdataPath(t, "example.schema")+" adds 3 object identifier macros, 3 attribute types and 5 object classes",
		"uid=ben,ou=people,dc=example,dc=org is published without exampleStaff, which its source declares: "+
			"uid=ben,ou=people,dc=example,dc=org has no exampleEmployeeId, which exampleStaff requires",
		"uid=ben,ou=people,dc=example,dc=org is published without exampleBadge: no class of the entry allows it; examplePerson and exampleStaff would",
	)
}

// check says what was loaded, what each source declares, and per person what
// was added, left off and dropped.
func TestCheckReportsSiteSchemas(t *testing.T) {
	dir := t.TempDir()
	body := exampleConfig(t, "")
	path := write(t, dir, "c.hcl", body)
	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	t.Log("\n" + out)
	contains(t, out,
		"schema: "+testdataPath(t, "example.schema")+" adds 3 object identifier macros, 3 attribute types and 5 object classes",
		"schema: "+testdataPath(t, "example.ldif")+" adds 1 attribute type and 1 object class",
		fmt.Sprintf("schema: the schema block at %s:%d:1 adds 1 attribute type and 1 object class: exampleLocker and exampleLockerHolder",
			path, lineOf(t, body, "schema {")),
		fmt.Sprintf("%s:%d:20: user \"ann\" declares exampleStaff, exampleLockerHolder and exampleOccupant for this person",
			path, lineOf(t, body, `object_classes = ["exampleStaff", "exampleLockerHolder"`)),
		fmt.Sprintf("group \"staff\" declares exampleGroup for this group"),
		"person, organizationalPerson, inetOrgPerson, uidObject, examplePerson, exampleStaff, exampleLockerHolder, exampleOccupant",
		"posixGroup, exampleGroup",
		"ben is published without exampleStaff, which its source declares: ben has no exampleEmployeeId, which exampleStaff requires",
		"ben is published without exampleBadge: no class of the entry allows it; examplePerson and exampleStaff would",
		"cat is published without exampleBadge: no class of the entry allows it; examplePerson and exampleStaff would",
		"this configuration can be served",
	)
}

// A declared class the schema refuses stops startup -- every one of them at
// once, each with its block, its position and why.
func TestADeclaredClassThatCannotBeDeclaredRefusesStartup(t *testing.T) {
	body := fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
schema_files = [%q]
user "a" {
  password       = "x"
  object_classes = ["exampleUnit"]
}
user "b" {
  password       = "x"
  object_classes = ["posixAccount"]
}
user "c" {
  password       = "x"
  object_classes = ["noSuchClass"]
}
user "d" {
  password       = "x"
  object_classes = ["exampleThing"]
}
group "g" {
  members        = ["a"]
  object_classes = ["UIDOBJECT"]
}
users "sql" {
  driver               = "sqlite"
  dsn_file             = "/nonexistent/dsn"
  users                = "select login from people"
  group_object_classes = ["groupOfNames"]
}
`, testdataPath(t, "example.schema"))
	_, err := openBody(t, body)
	if err == nil {
		t.Fatal("a configuration declaring structural, derived, unknown and abstract classes started")
	}
	msg := err.Error()
	for _, w := range []string{
		fmt.Sprintf("c.hcl:%d:20: user \"a\" object_classes: ", lineOf(t, body, `["exampleUnit"]`)),
		"exampleUnit is STRUCTURAL, and an entry has exactly one structural chain (RFC 4512 §2.4.2)",
		fmt.Sprintf("c.hcl:%d:20: user \"b\" object_classes: ", lineOf(t, body, `["posixAccount"]`)),
		"posixAccount is a class authnd derives itself",
		fmt.Sprintf("c.hcl:%d:20: user \"c\" object_classes: ", lineOf(t, body, `["noSuchClass"]`)),
		"the schema served here does not define noSuchClass",
		"exampleThing is ABSTRACT, which is only ever a superclass (RFC 4512 §2.4.1)",
		"group \"g\" object_classes: ",
		"UIDOBJECT is a class authnd derives itself",
		`users "sql" group_object_classes: `,
		"groupOfNames is a class authnd derives itself",
	} {
		if !strings.Contains(msg, w) {
			t.Errorf("the refusal does not say %q:\n%s", w, msg)
		}
	}
	// And `check` refuses the same way.
	dir := t.TempDir()
	if out, err := execute(t, "check", write(t, dir, "c.hcl", body)); err == nil || !strings.Contains(err.Error(), "exampleUnit is STRUCTURAL") {
		t.Errorf("check did not refuse: %v\n%s", err, out)
	}
}

// A class known only by another of its names is refused like the name
// authnd derives.
func TestADerivedClassUnderAnotherNameIsRefused(t *testing.T) {
	dir := t.TempDir()
	alias := write(t, dir, "alias.schema", "objectclass ( 1.3.6.1.4.1.99999.7.1 NAME 'exampleAlias' SUP top AUXILIARY )\n")
	srv, err := openBody(t, fmt.Sprintf("base_dn = \"dc=example,dc=org\"\nschema_files = [%q]\nuser \"a\" { password = \"x\" }\n", hclPath(alias)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.declarable("exampleAlias"); err != nil {
		t.Fatalf("exampleAlias: %v", err)
	}
	// A schema whose posixAccount has a second name: the name compares
	// false, the class it resolves to does not.
	srv.schema = mustBuild(t, "ldapsyntax ( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )\n"+
		"attributetype ( 2.5.4.0 NAME 'objectClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )\n"+
		"objectclass ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )\n"+
		"objectclass ( 1.3.6.1.1.1.2.0 NAME ( 'posixAccount' 'shadowlessAccount' ) SUP top AUXILIARY )\n")
	if _, err := srv.declarable("shadowlessAccount"); err == nil || !strings.Contains(err.Error(), "derives itself") {
		t.Errorf("another name of posixAccount was declarable: %v", err)
	}
}

func mustBuild(t *testing.T, extra string) *schema.Schema {
	t.Helper()
	d, err := schema.Read(schema.File{Name: "extra.schema", Data: []byte(extra)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := schema.BuildFrom(d)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The literal-only rule of hclschema holds inside authnd's configuration.
func TestASchemaBlockValueMustBeALiteral(t *testing.T) {
	for _, v := range []string{`"${var.x}"`, `"${"x"}"`, `"%{if true}x%{endif}"`, `upper("x")`} {
		body := fmt.Sprintf(`
base_dn = "dc=example,dc=org"
user "a" { password = "x" }
schema {
  attribute_type "exampleX" {
    oid    = "1.3.6.1.4.1.99999.8.1"
    desc   = %s
    syntax = "1.3.6.1.4.1.1466.115.121.1.15"
  }
}
`, v)
		_, err := openBody(t, body)
		want := fmt.Sprintf("c.hcl:%d:14: Not a literal", lineOf(t, body, "desc"))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("desc = %s: %v, want %q", v, err, want)
		}
	}
}

// writeSchema writes a schema file and gives back its path as HCL wants it.
func writeSchema(t *testing.T, dir, name, text string) string {
	t.Helper()
	return hclPath(write(t, dir, name, text))
}

// A schema file that does not build refuses startup, with the file and the
// line of the definition, for every way a build can fail.
func TestASchemaFileThatDoesNotBuildRefusesStartup(t *testing.T) {
	dir := t.TempDir()
	example := testdataPath(t, "example.schema")
	for _, c := range []struct {
		name, text string
		before     []string
		want       string
	}{
		{"unknown MAY", "# a comment\n\nattributetype ( 1.3.6.1.4.1.99999.9.1 NAME 'exampleA'\n  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n\n" +
			"objectclass ( 1.3.6.1.4.1.99999.9.2 NAME 'exampleB' SUP top AUXILIARY\n  MAY noSuchAttribute )\n",
			nil, ":6:1: the object class exampleB has MAY noSuchAttribute, which is not a defined attribute type (unknown reference)"},
		{"unknown superclass", "objectclass ( 1.3.6.1.4.1.99999.9.2 NAME 'exampleB' SUP noSuchClass AUXILIARY )\n",
			nil, ":1:1: the object class exampleB has the superclass noSuchClass, which is not defined (unknown reference)"},
		{"unknown syntax", "attributetype ( 1.3.6.1.4.1.99999.9.1 NAME 'exampleA' SYNTAX 1.2.3.4 )\n",
			nil, ":1:1: the attribute type exampleA has the syntax 1.2.3.4, which is not defined (unknown reference)"},
		{"unknown rule", "attributetype ( 1.3.6.1.4.1.99999.9.1 NAME 'exampleA' EQUALITY noSuchMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n",
			nil, ":1:1: the attribute type exampleA has the EQUALITY rule noSuchMatch, which is not defined (unknown reference)"},
		{"structural from auxiliary", "\n\nobjectclass ( 1.3.6.1.4.1.99999.9.2 NAME 'exampleB'\n SUP uidObject STRUCTURAL )\n",
			nil, ":3:1: the structural class exampleB derives from the auxiliary class uidObject (RFC 4512 2.4.2) (kind violation)"},
		{"rule with unknown syntax", "matchingrule ( 1.3.6.1.4.1.99999.9.3 NAME 'exampleMatch' SYNTAX 1.2.3.4 )\n",
			nil, ":1:1: the matching rule exampleMatch has the syntax 1.2.3.4, which is not defined (unknown reference)"},
		{"a usage mismatch", "attributetype ( 1.3.6.1.4.1.99999.9.1 NAME 'exampleA' SUP name USAGE dSAOperation )\n",
			nil, ":1:1: the attribute type exampleA is dSAOperation and its supertype name is userApplications (RFC 4512 2.5.1) (usage mismatch)"},
		{"a supertype cycle", "attributetype ( 1.3.6.1.4.1.99999.9.1 NAME 'exampleA' SUP exampleB )\nattributetype ( 1.3.6.1.4.1.99999.9.2 NAME 'exampleB' SUP exampleA )\n",
			nil, ":1:1: the attribute type exampleA is its own supertype (superior cycle)"},
		{"the same cn", "attributetype ( 2.5.4.3 NAME 'cn'\n\t   SUP name )\n",
			nil, ":1:1: the attribute type cn (2.5.4.3) is already defined by the standard schema (rfc4519.schema:42:1), and this is the same definition, word for word"},
		{"a different cn", "attributetype ( 2.5.4.3 NAME 'cn' SUP name SINGLE-VALUE )\n",
			nil, ":1:1: the attribute type cn (2.5.4.3) is already defined by the standard schema (rfc4519.schema:42:1), and this is a different definition"},
		{"cn under another OID", "attributetype ( 1.3.6.1.4.1.99999.9.1 NAME 'cn' SUP name )\n",
			nil, ":1:1: the attribute type cn (1.3.6.1.4.1.99999.9.1) is already defined by the standard schema (rfc4519.schema:42:1)"},
		{"the same class twice", "objectclass ( 1.3.6.1.4.1.99999.9.2 NAME 'exampleB' SUP top AUXILIARY )\n" +
			"objectclass ( 1.3.6.1.4.1.99999.9.2 NAME 'exampleC' SUP top AUXILIARY )\n",
			nil, ":2:1: the object class 1.3.6.1.4.1.99999.9.2 is defined twice (first defined at "},
		{"a name twice", "objectclass ( 1.3.6.1.4.1.99999.9.2 NAME 'exampleB' SUP top AUXILIARY )\n\n" +
			"objectclass ( 1.3.6.1.4.1.99999.9.3 NAME 'EXAMPLEB' SUP top AUXILIARY )\n",
			nil, ":3:1: the name \"EXAMPLEB\" is given to two object classes (first defined at "},
		{"an earlier file's", "attributetype ( 1.3.6.1.4.1.99999.1.1 NAME 'exampleBadge' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n",
			[]string{example}, ":1:1: the attribute type exampleBadge (1.3.6.1.4.1.99999.1.1) is already defined by " + example + ":"},
		{"a syntax", "ldapsyntax ( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'again' )\n",
			nil, ":1:1: the syntax 1.3.6.1.4.1.1466.115.121.1.15 (1.3.6.1.4.1.1466.115.121.1.15) is already defined by the standard schema (rfc4517.schema:"},
		{"a matching rule", "matchingrule ( 1.3.6.1.4.1.99999.9.3 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n",
			nil, ":1:1: the matching rule caseIgnoreMatch (1.3.6.1.4.1.99999.9.3) is already defined by the standard schema (rfc4517.schema:"},
		{"LDIF", "dn: cn=x,cn=schema,cn=config\nobjectClass: olcSchemaConfig\nolcObjectClasses: {0}( 1.3.6.1.4.1.99999.9.2 NAME 'exampleB'\n  SUP top AUXILIARY MAY noSuchAttribute )\n",
			nil, ":3:1: the object class exampleB has MAY noSuchAttribute"},
		{"CRLF and a joining backslash", "attributetype ( 1.3.6.1.4.1.99999.9.1 NAME 'exampleA' \\\r\nSYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\r\n\r\n" +
			"objectclass ( 1.3.6.1.4.1.99999.9.2 NAME 'exampleB'\r\n  SUP top AUXILIARY MAY nothingHere )\r\n",
			nil, ":4:1: the object class exampleB has MAY nothingHere"},
		{"a parse error", "attributetype ( 1.3.6.1.4.1.99999.9.1 NAME 'exampleA'\n  SYNTAX )\n",
			nil, ".schema:2:"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeSchema(t, dir, strings.ReplaceAll(c.name, " ", "-")+".schema", c.text)
			files := append(append([]string{}, c.before...), path)
			quoted := make([]string, len(files))
			for i, f := range files {
				quoted[i] = fmt.Sprintf("%q", f)
			}
			body := fmt.Sprintf("base_dn = \"dc=example,dc=org\"\nschema_files = [%s]\nuser \"a\" { password = \"x\" }\n", strings.Join(quoted, ", "))
			_, err := openBody(t, body)
			if err == nil {
				t.Fatalf("a schema file that does not build was loaded:\n%s", c.text)
			}
			want := c.want
			if strings.HasPrefix(want, ":") {
				want = path + want
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal reads\n  %v\nwant\n  %s", err, want)
			}
		})
	}
}

// With the samba block, Samba's definitions are part of what a file may not
// redefine -- a site loading Samba's whole samba.schema beside the block is
// told why it does not load.
func TestASchemaFileMayNotRedefineTheSambaBlocks(t *testing.T) {
	dir := t.TempDir()
	path := writeSchema(t, dir, "samba.schema", "attributetype ( 1.3.6.1.4.1.7165.2.1.20 NAME 'sambaSID'\n"+
		"  EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{64} SINGLE-VALUE )\n")
	_, err := openBody(t, fmt.Sprintf(`
listen          = "127.0.0.1:0"
base_dn         = "dc=example,dc=org"
publish_nt_hash = true
samba { domain_sid = "S-1-5-21-1-2-3" }
schema_files    = [%q]
user "a" { password = "x" }
`, path))
	want := path + ":1:1: the attribute type sambaSID (1.3.6.1.4.1.7165.2.1.20) is already defined by the standard schema, or samba.schema (the samba block)"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%v, want %q", err, want)
	}
}

// A schema file that is not a file, or too large, is refused before it is
// read through.
func TestSchemaFilesAreBounded(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.schema")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(schema.MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	ok := write(t, dir, "ok.schema", "# nothing\n")
	for _, c := range []struct{ path, want string }{
		{big, "more than the 4194304 bytes a schema file may have"},
		{dir, "is not a regular file"},
		{filepath.Join(dir, "missing.schema"), "missing.schema"},
	} {
		_, err := openBody(t, fmt.Sprintf("base_dn = \"dc=example,dc=org\"\nschema_files = [%q]\nuser \"a\" { password = \"x\" }\n", hclPath(c.path)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.path, err, c.want)
		}
	}
	// A small file is read whole.
	data, err := readSchemaFile(ok)
	if err != nil || string(data) != "# nothing\n" {
		t.Errorf("readSchemaFile(ok) = %q, %v", data, err)
	}
}

// A schema block that does not build names its own line in the
// configuration.
func TestASchemaBlockThatDoesNotBuildRefusesStartup(t *testing.T) {
	example := testdataPath(t, "example.schema")
	for _, c := range []struct{ name, block, needle, want string }{
		{"redefines a file's", `
  object_class "examplePerson" {
    oid  = "1.3.6.1.4.1.99999.2.1"
    kind = "auxiliary"
  }`, `object_class "examplePerson"`, "the object class examplePerson (1.3.6.1.4.1.99999.2.1) is already defined by " + example},
		{"unknown MAY", `
  object_class "exampleZ" {
    oid  = "1.3.6.1.4.1.99999.8.2"
    kind = "auxiliary"
    may  = ["noSuchAttribute"]
  }`, `object_class "exampleZ"`, "the object class exampleZ has MAY noSuchAttribute, which is not a defined attribute type"},
		{"labelled by OID", `
  ldap_syntax "1.3.6.1.4.1.1466.115.121.1.15" {
    desc = "again"
  }`, `ldap_syntax`, "the syntax 1.3.6.1.4.1.1466.115.121.1.15 (1.3.6.1.4.1.1466.115.121.1.15) is already defined by the standard schema"},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := fmt.Sprintf("base_dn = \"dc=example,dc=org\"\nschema_files = [%q]\nuser \"a\" { password = \"x\" }\nschema {%s\n}\n", example, c.block)
			_, err := openBody(t, body)
			want := fmt.Sprintf("c.hcl:%d:3: %s", lineOf(t, body, c.needle), c.want)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal reads\n  %v\nwant\n  %s", err, want)
			}
		})
	}
}

// Two schema blocks, in two files of one configuration directory, read as
// one: a macro the first defines is used by the second, and each block's
// errors carry its own file.
func TestSchemaBlocksAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.hcl", "base_dn = \"dc=example,dc=org\"\nuser \"a\" {\n  password = \"x\"\n  object_classes = [\"exampleMacroClass\"]\n}\n"+
		"schema {\n  object_identifier \"exampleArc\" {\n    oid = \"1.3.6.1.4.1.99999.10\"\n  }\n}\n")
	write(t, dir, "b.hcl", "# the second file\nschema {\n  object_class \"exampleMacroClass\" {\n    oid  = \"exampleArc:1\"\n    kind = \"auxiliary\"\n  }\n}\n")
	cfg, err := loadConfig([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if oc := srv.schema.ObjectClass("exampleMacroClass"); oc == nil || oc.OID != "1.3.6.1.4.1.99999.10.1" {
		t.Fatalf("the macro did not reach the second block: %+v", oc)
	}
	lines := strings.Join(srv.schemaLines(), "\n")
	contains(t, lines, "the schema block at "+filepath.Join(dir, "a.hcl")+":6:1 adds 1 object identifier macro",
		"the schema block at "+filepath.Join(dir, "b.hcl")+":2:1 adds 1 object class: exampleMacroClass")

	// A block not in HCL's native syntax, or whose text is not where the
	// parser put it, is refused rather than guessed at.
	cfg.sources = map[string][]byte{}
	if _, err := cfg.schemaBlockFiles(); err == nil || !strings.Contains(err.Error(), "not where the parser said") {
		t.Errorf("a schema block with no text: %v", err)
	}
	cfg.Schemas[0].Body = nil
	if _, err := cfg.schemaBlockFiles(); err == nil || !strings.Contains(err.Error(), "native syntax") {
		t.Errorf("a schema block that is not hclsyntax: %v", err)
	}
}

// check SAYS when two sources declare different classes for one group;
// go-authn/directory publishes the first and ignores the second, silently.
func TestCheckSaysWhenSourcesDisagreeOnAGroup(t *testing.T) {
	srv, err := openBody(t, exampleConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	same, _ := directory.NewObjectClasses("EXAMPLEGROUP")
	other, _ := directory.NewObjectClasses("exampleOccupant", "exampleGroup")
	srv.dir.Add(&directory.Static{Name: "the same list", Groups: map[string][]string{"staff": {"ann"}},
		GroupClasses: map[string]directory.ObjectClasses{"staff": same}})
	srv.dir.Add(&directory.Static{Name: "another list", Groups: map[string][]string{"staff": {"ann"}},
		GroupClasses: map[string]directory.ObjectClasses{"staff": other}})
	reread(t, srv)
	lines := srv.groupClassConflicts()
	if len(lines) != 1 {
		t.Fatalf("conflicts: %q, want one", lines)
	}
	contains(t, lines[0], "group staff: ", " declares exampleGroup and another list declares exampleOccupant and exampleGroup; "+
		"the first is published and the second is ignored")
	// And what is published is the first list.
	if e := entryOf(t, srv.publish(), "staff", true); strings.Join(e.declared, " ") != "exampleGroup" {
		t.Errorf("staff carries %v", e.declared)
	}
}

// The defence behind checkDeclared: a class no declaration named is left
// off, and said, rather than published unchecked.
func TestAClassNobodyCheckedIsLeftOff(t *testing.T) {
	srv, err := openBody(t, exampleConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	delete(srv.declared, "exampleoccupant")
	ann := entryOf(t, srv.publish(), "ann", false)
	if strings.Contains(strings.Join(ann.shape, " "), "exampleOccupant") {
		t.Errorf("a class nobody checked was published: %v", ann.shape)
	}
	contains(t, strings.Join(leftOffLines(ann, "ann"), "\n"), "ann is published without exampleOccupant: the class was not checked at startup")
}

// What a site file that does not build on the standard schema is refused
// with points at a line of the file that starts a record -- not a
// continuation, not a comment -- and that the operator can read from there:
// the file's definition read from that line on, alone, is the one refused.
// The line comes from go-authn/ldap's BuildError; this holds authnd's use of
// it, not ldap's reader (FuzzBuildErrorPosition there).
func FuzzSchemaFileRefusal(f *testing.F) {
	f.Add([]byte("attributetype ( 1.3.6.1.4.1.99999.9.1 NAME 'x'\n  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n" +
		"# c\nobjectclass ( 1.3.6.1.4.1.99999.9.2 NAME 'y' SUP top AUXILIARY MAY nope )\n"))
	f.Add([]byte("dn: cn=x\nolcAttributeTypes: {0}( 2.5.4.3 NAME 'x'\n  SUP name )\nolcObjectClasses: ( 1.1.2 NAME 'y' )\n"))
	f.Add([]byte("attributetype ( 1.1.1 NAME 'x' \\\r\nSYNTAX 1.1 )\r\n\r\nattributetype ( 1.1.2 NAME 'CN' SUP name )\r\n"))
	std, err := schema.Read(schema.StandardFiles()...)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<14 || strings.Contains(string(data), "objectidentifier") {
			return // a macro makes a suffix unreadable alone
		}
		file := schema.File{Name: "f", Data: data}
		d, err := schema.Read(file)
		if err != nil {
			return
		}
		_, err = schema.BuildFrom(std, d)
		var be *schema.BuildError
		if !errors.As(err, &be) {
			return
		}
		got := refusal(err, d, ownersOf(std, "the standard schema"), "f")
		lines := strings.Split(string(data), "\n")
		line := be.Pos.Line
		if line < 1 || line > len(lines) || !strings.HasPrefix(got, fmt.Sprintf("f:%d:1: ", line)) {
			t.Fatalf("refused at %q, outside the file's %d lines or not where the error is (%+v)", got, len(lines), be.Pos)
		}
		rest, err := schema.Read(schema.File{Name: "f", Data: []byte(strings.Join(lines[line-1:], "\n"))})
		if err != nil || definitionAt(rest, &schema.BuildError{Element: be.Element, OID: be.OID, Pos: schema.Position{File: "f", Line: 1, Column: 1}}) == nil {
			t.Fatalf("%q: the file read from line %d does not start with the definition refused (%v)", got, line, err)
		}
	})
}

// The pieces that only have one caller each, at their edges.
func TestSiteSchemaHelpers(t *testing.T) {
	if got := describeAddition(&schema.Definitions{}); got != "nothing" {
		t.Errorf("describeAddition of nothing = %q", got)
	}
	if got := position(hcl.Range{}); got != "?" {
		t.Errorf("position of no range = %q", got)
	}
	if (declaration{}).at() != "" {
		t.Error("a declaration with no range has a position")
	}
	for k, want := range map[string]string{"attribute type": "attributeType", "object class": "objectClass",
		"matching rule": "matchingRule", "syntax": "ldapSyntax"} {
		if got := slapdKind(k); got != want {
			t.Errorf("slapdKind(%q) = %q", k, got)
		}
	}
	// An error that is not a BuildError is said as it is.
	if got := refusal(fmt.Errorf("schema: something else"), &schema.Definitions{}, owners{}, "f"); got != "schema: something else" {
		t.Errorf("refusal = %q", got)
	}
	// A BuildError with no position -- definitions made in code -- is said
	// at the file or block it came from.
	_, err := schema.BuildFrom(&schema.Definitions{ObjectClasses: []*schema.ObjectClass{{OID: "1.1", Sup: []string{"x"}}}})
	if got, want := refusal(err, &schema.Definitions{}, owners{}, "the schema block at c.hcl:3:1"),
		"the schema block at c.hcl:3:1: the object class 1.1 has the superclass x, which is not defined (unknown reference)"; got != want {
		t.Errorf("refusal = %q, want %q", got, want)
	}
	// definitionAt finds nothing for an element or a position nothing has.
	d := &schema.Definitions{MatchingRules: []*schema.MatchingRule{{OID: "1.1"}}}
	for _, be := range []*schema.BuildError{{Element: 0, OID: "1.1"}, {Element: schema.ElementMatchingRule, OID: "1.1", Pos: schema.Position{Line: 2}}} {
		if got := definitionAt(d, be); got != nil {
			t.Errorf("definitionAt(%+v) = %v", be, got)
		}
	}
}
