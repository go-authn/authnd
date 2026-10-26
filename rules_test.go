// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-authn/ldap/schema"
)

// rulesConfig is a site that loads schemaFiles, with one person and one group
// for every way the rules of testdata/rules.schema shape an entry:
//
//	alice  an account: ldapPublicKey left off (not in AUX), description dropped (NOT)
//	bob    an inetOrgPerson with a telephone number: published as he is
//	carol  an inetOrgPerson without one: left out (the rule's MUST)
//	staff  a posixGroup: published
//	team   a groupOfNames (no gidNumber), which no structure rule places: left out
func rulesConfig(t *testing.T, base string, schemaFiles ...string) string {
	t.Helper()
	files := make([]string, len(schemaFiles))
	for i, f := range schemaFiles {
		files[i] = fmt.Sprintf("%q", f)
	}
	return fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = %q
reader "cn=reader,%s" { password = "let me read" }
schema_files = [%s]

user "alice" {
  password        = "x"
  authorized_keys = ["`+shapeKey+`"]
  attributes = {
    uidNumber     = "1000"
    gidNumber     = "100"
    homeDirectory = "/home/alice"
    description   = "kept out by the rule"
  }
}
user "bob" {
  password   = "x"
  attributes = { sn = "Bob", telephoneNumber = "+33 1 23 45 67 89" }
}
user "carol" {
  password   = "x"
  attributes = { sn = "Carol" }
}
group "staff" {
  members    = ["alice", "bob"]
  attributes = { gidNumber = "100" }
}
group "team" { members = ["bob"] }
`, base, base, strings.Join(files, ", "))
}

func publishedFor(t *testing.T, body string) publication {
	t.Helper()
	srv, err := openBody(t, body)
	if err != nil {
		t.Fatal(err)
	}
	return srv.publish()
}

// Each way a content rule and the structure rules shape an entry, against
// the same site without the rules: every difference is the rules' doing.
func TestTheRulesShapeEachEntry(t *testing.T) {
	rules := testdataPath(t, "rules.schema")
	with, without := publishedFor(t, rulesConfig(t, "dc=example,dc=org", rules)), publishedFor(t, rulesConfig(t, "dc=example,dc=org"))

	// alice: ldapPublicKey is not in exampleAccountRule's AUX. She is
	// published without it and without the sshPublicKey only it allowed;
	// her description, which the rule's NOT precludes, is dropped.
	alice := entryOf(t, with, "alice", false)
	if alice.invalid != nil {
		t.Fatalf("alice is not published: %v", alice.invalid)
	}
	if got := strings.Join(attrValues(alice, "objectClass"), " "); got != "top account posixAccount uidObject" {
		t.Errorf("alice's objectClass is %q", got)
	}
	if attrValues(alice, "sshPublicKey") != nil || attrValues(alice, "description") != nil {
		t.Errorf("alice kept what the rule refuses: %v", alice.Attributes)
	}
	if len(alice.leftOff) != 1 || alice.leftOff[0].class != "ldapPublicKey" || alice.leftOff[0].rule != "exampleAccountRule" {
		t.Errorf("alice's left-off classes: %+v", alice.leftOff)
	}
	if len(alice.dropped) != 1 || alice.dropped[0].name != "description" || !strings.Contains(alice.dropped[0].why, "exampleAccountRule precludes it") {
		t.Errorf("alice's dropped attributes: %+v", alice.dropped)
	}
	// The witness: without the rules she has both.
	if a := entryOf(t, without, "alice", false); attrValues(a, "sshPublicKey") == nil || attrValues(a, "description") == nil {
		t.Errorf("without the rules, alice is %v", a.Attributes)
	}

	if bob := entryOf(t, with, "bob", false); bob.invalid != nil || len(bob.leftOff)+len(bob.dropped) != 0 {
		t.Errorf("bob: %v %+v %+v", bob.invalid, bob.leftOff, bob.dropped)
	}

	// carol: examplePersonRule MUST telephoneNumber applies to the entry as a
	// whole -- no class to leave off -- so she is left out.
	carol := entryOf(t, with, "carol", false)
	var v *schema.ValidationError
	if carol.invalid == nil || !asValidation(carol.invalid, &v) || !v.Has(schema.MissingRequired) {
		t.Errorf("carol: %v", carol.invalid)
	}
	if entryOf(t, without, "carol", false).invalid != nil {
		t.Error("without the rules, carol is not published")
	}

	if e := entryOf(t, with, "staff", true); e.invalid != nil {
		t.Errorf("group staff: %v", e.invalid)
	}
	// team: a groupOfNames, which no structure rule places under ou=groups --
	// data (it has no gidNumber), so the group is left out and the server
	// starts.
	team := entryOf(t, with, "team", true)
	if team.invalid == nil || !asValidation(team.invalid, &v) || !v.Has(schema.NoStructureRule) ||
		!strings.Contains(team.invalid.Error(), "no active DIT structure rule has a name form for groupOfNames (X.501 13.7.5)") {
		t.Errorf("team: %v", team.invalid)
	}
	if entryOf(t, without, "team", true).invalid != nil {
		t.Error("without the rules, the team group is not published")
	}
}

func asValidation(err error, v **schema.ValidationError) bool {
	ve, ok := err.(*schema.ValidationError)
	*v = ve
	return ok
}

// What is left out and why is said by check, which still serves the rest.
func TestCheckSaysWhatTheRulesDid(t *testing.T) {
	path := write(t, t.TempDir(), "c.hcl", rulesConfig(t, "dc=example,dc=org", testdataPath(t, "rules.schema")))
	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	contains(t, out,
		"adds 2 DIT content rules, 5 name forms and 5 DIT structure rules",
		"alice is published without ldapPublicKey: the DIT content rule exampleAccountRule does not allow it (not in its AUX)",
		"alice is published without description: the DIT content rule exampleAccountRule precludes it (NOT)",
		"carol is NOT published",
		"telephoneNumber is required by the DIT content rule examplePersonRule and is missing",
		"group team is NOT published",
		"this configuration can be served",
	)
}

// A tree the structure rules do not allow refuses startup and check, naming
// the DN, the rule or name form and the clause -- every refusal at once.
func TestATreeTheStructureRulesRefuseDoesNotStart(t *testing.T) {
	const forms = `
nameform ( 1.3.6.1.4.1.99999.9.1 NAME 'domainForm' OC domain MUST dc )
nameform ( 1.3.6.1.4.1.99999.9.2 NAME 'unitForm' OC organizationalUnit MUST ou )
nameform ( 1.3.6.1.4.1.99999.9.3 NAME 'accountForm' OC account MUST uid )
nameform ( 1.3.6.1.4.1.99999.9.4 NAME 'accountByCN' OC account MUST cn )
nameform ( 1.3.6.1.4.1.99999.9.5 NAME 'groupForm' OC posixGroup MUST cn )
ditstructurerule ( 1 NAME 'suffix' FORM domainForm )
`
	for _, c := range []struct {
		name, base, rules string
		says              []string
	}{
		{"a container no rule places", "dc=example,dc=org",
			"ditstructurerule ( 2 NAME 'unitAtTheRoot' FORM unitForm )\n",
			[]string{"DIT structure rules: ou=people,dc=example,dc=org, where authnd publishes its people, as an organizationalUnit: " +
				"no DIT structure rule allows organizationalUnit under an entry governed by the rule suffix (X.501 13.7.5)",
				"DIT structure rules: ou=groups,dc=example,dc=org, where authnd publishes its groups"}},
		{"a suffix of a class no rule names", "o=example",
			"ditstructurerule ( 2 FORM unitForm SUP 1 )\n",
			[]string{"DIT structure rules: o=example, the suffix (base_dn), as an organization: no active DIT structure rule has a name form for organization (X.501 13.7.5)"}},
		{"a suffix authnd has no class for", "cn=example",
			"ditstructurerule ( 2 FORM unitForm SUP 1 )\n",
			[]string{"DIT structure rules: the suffix cn=example is named by cn, and authnd gives a class to a suffix named by dc, o, ou, c and l only"}},
		{"the RDN attribute authnd chooses", "dc=example,dc=org",
			"ditstructurerule ( 2 FORM unitForm SUP 1 )\nditstructurerule ( 3 NAME 'peopleByCN' FORM accountByCN SUP 2 )\nditstructurerule ( 4 FORM groupForm SUP 2 )\n",
			[]string{"DIT structure rules: authnd names its people uid=<name>,ou=people,dc=example,dc=org, and an account named so is refused: " +
				"the RDN (uid) is allowed by the name form of no DIT structure rule that places account under an entry governed by the rule 2: accountByCN needs cn"}},
		{"nothing that could be placed", "dc=example,dc=org",
			"ditstructurerule ( 2 FORM unitForm SUP 1 )\nditstructurerule ( 3 FORM accountForm SUP 2 )\n",
			[]string{"DIT structure rules: no entry authnd publishes under ou=groups,dc=example,dc=org could be placed there: " +
				"posixGroup (no active DIT structure rule has a name form for posixGroup (X.501 13.7.5)); groupOfNames (",
				"organizationalRole (no active DIT structure rule has a name form for organizationalRole"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			body := rulesConfig(t, c.base, hclPath(write(t, dir, "tree.schema", forms+c.rules)))
			if _, err := openBody(t, body); err == nil {
				t.Fatal("it started")
			} else {
				contains(t, err.Error(), c.says...)
				if strings.Contains(err.Error(), "let me read") {
					t.Error("a password is in the refusal")
				}
			}
			out, err := execute(t, "check", write(t, dir, "c.hcl", body))
			if err == nil {
				t.Fatalf("check passed:\n%s", out)
			}
			contains(t, err.Error(), c.says[0])
		})
	}
}

// The rules come through schema blocks too, and a schema file may not
// redefine one, even word for word.
func TestTheRulesInSchemaBlocksAndRedefinitions(t *testing.T) {
	dir := t.TempDir()
	rules := testdataPath(t, "rules.schema")
	again := hclPath(write(t, dir, "again.schema", "nameform ( 1.3.6.1.4.1.99999.9.3 NAME 'exampleAccountForm' OC account MUST uid )\n"))
	_, err := openBody(t, rulesConfig(t, "dc=example,dc=org", rules, again))
	if err == nil {
		t.Fatal("a redefined name form was accepted")
	}
	contains(t, err.Error(), again+":1:1: the name form exampleAccountForm (1.3.6.1.4.1.99999.9.3) is already defined by "+rules,
		"and this is the same definition, word for word",
		"slapd has no name forms, and this server holds them to the rule slapd applies to the others")

	body := rulesConfig(t, "dc=example,dc=org") + `
schema {
  dit_content_rule "groupRule" {
    oid = "1.3.6.1.1.1.2.2"
    not = ["description"]
  }
}
group "described" {
  members    = ["bob"]
  attributes = { gidNumber = "200", description = "precluded" }
}
`
	p := publishedFor(t, body)
	g := entryOf(t, p, "described", true)
	if g.invalid != nil || attrValues(g, "description") != nil || len(g.dropped) != 1 {
		t.Errorf("the group is %v %v %+v", g.invalid, g.Attributes, g.dropped)
	}
	// No structure rule in that site: the groupOfNames is published.
	if e := entryOf(t, p, "team", true); e.invalid != nil {
		t.Errorf("without structure rules: %v", e.invalid)
	}
}

// A declared class whose superclass the content rule does not allow is left
// off with it (RFC 4512 §3.3 wants every superclass listed), and both are
// said.
func TestADeclaredClassGoesWithItsSuperclass(t *testing.T) {
	body := rulesConfig(t, "dc=example,dc=org") + `
schema {
  object_class "siteBase" {
    oid  = "1.3.6.1.4.1.99999.8.1"
    kind = "auxiliary"
  }
  object_class "siteExtra" {
    oid  = "1.3.6.1.4.1.99999.8.2"
    sup  = ["siteBase"]
    kind = "auxiliary"
  }
  dit_content_rule "accountRule" {
    oid = "0.9.2342.19200300.100.4.5"
    aux = ["posixAccount", "uidObject", "ldapPublicKey", "siteExtra"]
  }
}
user "dan" {
  password       = "x"
  object_classes = ["siteExtra"]
}
`
	dan := entryOf(t, publishedFor(t, body), "dan", false)
	if dan.invalid != nil {
		t.Fatalf("dan: %v", dan.invalid)
	}
	if got := strings.Join(attrValues(dan, "objectClass"), " "); got != "top account uidObject" {
		t.Errorf("dan's objectClass is %q", got)
	}
	lines := strings.Join(leftOffLines(dan, "dan"), "\n")
	contains(t, lines,
		"dan is published without siteBase: the DIT content rule accountRule does not allow it (not in its AUX)",
		"dan is published without siteExtra: its superclass siteBase is not allowed by the DIT content rule accountRule (not in its AUX)")
}

// A content rule or a structure rule redefined by a later file is refused
// as any definition is, with what slapd says of the kind.
func TestRedefinedRulesOfEachKind(t *testing.T) {
	dir := t.TempDir()
	rules := testdataPath(t, "rules.schema")
	for _, c := range []struct{ text, says string }{
		{"ditcontentrule ( 0.9.2342.19200300.100.4.5 NAME 'other' )\n",
			`the DIT content rule other (0.9.2342.19200300.100.4.5) is already defined by ` + rules + `:10:1, and this is a different definition: ` +
				`a schema file adds definitions and never replaces one -- slapd refuses this too ("Duplicate Content Rule"`},
		{"ditstructurerule ( 3 NAME 'exampleAccounts' FORM exampleAccountForm SUP 2 )\n",
			"the DIT structure rule exampleAccounts (3) is already defined by " + rules + ":30:1, and this is the same definition, word for word: " +
				"a schema file adds definitions and never replaces one -- slapd has no DIT structure rules"},
	} {
		again := hclPath(write(t, dir, "again.schema", c.text))
		_, err := openBody(t, rulesConfig(t, "dc=example,dc=org", rules, again))
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%q: %v\nwant %q", c.text, err, c.says)
		}
	}
}

func TestStructureHelpers(t *testing.T) {
	srv, err := openBody(t, rulesConfig(t, "dc=example,dc=org"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.containerClass("not a DN"); err == nil || !strings.Contains(err.Error(), `base_dn "not a DN" is not a DN`) {
		t.Errorf("%v", err)
	}
	if article("domain") != "a" || article("organization") != "an" {
		t.Error("article")
	}
}

// The rules as a client sees them: served at cn=Subschema, and the tree
// they shape, read by OpenLDAP's own client.
func TestTheRulesAreServedAndSearched(t *testing.T) {
	bin := needLDAPSearch(t)
	r := start(t, rulesConfig(t, "dc=example,dc=org", testdataPath(t, "rules.schema")))

	out := readerSearch(t, bin, r, "-b", "cn=Subschema", "-s", "base", "(objectClass=subschema)", "dITContentRules", "nameForms", "dITStructureRules")
	contains(t, out,
		"dITContentRules: ( 0.9.2342.19200300.100.4.5 NAME 'exampleAccountRule' AUX ( posixAccount $ shadowAccount $ uidObject ) NOT description )",
		"nameForms: ( 1.3.6.1.4.1.99999.9.3 NAME 'exampleAccountForm' OC account MUST uid )",
		"dITStructureRules: ( 3 NAME 'exampleAccounts' FORM exampleAccountForm SUP 2 )",
	)
	out = readerSearch(t, bin, r, "-LLL", "-b", "ou=people,dc=example,dc=org", "(objectClass=*)", "uid", "objectClass", "description", "sshPublicKey")
	contains(t, out, "dn: uid=alice,ou=people,dc=example,dc=org", "dn: uid=bob,ou=people,dc=example,dc=org")
	for _, absent := range []string{"carol", "ldapPublicKey", "sshPublicKey", "description"} {
		if strings.Contains(out, absent) {
			t.Errorf("%s was published:\n%s", absent, out)
		}
	}
	out = readerSearch(t, bin, r, "-LLL", "-b", "ou=groups,dc=example,dc=org", "(objectClass=*)", "cn")
	contains(t, out, "dn: cn=staff,ou=groups,dc=example,dc=org")
	if strings.Contains(out, "team") {
		t.Errorf("the groupOfNames was published:\n%s", out)
	}
	contains(t, r.out.String(),
		"uid=alice,ou=people,dc=example,dc=org is published without ldapPublicKey: the DIT content rule exampleAccountRule does not allow it (not in its AUX)",
		"uid=carol,ou=people,dc=example,dc=org is NOT published: it fails the schema: telephoneNumber is required by the DIT content rule examplePersonRule and is missing",
		"cn=team,ou=groups,dc=example,dc=org is NOT published: it fails the schema: no active DIT structure rule has a name form for groupOfNames (X.501 13.7.5)",
	)
}
