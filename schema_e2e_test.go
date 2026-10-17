// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// schemaPeople is a directory with every person shape, three uidNumbers that
// sort differently as strings and as integers, and one person whose entry
// fails the schema.
const schemaPeople = `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }

user "ann" {
  password   = "x"
  attributes = { sn = "Ann", uidNumber = "999", gidNumber = "100", homeDirectory = "/home/ann" }
}
user "ben" {
  password   = "x"
  attributes = { uidNumber = "1000", gidNumber = "100", homeDirectory = "/home/ben" }
}
user "cat" {
  password   = "x"
  attributes = { uidNumber = "10000", gidNumber = "100", homeDirectory = "/home/cat" }
}
user "dan" { password = "x" }
user "eve" {
  password   = "x"
  attributes = { uidNumber = "1001" }
}

group "staff" {
  members    = ["ann", "ben"]
  attributes = { gidNumber = "100" }
}
group "readers" { members = ["cat", "dan"] }
`

// ldap runs ldapsearch as the reader with the extra arguments, and gives
// back what it printed.
func readerSearch(t *testing.T, bin string, r *running, args ...string) string {
	t.Helper()
	all := append([]string{"-x", "-H", r.url(), "-D", "cn=reader,dc=example,dc=org", "-w", "let me read"}, args...)
	out, err := exec.Command(bin, all...).CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch %v: %v\n%s", args, err, out)
	}
	return unfold(string(out))
}

// The root DSE names the subschema subentry, and the subentry answers with
// the definitions -- read by OpenLDAP's own client.
func TestTheSchemaIsServed(t *testing.T) {
	bin := needLDAPSearch(t)
	r := start(t, schemaPeople)

	out := readerSearch(t, bin, r, "-b", "", "-s", "base", "(objectClass=*)", "+")
	contains(t, out, "subschemaSubentry: cn=Subschema")

	out = readerSearch(t, bin, r, "-b", "cn=Subschema", "-s", "base", "(objectClass=subschema)", "*", "+")
	contains(t, out,
		"objectClass: subschema",
		// The classes the entries use, as the server defines them.
		"objectClasses: ( 1.3.6.1.1.3.1 NAME 'uidObject'",
		"objectClasses: ( 0.9.2342.19200300.100.4.5 NAME 'account'",
		"NAME 'posixAccount'",
		"NAME 'inetOrgPerson'",
		"NAME 'organizationalRole'",
		// The ORDERING that makes (uidNumber>=1000) an integer comparison.
		"NAME 'uidNumber'",
		"ORDERING integerOrderingMatch",
	)
	// Without the samba block there is no Samba schema to publish.
	if strings.Contains(out, "sambaSamAccount") {
		t.Errorf("sambaSamAccount is published by a server with no samba block:\n%.2000s", out)
	}
}

// (uidNumber>=1000) compares INTEGERS: "999" >= "1000" as strings, and
// "10000" sorts before "9999". go-authn/ldap v0.8.0 gives uidNumber
// ORDERING integerOrderingMatch, and the handler asks req.Matches.
func TestARangeFilterComparesIntegers(t *testing.T) {
	bin := needLDAPSearch(t)
	r := start(t, schemaPeople)
	out := readerSearch(t, bin, r, "-b", "ou=people,dc=example,dc=org", "(uidNumber>=1000)", "uid")
	contains(t, out, "uid: ben", "uid: cat", "numEntries: 2")
	if strings.Contains(out, "uid: ann") {
		t.Errorf("999 >= 1000 was true: the comparison is of strings\n%s", out)
	}
	// ⛔ The other direction is the one only the HANDLER can get wrong. The
	// library drops an entry the handler sent that the schema does not
	// match, so 999 above is caught either way; it cannot bring back one the
	// handler left out. As strings, "10000" < "9999", and a handler using
	// req.Filter.Matches never sends cat.
	out = readerSearch(t, bin, r, "-b", "ou=people,dc=example,dc=org", "(uidNumber>=9999)", "uid")
	contains(t, out, "uid: cat", "numEntries: 1")
}

// The invariant, seen from a client: an entry that fails the schema is not in
// any answer, whatever is asked; the others are.
func TestAnEntryThatFailsTheSchemaIsNotPublished(t *testing.T) {
	bin := needLDAPSearch(t)
	r := start(t, schemaPeople)
	out := readerSearch(t, bin, r, "-b", "dc=example,dc=org", "(objectClass=*)", "objectClass")
	if strings.Contains(out, "uid=eve,") {
		t.Errorf("eve, whose uidNumber no class of theirs allows, was published:\n%s", out)
	}
	contains(t, out,
		"dn: uid=ann,ou=people,dc=example,dc=org",
		"dn: uid=dan,ou=people,dc=example,dc=org",
		"dn: cn=staff,ou=groups,dc=example,dc=org",
		"dn: cn=readers,ou=groups,dc=example,dc=org",
	)
	out = readerSearch(t, bin, r, "-b", "ou=people,dc=example,dc=org", "(uid=eve)")
	contains(t, out, "# numResponses: 1\n") // the result alone: no entry
	// And the startup output said so, with the problem.
	contains(t, r.out.String(), "uid=eve,ou=people,dc=example,dc=org is NOT published", "uidNumber is not allowed")

	// One class finds every person, whatever the structural class.
	out = readerSearch(t, bin, r, "-b", "ou=people,dc=example,dc=org", "(objectClass=uidObject)", "uid")
	contains(t, out, "uid: ann", "uid: ben", "uid: cat", "uid: dan", "numEntries: 4")
}

// A paged search (RFC 2696) asking for one attribute gets every person, a
// page at a time, with that attribute and no other.
func TestAPagedSearch(t *testing.T) {
	bin := needLDAPSearch(t)
	r := start(t, schemaPeople)
	out := readerSearch(t, bin, r, "-E", "pr=2/noprompt", "-b", "ou=people,dc=example,dc=org", "(objectClass=uidObject)", "uidNumber")
	contains(t, out, "uidNumber: 999", "uidNumber: 1000", "uidNumber: 10000", "numEntries: 4", "result: 0 Success")
	if strings.Contains(out, "homeDirectory:") || strings.Contains(out, "\nuid: ") {
		t.Errorf("a search for uidNumber returned other attributes:\n%s", out)
	}
	// Two people a page: dan, with no uidNumber, still counts.
	if n := strings.Count(out, "pagedresults: cookie="); n < 2 {
		t.Errorf("%d paged-results controls, want two pages or more:\n%s", n, out)
	}
}

// check says what each entry is published as, who lacks posixAccount's
// attributes and which ones, which groups lack a gidNumber, and every entry
// held back with the problems Validate named.
func TestCheckSaysWhatTheSchemaDecided(t *testing.T) {
	dir := t.TempDir()
	out, err := execute(t, "check", write(t, dir, "c.hcl", schemaPeople))
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	t.Log("\n" + out)
	contains(t, out,
		// The tables: each row says what the entry is published as.
		"PUBLISHED AS",
		"person, organizationalPerson, inetOrgPerson, posixAccount, uidObject",
		"account, posixAccount, uidObject",
		"NOT PUBLISHED (see below)",
		// The people without posixAccount, and what each lacks.
		"dan has no uidNumber, gidNumber or homeDirectory: not a posixAccount, published as account, uidObject",
		"eve has no gidNumber or homeDirectory: not a posixAccount, and as account, uidObject the entry fails the schema (below)",
		// The groups without gidNumber, and what they are instead.
		"group readers has no gidNumber: not a posixGroup, published as a groupOfNames",
		// The one held back, with Validate's words.
		"eve is NOT published: as account, uidObject it fails the schema:",
		"  - uidNumber is not allowed by any of the entry's object classes",
	)
	// Row by row, since a shape can be a substring of a sentence.
	for _, row := range [][]string{
		{"dan ", "account, uidObject "},
		{"staff ", "ann and ben", "posixGroup"},
		{"readers ", "cat and dan", "groupOfNames"},
	} {
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, row[0]) && !strings.Contains(line, ":") {
				found = true
				for _, w := range row[1:] {
					if !strings.Contains(line, w) {
						t.Errorf("the row for %q reads %q, want %q in it", row[0], line, w)
					}
				}
			}
		}
		if !found {
			t.Errorf("no row for %q:\n%s", row[0], out)
		}
	}
	// staff has a gidNumber, and is not said to lack one.
	if strings.Contains(out, "group staff has no gidNumber") {
		t.Errorf("staff's gidNumber did not reach its entry:\n%s", out)
	}
}
