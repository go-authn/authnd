//go:build !nosql

package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
)

// The whole point, end to end: a database, published as LDAP, read back by the
// library a file server uses.
//
// go-fileshare/fileshare authenticates people through
// go-authn/directory/ldapdir. If ldapdir can read this server and comes away
// with what each protocol needs, then a file server pointed here can serve
// those people -- and the ones it CANNOT serve are exactly the ones this
// server could not publish enough for, which is the honest half.
func TestAFileServersOwnReaderReadsThisDirectory(t *testing.T) {
	dir := t.TempDir()
	// dora has a password: everything can be derived from it, including the
	// NT hash NTLMv2 needs. frank has ONLY an nt_hash, as a site that stores
	// what Samba stores does. eli has a password too, but the server is asked
	// not to publish hashes for the first half of the test.
	dsn := sqliteWith(t, dir, fmt.Sprintf(`
create table staff (login text primary key, secret text, nt_hash text);
insert into staff values ('dora', 'hunter2', null), ('frank', null, '%s');
create table teams (team text, member text);
insert into teams values ('engineers', 'dora'), ('engineers', 'frank');
`, strings.ToLower(hunter2NTHash)))
	body := fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

publish_nt_hash = true

reader "cn=reader,dc=example,dc=org" { password = "let me read" }

users "sql" {
  driver   = "sqlite"
  dsn_file = %q
  users    = "select login, secret, nt_hash from staff"
  groups   = "select team, member from teams"
}
`, hclPath(dsn))
	r := start(t, body)

	src, err := ldapdir.New(ldapdir.Config{
		URL:          r.url(),
		BaseDN:       "ou=people,dc=example,dc=org",
		GroupBaseDN:  "ou=groups,dc=example,dc=org",
		BindDN:       "cn=reader,dc=example,dc=org",
		BindPassword: "let me read",
	})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("%d people came back, want 2", len(ids))
	}
	for _, id := range ids {
		// Both were published with sambaNTPassword, so a file server can
		// serve both over SMB -- one from a password the database holds, one
		// from a hash it holds instead. That equivalence is the whole reason
		// the hash is publishable at all.
		if !id.Can(directory.NTHash) {
			t.Errorf("%s came back without an NT hash: SMB could not serve them", id.Name())
			continue
		}
		key, err := id.NTKey()
		if err != nil {
			t.Errorf("%s: %v", id.Name(), err)
			continue
		}
		if got := strings.ToUpper(hex.EncodeToString(key)); got != hunter2NTHash {
			// Both people are set up with the same password, deliberately:
			// the value crossing the wire is then a single known constant,
			// computed by an OpenSSL that is not this program.
			t.Errorf("%s's key = %s, want %s", id.Name(), got, hunter2NTHash)
		}
		// And never the password itself: LDAP does not give one up, so a
		// reader gets the hash and a bind, and nothing else.
		if id.Can(directory.Password) {
			t.Errorf("%s's password came out of LDAP, which LDAP does not do", id.Name())
		}
	}

	// The group, read the way a file server expands `allow = ["@engineers"]`.
	members, err := src.Members("engineers")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Errorf("engineers = %v, want dora and frank", members)
	}
	// And a bind, which is what WebDAV would use.
	for _, id := range ids {
		if id.Name() != "dora" {
			continue
		}
		if err := id.Verify("hunter2"); err != nil {
			t.Errorf("dora's password was refused through the whole stack: %v", err)
		}
		if err := id.Verify("wrong"); err == nil {
			t.Error("a wrong password was accepted through the whole stack")
		}
		// ⛔ And the empty one, which this server refuses before binding.
		if err := id.Verify(""); err == nil {
			t.Error("an empty password was accepted (the unauthenticated bind)")
		}
	}
}

// Without publish_nt_hash, the same stack cannot serve SMB -- and that is
// visible in the model rather than at somebody's mount.
func TestWithoutTheHashSMBCannotBeServedThroughThisDirectory(t *testing.T) {
	dir := t.TempDir()
	r := start(t, peopleConfig(t, dir, ""))
	src, err := ldapdir.New(ldapdir.Config{
		URL:          r.url(),
		BaseDN:       "ou=people,dc=example,dc=org",
		BindDN:       "cn=reader,dc=example,dc=org",
		BindPassword: "let me read",
	})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id.Can(directory.NTHash) {
			t.Errorf("%s came back with an NT hash, which this server did not publish", id.Name())
		}
		// What a bind CAN answer is still there, which is the point of saying
		// it per protocol rather than per person.
		if !id.Can(directory.Verifier) {
			t.Errorf("%s cannot even be checked by a bind", id.Name())
		}
	}
}
