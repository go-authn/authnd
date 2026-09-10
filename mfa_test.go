// The people here are `user` blocks whichever build this is, so a binary
// without SQL is asked the same questions about codes as one with it.
package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/totp"
)

// A second factor at the bind, judged by OpenLDAP's own client.
//
// LDAP's simple bind carries one field, so the code goes on the end of the
// password. What is measured here is that a real client, typing what a person
// would type, is let in with the code and refused without it.
func TestABindCarriesAPasswordAndACode(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	r := start(t, withMFA(t, dir, `
mfa {
  factors        = 2
  distinct_kinds = true
}
`))
	people := "ou=people,dc=example,dc=org"
	dn := "uid=tess," + people

	code := codeNow(t, tess)
	// The password alone is not enough, and neither is the code alone.
	if out, _ := search(bin, r.url(), dn, "hunter2", people, "(uid=tess)"); !strings.Contains(out, "Invalid credentials (49)") {
		t.Errorf("the password alone gave:\n%s", out)
	}
	if out, _ := search(bin, r.url(), dn, code, people, "(uid=tess)"); !strings.Contains(out, "Invalid credentials (49)") {
		t.Errorf("the code alone gave:\n%s", out)
	}
	// Together they are: the search is then refused for the OTHER reason,
	// which is how a successful bind shows through a client that only
	// searches.
	out, err := search(bin, r.url(), dn, "hunter2"+code, people, "(uid=tess)")
	if err == nil {
		t.Errorf("dora searched, and only a reader may:\n%s", out)
	}
	if !strings.Contains(out, "Insufficient access") {
		t.Errorf("password+code did not bind:\n%s", out)
	}

	// ⛔ And the same code again is a replay, refused even though it is still
	// the right code for this half-minute.
	if out, _ := search(bin, r.url(), dn, "hunter2"+code, people, "(uid=tess)"); !strings.Contains(out, "Invalid credentials (49)") {
		t.Errorf("the same code was accepted twice:\n%s", out)
	}
	// The server says why, where an administrator can read it and a client
	// cannot.
	if said := r.out.String(); !strings.Contains(said, "already been used") {
		t.Errorf("the replay was not reported to the server's own output:\n%s", said)
	}
}

// A wrong code with the right password is refused, and a right code with the
// wrong password is too -- both halves are checked, and the client is told the
// same thing either way.
func TestBothHalvesAreChecked(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	r := start(t, withMFA(t, dir, "\nmfa { factors = 2 }\n"))
	people := "ou=people,dc=example,dc=org"
	dn := "uid=tess," + people

	for _, given := range []string{"hunter2000000", "wrong" + codeNow(t, tess)} {
		if out, _ := search(bin, r.url(), dn, given, people, "(uid=tess)"); !strings.Contains(out, "Invalid credentials (49)") {
			t.Errorf("%q gave:\n%s", given, out)
		}
	}
	// A field too short to hold a code is refused rather than guessed at: a
	// password shorter than a code cannot be told apart from one.
	if out, _ := search(bin, r.url(), dn, "12345", people, "(uid=tess)"); !strings.Contains(out, "Invalid credentials (49)") {
		t.Errorf("a field shorter than a code gave:\n%s", out)
	}
	if said := r.out.String(); !strings.Contains(said, "the last 6 of it are the code") {
		t.Errorf("the server did not say why:\n%s", said)
	}
}

// ⛔ A person with no authenticator enrolled has refused nothing -- and a
// policy of two factors still refuses them, because one factor is not two.
// The server says which, in words an administrator can act on.
func TestSomebodyWithNoSecondFactor(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	r := start(t, withMFA(t, dir, "\nmfa { factors = 2 }\n"))
	people := "ou=people,dc=example,dc=org"

	// gus has a password and no secret.
	if out, _ := search(bin, r.url(), "uid=gus,"+people, "swordfish123456", people, "(uid=gus)"); !strings.Contains(out, "Invalid credentials (49)") {
		t.Errorf("gus was let in without a second factor:\n%s", out)
	}
	if said := r.out.String(); !strings.Contains(said, "enrolled") {
		t.Errorf("the server did not say that gus has no second factor:\n%s", said)
	}
}

// The readers are service accounts with no phone, so they carry a password
// only -- unless the configuration says otherwise.
func TestReadersCarryACodeOnlyWhenAsked(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	reader, people := "cn=reader,dc=example,dc=org", "ou=people,dc=example,dc=org"

	r := start(t, withMFA(t, dir, "\nmfa { factors = 2 }\n"))
	if _, err := search(bin, r.url(), reader, "let me read", people, "(uid=tess)"); err != nil {
		t.Errorf("the reader was asked for a code it was never given: %v", err)
	}

	// Asked for: the reader needs its own code, from its own secret.
	dir2 := t.TempDir()
	r2 := start(t, withMFA(t, dir2, fmt.Sprintf(`
mfa {
  factors = 2
  readers = true
}
`)+fmt.Sprintf("\nreader \"cn=keyed,dc=example,dc=org\" {\n  password    = \"let me read\"\n  totp_secret = %q\n}\n", readerSecretB32)))
	if out, _ := search(bin, r2.url(), "cn=keyed,dc=example,dc=org", "let me read", people, "(uid=tess)"); !strings.Contains(out, "Invalid credentials (49)") {
		t.Errorf("a reader that must carry a code got in without one:\n%s", out)
	}
	if _, err := search(bin, r2.url(), "cn=keyed,dc=example,dc=org", "let me read"+codeNow(t, readerSecret), people, "(uid=tess)"); err != nil {
		t.Errorf("the reader could not read with its code: %v", err)
	}
}

// What check says about a configuration that asks for two factors.
func TestCheckSaysWhoHasASecondFactor(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", withMFA(t, dir, "\nmfa { factors = 2 }\n"))
	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	contains(t, out,
		"a password with a 6-digit code after it",
		"tess",
		"a one-time-code secret",
		"have no second factor here",
		"gus", // named among them
	)
	if strings.Contains(out, tessSecretB32) {
		t.Error("check printed a one-time-code secret")
	}
}

// Configurations that ask for something a bind cannot carry.
func TestMFABlocksThatCannotWork(t *testing.T) {
	for _, tc := range []struct{ name, block, want string }{
		{"one factor", "mfa { factors = 1 }", "a password and nothing else"},
		{"three factors", "mfa { factors = 3 }", "which is 2"},
		{"five digits", "mfa {\n  factors = 2\n  digits  = 5\n}", "RFC 4226 allows 6 to 10"},
		{"a negative window", "mfa {\n  factors = 2\n  window  = -1\n}", "window of -1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			body := withMFA(t, dir, "\n"+tc.block+"\n")
			if _, err := loadConfig([]string{write(t, dir, "c.hcl", body)}); err == nil {
				t.Error("the configuration was accepted")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// The secrets these tests use. tess has one, gus does not.
const (
	tessSecretB32   = "JBSWY3DPEHPK3PXP"
	readerSecretB32 = "MFRGGZDFMZTWQ2LK"
)

var tess, readerSecret = mustSecret(tessSecretB32), mustSecret(readerSecretB32)

func mustSecret(s string) []byte {
	raw, err := directory.ParseTOTPSecret(s)
	if err != nil {
		panic(err)
	}
	return raw
}

// codeNow is what an authenticator would show this second.
func codeNow(t *testing.T, secret []byte) string {
	t.Helper()
	code, err := totp.At(secret, time.Now(), totp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// withMFA is the shared people, plus two more: tess, who has enrolled an
// authenticator, and gus, who has not. They are named differently from the
// people peopleConfig brings so that this works in both builds -- with SQL
// those come out of a database, and without it they are `user` blocks with
// the same names.
func withMFA(t *testing.T, dir, extra string) string {
	t.Helper()
	return peopleConfig(t, dir, fmt.Sprintf(`
user "tess" {
  password    = "hunter2"
  totp_secret = %q
}

user "gus" { password = "swordfish" }
%s`, tessSecretB32, extra))
}
