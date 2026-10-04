package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-authn/ldap"
)

// ⛔ Somebody who knows only a NAME must not be able to throttle or lock out
// its owner. The code's limits are there against guessing CODES, and a guess
// at a code is only a guess once the password in front of it was right:
// counting the code of a bind whose password was wrong let anybody freeze an
// account for fifteen minutes with five binds, and lock it for good with a
// hundred.
func TestAWrongPasswordCostsTheOwnerNothing(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", withMFA(t, dir, "\nmfa { factors = 2 }\n"))})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.codes.Throttle, srv.codes.Lockout = 3, 6

	dn := "uid=tess,ou=people,dc=example,dc=org"
	bind := func(given string) ldap.ResultCode {
		t.Helper()
		r, err := srv.Bind(context.Background(), nil, &ldap.BindRequest{Version: 3, Name: dn, Simple: []byte(given)})
		if err != nil {
			t.Fatal(err)
		}
		return r.Code
	}
	wrong := func() string {
		// A code that is not this half-minute's, nor either neighbour's.
		for _, c := range []string{"000000", "111111", "222222", "333333"} {
			if c != codeNow(t, tess) {
				return c
			}
		}
		return "444444"
	}

	// The attacker: more wrong binds than the lockout, with the right code and
	// with wrong ones, and never the password.
	for i := 0; i < 10; i++ {
		for _, given := range []string{"guess" + wrong(), "guess" + codeNow(t, tess)} {
			if got := bind(given); got != ldap.InvalidCredentials {
				t.Fatalf("a wrong password gave %v", got)
			}
		}
	}
	if got := bind("hunter2" + codeNow(t, tess)); got != ldap.Success {
		t.Fatalf("after binds with a wrong password, tess with the password and code got %v; the server said:\n%s",
			got, srv.out.(*safeBuffer).String())
	}

	// And the limit still holds for whoever HAS the password: guessing codes
	// behind it is throttled.
	for i := 0; i < 3; i++ {
		bind("hunter2" + wrong())
	}
	if got := bind("hunter2" + codeNow(t, tess)); got != ldap.InvalidCredentials {
		t.Errorf("three wrong codes behind the right password were not throttled: %v", got)
	}
	if said := srv.out.(*safeBuffer).String(); !strings.Contains(said, "throttled") && !strings.Contains(said, "too many") {
		t.Logf("the server said:\n%s", said)
	}
}

// ⛔ A reader's code is counted, and remembered as used, against the reader
// the configuration names -- not against the bytes the client sent. A DN is
// compared without case, so keyed by what was typed, "CN=keyed" was a second
// reader with its own used codes and its own budget of guesses: a code
// replayed under a new spelling was accepted, and every spelling (2^n of them
// for n letters) brought five more guesses before a pause.
func TestAReaderIsOneNameWhateverItsCase(t *testing.T) {
	dir := t.TempDir()
	keyed := "cn=keyed,dc=example,dc=org"
	body := withMFA(t, dir, fmt.Sprintf(`
mfa {
  factors = 2
  readers = true
}

reader %q {
  password    = "let me read"
  totp_secret = %q
}
`, keyed, readerSecretB32))
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.codes.Throttle = 3
	bind := func(dn, given string) ldap.ResultCode {
		t.Helper()
		r, err := srv.Bind(context.Background(), nil, &ldap.BindRequest{Version: 3, Name: dn, Simple: []byte(given)})
		if err != nil {
			t.Fatal(err)
		}
		return r.Code
	}

	code := codeNow(t, readerSecret)
	if got := bind(keyed, "let me read"+code); got != ldap.Success {
		t.Fatalf("the reader with its password and code got %v", got)
	}
	if got := bind("CN=Keyed,DC=example,DC=org", "let me read"+code); got != ldap.InvalidCredentials {
		t.Errorf("a used code replayed under another spelling of the DN gave %v", got)
	}

	// Three wrong codes, each under its own spelling, are three against ONE
	// reader: the right code is then refused under any spelling.
	for _, dn := range []string{"Cn=keyed,dc=example,dc=org", "cN=keyed,dc=example,dc=org", "cn=KEYED,dc=example,dc=org"} {
		bind(dn, "let me read000000")
	}
	if got := bind("cn=keyeD,dc=example,dc=org", "let me read"+codeNow(t, readerSecret)); got != ldap.InvalidCredentials {
		t.Errorf("three wrong codes under three spellings did not throttle the reader: %v", got)
	}
}

// Somebody with no authenticator enrolled is still reported as such when the
// password in front was wrong too: the administrator reading the log is told
// what to fix, not that the server was built without a Verifier.
func TestNobodyEnrolledIsSaidBehindAWrongPassword(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", withMFA(t, dir, "\nmfa { factors = 2 }\n"))})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	r, err := srv.Bind(context.Background(), nil, &ldap.BindRequest{Version: 3,
		Name: "uid=gus,ou=people,dc=example,dc=org", Simple: []byte("not-swordfish123456")})
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != ldap.InvalidCredentials {
		t.Fatalf("gus with a wrong password got %v", r.Code)
	}
	if said := srv.out.(*safeBuffer).String(); !strings.Contains(said, "enrolled") {
		t.Errorf("the server did not say that gus has no second factor:\n%s", said)
	}
}
