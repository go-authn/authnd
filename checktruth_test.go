// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// Each test here pins a sentence `check` or the server used to say that was
// not so. They were found by running v0.9.6 for the documentation site, not
// by reading the code: every one of them passed the suite.

// keytabWithout writes a keytab holding a service key and NO krbtgt, which a
// realm cannot sign its own tickets without.
func keytabWithout(t *testing.T, dir string) string {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry("nfs/localhost", testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
		t.Fatal(err)
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "no-krbtgt.keytab")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// check opens what the server opens before it listens. v0.9.6 passed both of
// these with "this configuration can be served", and the restart exited 1.
func TestCheckRefusesWhatTheServerWouldRefuse(t *testing.T) {
	dir := t.TempDir()
	garbage := write(t, dir, "garbage.pem", "not a certificate\n")
	for _, c := range []struct {
		name, body, want string
	}{
		{
			name: "a certificate that does not load",
			body: fmt.Sprintf(`
listen    = "127.0.0.1:0"
base_dn   = "dc=example,dc=org"
cert_file = %q
key_file  = %q
user "alice" { password = "alicepw" }
`, garbage, garbage),
			want: "the certificate:",
		},
		{
			name: "a keytab without krbtgt",
			body: fmt.Sprintf(`
base_dn = "dc=example,dc=org"
user "alice" { password = "alicepw" }
kerberos {
  realm  = %q
  listen = "127.0.0.1:%d"
  keytab = %q
}
`, testRealm, freePort(t), keytabWithout(t, dir)),
			want: "krbtgt",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := execute(t, "check", write(t, t.TempDir(), "c.hcl", c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("check accepted it or said the wrong thing: err=%v\n%s", err, out)
			}
			if strings.Contains(out, "this configuration can be served") {
				t.Errorf("check still says it can be served:\n%s", out)
			}
		})
	}
}

// A person known only by an NT hash cannot simple-bind: a bind is checked
// against a password or a password check, and an NT hash is neither. v0.9.6
// listed bob with "an NT hash" and then "every bind still works"; bob's
// correct password got invalidCredentials.
func TestCheckSaysWhoCannotBindWithAPassword(t *testing.T) {
	path := write(t, t.TempDir(), "c.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "alicepw" }
user "bob"   { nt_hash  = "8846f7eaee8fb117ad06bdd830b7586c" }
`)
	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if !strings.Contains(out, "bob cannot bind with a password") {
		t.Errorf("check does not say bob cannot bind:\n%s", out)
	}
	if strings.Contains(out, "alice cannot bind") || strings.Contains(out, "alice and bob cannot bind") {
		t.Errorf("check names alice, who can:\n%s", out)
	}
	if strings.Contains(out, "every bind still works") {
		t.Errorf("check still says every bind works:\n%s", out)
	}
}

// With an oidc block, a person with no TOTP secret is not locked out by a
// two-factor policy: a token whose amr names two kinds satisfies it.
func TestCheckDoesNotLockOutWhoATokenCanStillAdmit(t *testing.T) {
	p := newProvider(t)
	path := write(t, t.TempDir(), "c.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

mfa {
  factors        = 2
  distinct_kinds = true
}

user "alice" { password = "hunter2" }
`+p.block(""))
	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if strings.Contains(out, "cannot bind while one is required") {
		t.Errorf("check says alice cannot bind, though a token can admit her:\n%s", out)
	}
	if !strings.Contains(out, "a token whose amr names two kinds still can") {
		t.Errorf("check does not say what still admits alice:\n%s", out)
	}
}

// The listening line comes after everything that can still fail. v0.9.6
// printed "ldap on ..., serving N people" and then failed on the keytab: a
// journal whose last line of success was not one.
func TestTheListeningLineComesAfterTheRealm(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "alicepw" }
kerberos {
  realm  = %q
  listen = "127.0.0.1:%d"
  keytab = %q
}
`, testRealm, freePort(t), keytabWithout(t, dir)))})
	if err != nil {
		t.Fatal(err)
	}
	out := &safeBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if err := srv.listen(); err == nil {
		t.Fatal("a realm without krbtgt listened")
	}
	if strings.Contains(out.String(), " on 127.0.0.1") {
		t.Errorf("it said it was listening before it failed:\n%s", out.String())
	}
}
