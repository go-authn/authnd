// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-authn/ldap"
	"github.com/go-authn/ldap/ldaptest"
)

// passwdModify is an RFC 3062 request value: the identity when it is not
// empty, and the new password.
func passwdModifyValue(identity, newPassword string) []byte {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	if identity != "" {
		seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
			ber.Tag(tagUserIdentity), identity, ""))
	}
	seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
		ber.Tag(tagNewPasswd), newPassword, ""))
	return seq.Bytes()
}

// ⛔ Two people whose names differ only by case are refused at startup.
//
// A uid is compared caseIgnoreMatch (RFC 4519 2.39), and so is a DN (RFC 4514,
// ldap.EqualDN). A map keyed by the exact bytes holds "Backup" and "backup" as
// two people while every DN comparison says they are one -- and the password
// change compared DNs, so either could rewrite the other's password. A server
// that cannot say which of the two a DN means must not start.
func TestNamesThatDifferOnlyByCaseAreRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "backup" { password = "service-secret" }
user "Backup" { password = "another-secret" }
`)})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if err == nil {
		srv.Close()
		t.Fatal("two people whose names differ only by case were both served")
	}
	contains(t, err.Error(), `"backup"`, `"Backup"`, "case")
}

// ⛔ A password is changed by the identity that bound, and by no other.
//
// The bound DN and the target DN used to be compared with ldap.EqualDN, which
// folds case: a session bound as uid=Backup passed the check for uid=backup.
// The startup refusal above keeps two such people from being served at once,
// and this keeps the authorization exact on its own -- the two are separate
// controls, and either one failing alone must not be enough.
func TestAPasswordIsChangedOnlyByItsExactOwner(t *testing.T) {
	t.Parallel()
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "backup" { password = "service-secret" }
`)
	target := "uid=backup,ou=people,dc=example,dc=org"
	ctx := context.Background()
	for _, who := range []string{
		"uid=Backup,ou=people,dc=example,dc=org",
		"uid=BACKUP,ou=people,dc=example,dc=org",
	} {
		res, err := r.srv.Modify(ctx, session{dn: who},
			&ldap.ModifyRequest{DN: target, Changes: replace("userPassword", "not yours")})
		if err != nil || res.Code != ldap.InsufficientAccessRights {
			t.Errorf("modify by %s: %s %v", who, res.Code, err)
		}
		ext, err := r.srv.Extended(ctx, session{dn: who}, &ldap.ExtendedRequest{
			Name: ldap.OIDPasswordModify, Value: passwdModifyValue(target, "not yours")})
		if err != nil || ext.Code != ldap.InsufficientAccessRights {
			t.Errorf("password modify by %s: %s %v", who, ext.Code, err)
		}
		// The identity left out means "this connection" (RFC 3062 2), and
		// this connection is not backup either.
		ext, err = r.srv.Extended(ctx, session{dn: who}, &ldap.ExtendedRequest{
			Name: ldap.OIDPasswordModify, Value: passwdModifyValue("", "not yours")})
		if err != nil || ext.Code == ldap.Success {
			t.Errorf("password modify of its own by %s: %s %v", who, ext.Code, err)
		}
	}
	c := client(t, r)
	if res, _ := c.Bind(target, "service-secret"); res.Code != ldap.Success {
		t.Fatalf("the original password no longer binds: %s", res.Code)
	}

	// The attribute TYPES and the suffix are still compared as a DN compares
	// them: only the value names a person, and it is the value that must be
	// exact.
	res, err := r.srv.Modify(ctx, session{dn: "UID=backup,OU=People,DC=Example,DC=Org"},
		&ldap.ModifyRequest{DN: target, Changes: safeChange("service-secret", "the owner's")})
	if err != nil || res.Code != ldap.Success {
		t.Fatalf("the owner, spelling the DN differently: %s %v", res.Code, err)
	}
	if res, _ := client(t, r).Bind(target, "the owner's"); res.Code != ldap.Success {
		t.Errorf("the owner's new password does not bind: %s", res.Code)
	}
}

// ⛔ A password change rebuilds who is served while other connections read it.
//
// The rebuild wrote the map that Bind and Search read without a lock, and the
// runtime answers that with "concurrent map iteration and map write", which
// ends the process. Run under -race (the CI race lane), this fails on any
// unsynchronised access, not only on the ones that happen to crash.
func TestAPasswordChangeDoesNotRaceTheReaders(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "alice" { password = "hunter2" }
user "bob"   { password = "hunter2" }
`)
	for i := range 50 {
		fmt.Fprintf(&b, "user \"u%02d\" { password = \"p\" }\n", i)
	}
	r := start(t, b.String())

	stop := time.Now().Add(1500 * time.Millisecond)
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c := client(t, r)
			if res, _ := c.Bind("cn=reader,dc=example,dc=org", "let me read"); res.Code != ldap.Success {
				errs <- "reader bind: " + res.Code.String()
				return
			}
			for time.Now().Before(stop) {
				got, err := c.Search(ldaptest.Search{Base: "dc=example,dc=org",
					Scope: ldap.ScopeWholeSubtree, Filter: "(uid=bob)"})
				if err != nil || got.Result.Code != ldap.Success || len(got.Entries) != 1 {
					errs <- fmt.Sprintf("search: %v %+v", err, got.Result)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			c := client(t, r)
			for time.Now().Before(stop) {
				if res, err := c.Bind("uid=bob,ou=people,dc=example,dc=org", "hunter2"); err != nil ||
					res.Code != ldap.Success {
					errs <- fmt.Sprintf("bob's bind: %s %v", res.Code, err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c := client(t, r)
		if res, _ := c.Bind("uid=alice,ou=people,dc=example,dc=org", "hunter2"); res.Code != ldap.Success {
			errs <- "alice's bind: " + res.Code.String()
			return
		}
		old := "hunter2"
		for n := 0; time.Now().Before(stop); n++ {
			next := fmt.Sprintf("pw-%d", n)
			res, err := c.Extended(ldap.OIDPasswordModify, passwdModifyWithOld("", old, next))
			if err != nil || res.Code != ldap.Success {
				errs <- fmt.Sprintf("password change %d: %s %v", n, res.Code, err)
				return
			}
			old = next
		}
	}()
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// ⛔ A realm under an mfa block would let a password alone do what the block
// refuses.
//
// RFC 4120's PA-ENC-TIMESTAMP is encrypted under a key derived from the
// password and nothing else; carrying a second factor needs an OTP
// pre-authentication (RFC 6560) inside FAST (RFC 6113), which this KDC does
// not implement. So a configuration asking for both is refused, rather than
// started with one door that checks two factors and one that checks one.
func TestKerberosIsRefusedWhereMFAIsRequired(t *testing.T) {
	t.Parallel()
	for _, block := range []string{
		"mfa { factors = 2 }",
		"mfa {}",
	} {
		dir := t.TempDir()
		body := fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
%s
user "alice" {
  password    = "hunter2"
  totp_secret = %q
}
kerberos {
  realm  = "EXAMPLE.ORG"
  listen = "127.0.0.1:0"
  keytab = %q
}
`, block, tessSecretB32, hclPath(filepath.Join(dir, "realm.keytab")))
		_, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
		if err == nil {
			t.Errorf("%s with a kerberos block was accepted", block)
			continue
		}
		contains(t, err.Error(), "kerberos", "mfa")
	}
}

// ⛔ A password changed over LDAP is the password the KDC derives keys from.
//
// The KDC read people through the source set built at startup, and the
// rebuild after a password change replaced only what LDAP binds read: kinit
// went on accepting the old password and refusing the new one. A password
// change that one half of the server has not heard of is a change that did
// not happen.
func TestKerberosSeesAPasswordChangedOverLDAP(t *testing.T) {
	mitAvailable(t)
	dir := t.TempDir()
	port := freePort(t)
	r := start(t, fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "oldpassword" }
kerberos {
  realm  = %q
  listen = "127.0.0.1:%d"
  keytab = %q
}
`, testRealm, port, hclPath(writeKeytab(t, dir))))
	t.Setenv("KRB5_CONFIG", krb5Conf(t, dir, port))
	t.Setenv("KRB5CCNAME", "FILE:"+filepath.Join(dir, "ccache"))

	if out, err := kinit(t, "alice", "oldpassword"); err != nil {
		t.Fatalf("kinit before the change: %v\n%s\n--- server said:\n%s", err, out, r.out.String())
	}
	c := client(t, r)
	if res, _ := c.Bind("uid=alice,ou=people,dc=example,dc=org", "oldpassword"); res.Code != ldap.Success {
		t.Fatalf("binding: %s", res.Code)
	}
	if res, err := c.Extended(ldap.OIDPasswordModify, passwdModifyWithOld("", "oldpassword", "newpassword")); err != nil ||
		res.Code != ldap.Success {
		t.Fatalf("changing the password: %s %v", res.Code, err)
	}
	os.Remove(filepath.Join(dir, "ccache"))
	if out, err := kinit(t, "alice", "oldpassword"); err == nil {
		t.Errorf("kinit still accepts the OLD password after it was changed over LDAP:\n%s", out)
	}
	if out, err := kinit(t, "alice", "newpassword"); err != nil {
		t.Errorf("kinit refuses the NEW password: %v\n%s\n--- server said:\n%s", err, out, r.out.String())
	}
}
