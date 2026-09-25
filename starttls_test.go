// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/ldap"
	"github.com/go-authn/ldap/ldaptest"
)

// ⛔ cert_file and key_file used to be documented as giving BOTH ldaps:// and
// StartTLS. They cannot: tls.NewListener handshakes before a byte of LDAP is
// spoken, so the StartTLS that TLSConfig enables had no plaintext connection
// left to upgrade, and every client configured for it was simply cut off at
// the first exchange. It is one or the other, and `starttls` says which.
func TestStartTLSIsReachableWhenAskedFor(t *testing.T) {
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	r := start(t, peopleConfig(t, dir, fmt.Sprintf(`
starttls  = true
cert_file = %q
key_file  = %q
`, hclPath(cert), hclPath(key))))

	c := upgraded(t, r)
	// The connection works afterwards, which is the half a handshake alone
	// does not prove.
	if res, err := c.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil || res.Code != ldap.Success {
		t.Errorf("the upgraded connection could not bind: %s (%v)\n%s", res.Code, err, r.out.String())
	}
}

// ⛔ StartTLS is asked for by the CLIENT. A server that merely offers it has
// promised nothing -- so a listener configured for it refuses to work until
// it has been upgraded, which is what turns cert_file back into a guarantee.
func TestAStartTLSListenerRefusesEverythingUntilItIsUpgraded(t *testing.T) {
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	r := start(t, peopleConfig(t, dir, fmt.Sprintf(`
starttls  = true
cert_file = %q
key_file  = %q
`, hclPath(cert), hclPath(key))))

	c := client(t, r)
	// The RIGHT password, in the clear, on a listener that said it wanted
	// TLS. It is refused for the TRANSPORT, not for the credential -- and
	// the code says which, so an operator is not sent hunting a password
	// problem that does not exist.
	res, err := c.Bind("cn=reader,dc=example,dc=org", "let me read")
	if err != nil {
		t.Fatalf("the bind did not get an answer at all: %v", err)
	}
	if res.Code != ldap.ConfidentialityRequired {
		t.Errorf("a password in the clear answered %s, want confidentialityRequired", res.Code)
	}
}

// Without starttls the listener is ldaps:// as it always was, and a plain
// client gets nowhere -- which is the behaviour every existing deployment
// has.
func TestWithoutTheFlagTheListenerIsStillLDAPS(t *testing.T) {
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	r := start(t, peopleConfig(t, dir, fmt.Sprintf("\ncert_file = %q\nkey_file  = %q\n", hclPath(cert), hclPath(key))))

	c, err := ldaptest.Dial(r.addr, 5*time.Second)
	if err != nil {
		return // refused at the socket is also an answer
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if res, err := c.Bind("cn=reader,dc=example,dc=org", "let me read"); err == nil && res.Code == ldap.Success {
		t.Error("a plaintext bind worked against an ldaps:// listener")
	}
}

// starttls with nothing to upgrade a connection WITH is refused where it can
// be read, not at the first client that tries.
func TestStartTLSWithoutACertificateIsRefusedAtStartup(t *testing.T) {
	dir := t.TempDir()
	_, err := loadConfig([]string{write(t, dir, "c.hcl", `
listen   = "127.0.0.1:0"
base_dn  = "dc=example,dc=org"
starttls = true
`)})
	if err == nil {
		t.Fatal("starttls without a certificate was accepted")
	}
	if !strings.Contains(err.Error(), "cert_file") {
		t.Errorf("the refusal does not name what is missing: %v", err)
	}
}

// ⛔ A token in the clear is a credential in the clear, and this is the
// listener where "in the clear" is the client's choice. The two guards are
// the same evidence -- a *tls.Conn or not -- so this checks that the OIDC one
// is not a separate opinion that could drift from it.
func TestATokenOnAStartTLSListenerNeedsTheUpgradeToo(t *testing.T) {
	p := newProvider(t)
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	r := start(t, fmt.Sprintf(`
listen    = "127.0.0.1:0"
base_dn   = "dc=example,dc=org"
starttls  = true
cert_file = %q
key_file  = %q

user "alice" { password = "hunter2" }

oidc {
  issuer   = %q
  audience = "ldap"
}
`, hclPath(cert), hclPath(key), p.issuer()))

	tok := p.token(t, map[string]any{"preferred_username": "alice"})

	// Before the upgrade: refused, for the TRANSPORT and not the token.
	before, _ := client(t, r).BindSASL(oauthBearer, oauthBearerCredentials("", tok))
	if before.Code != ldap.ConfidentialityRequired {
		t.Errorf("in the clear the token answered %s, want confidentialityRequired", before.Code)
	}

	// After it: the SAME token, accepted. That is what makes the refusal
	// above about the connection rather than about the token.
	after, _ := upgraded(t, r).BindSASL(oauthBearer, oauthBearerCredentials("", tok))
	if after.Code != ldap.Success {
		t.Errorf("after StartTLS the token answered %s (%s)\n%s", after.Code, after.ServerCreds, r.out.String())
	}
}
