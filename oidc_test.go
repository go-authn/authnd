// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/ldap"
)

// bindWithToken does one OAUTHBEARER bind against a running server and
// returns what it answered.
func bindWithToken(t *testing.T, r *running, authzid, token string) (ldap.LDAPResultCode, []byte) {
	t.Helper()
	c, err := ldap.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	code, creds, _ := c.SASLBind("", oauthBearer, oauthBearerCredentials(authzid, token))
	return code, creds
}

func oidcServer(t *testing.T, p *provider, extraBlock, extraConfig string) *running {
	t.Helper()
	return start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

reader "cn=reader,dc=example,dc=org" { password = "let me read" }

user "alice" { password = "hunter2" }
user "bob"   { password = "correct horse" }
`+p.block(extraBlock)+extraConfig)
}

// The whole point: a token goes in a field that is not the password, and the
// connection comes back bound as the person the token names.
func TestATokenBindsAsThePersonItNames(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")

	tok := p.token(t, map[string]any{"preferred_username": "alice"})
	c, err := ldap.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	code, _, err := c.SASLBind("", oauthBearer, oauthBearerCredentials("", tok))
	if err != nil || code != ldap.LDAPResultSuccess {
		t.Fatalf("the bind answered %d (%v); the server said: %s", code, err, r.out.String())
	}
}

// ⛔ The password field is untouched. This is the whole reason for not
// putting the token in it: on ONE listener, at the same time, a person who
// binds with a password still types their code on the end of it, and a person
// who has a token sends the token -- and neither arrangement costs the other
// anything.
//
// The two halves are asserted against the same running server, because the
// claim is that they coexist. Asserting them separately would prove only that
// each works when it is the only thing configured.
func TestAPasswordWithACodeAndATokenWorkOnTheSameListener(t *testing.T) {
	p := newProvider(t)
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

mfa {
  factors        = 2
  distinct_kinds = true
}

user "tess" {
  password    = "hunter2"
  totp_secret = "`+tessSecretB32+`"
}
user "alice" { password = "hunter2" }
`+p.block(""))

	// tess binds the way she always did: her password with this second's
	// code on the end of it.
	c, err := ldap.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("uid=tess,ou=people,dc=example,dc=org", "hunter2"+codeNow(t, tess)); err != nil {
		t.Errorf("a password-and-code bind stopped working once OIDC was configured: %v\n%s", err, r.out.String())
	}

	// alice sends a token, on the same server, under the same policy. Her
	// provider says it checked two distinct kinds, and that is the evidence.
	tok := p.token(t, map[string]any{"preferred_username": "alice", "amr": []string{"pwd", "otp"}})
	if code, creds := bindWithToken(t, r, "", tok); code != ldap.LDAPResultSuccess {
		t.Errorf("the token bind answered %d (%s)\n%s", code, creds, r.out.String())
	}
}

func TestATokenForSomebodyThisDirectoryDoesNotHaveIsRefused(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")

	tok := p.token(t, map[string]any{"preferred_username": "mallory"})
	code, creds := bindWithToken(t, r, "", tok)
	if code == ldap.LDAPResultSuccess {
		t.Fatal("a token for somebody nobody publishes bound")
	}
	// The client is told the token is not good, and nothing about who exists.
	if !strings.Contains(string(creds), "invalid_token") {
		t.Errorf("the challenge was %q", creds)
	}
	if strings.Contains(string(creds), "mallory") || strings.Contains(string(creds), "no source") {
		t.Errorf("the challenge told the client why: %q", creds)
	}
	// The reason is in the server's own output, where an administrator is.
	if !strings.Contains(r.out.String(), "no source here publishes") {
		t.Errorf("the server did not say why in its own log:\n%s", r.out.String())
	}
}

func TestATokenSignedByTheWrongKeyIsRefused(t *testing.T) {
	p := newProvider(t)
	other := newProvider(t) // a different key, not in p's key set
	r := oidcServer(t, p, "", "")

	tok := other.signWith(t, other.key,
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": p.kid},
		map[string]any{
			"iss": p.issuer(), "aud": "ldap", "sub": "x",
			"preferred_username": "alice",
			"iat":                time.Now().Unix(),
			"exp":                time.Now().Add(time.Hour).Unix(),
		})
	if code, _ := bindWithToken(t, r, "", tok); code == ldap.LDAPResultSuccess {
		t.Fatal("a token signed by a key this provider does not publish bound")
	}
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")

	tok := p.token(t, map[string]any{
		"preferred_username": "alice",
		"exp":                time.Now().Add(-time.Hour).Unix(),
		"iat":                time.Now().Add(-2 * time.Hour).Unix(),
	})
	if code, _ := bindWithToken(t, r, "", tok); code == ldap.LDAPResultSuccess {
		t.Fatal("an expired token bound")
	}
}

func TestATokenForAnotherAudienceIsRefused(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")

	tok := p.token(t, map[string]any{"preferred_username": "alice", "aud": "somebody-else"})
	if code, _ := bindWithToken(t, r, "", tok); code == ldap.LDAPResultSuccess {
		t.Fatal("a token addressed to another service bound")
	}
}

// ⛔ The GS2 header may ask to act as somebody else. A token for alice
// carrying a request to be bob is refused, not quietly treated as alice --
// and certainly not as bob.
func TestATokenMayNotAskToBeSomebodyElse(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")

	tok := p.token(t, map[string]any{"preferred_username": "alice"})
	code, _ := bindWithToken(t, r, "bob", tok)
	if code == ldap.LDAPResultSuccess {
		t.Fatal("a token for alice bound while asking to be bob")
	}
	if !strings.Contains(r.out.String(), "does not delegate") {
		t.Errorf("the server did not say why:\n%s", r.out.String())
	}
}

// The authzid naming the SAME person is not a request to act as anybody, and
// several clients send it as a matter of course.
func TestAnAuthzidThatNamesTheSamePersonIsFine(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")

	tok := p.token(t, map[string]any{"preferred_username": "alice"})
	if code, creds := bindWithToken(t, r, "alice", tok); code != ldap.LDAPResultSuccess {
		t.Fatalf("answered %d (%s); the server said: %s", code, creds, r.out.String())
	}
}

// ⛔ What the issuer says it did is the ONLY evidence there is about how many
// factors answered. A policy that asks for two distinct kinds is satisfied by
// a token whose amr says a password and a one-time code, and refused by one
// that says nothing -- because a bare token is one thing, and deciding
// otherwise would mean this server inventing a factor nobody performed.
func TestTwoFactorPolicyReadsTheIssuersAmr(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", `
mfa {
  factors        = 2
  distinct_kinds = true
}
`)
	for _, tc := range []struct {
		what string
		amr  any
		want bool
	}{
		{"no amr at all", nil, false},
		{"one method", []string{"pwd"}, false},
		{"two of the SAME kind", []string{"pwd", "pin"}, false},
		{"two distinct kinds", []string{"pwd", "otp"}, true},
		{"a method nothing here classifies", []string{"pwd", "quantum"}, false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			claims := map[string]any{"preferred_username": "alice"}
			if tc.amr != nil {
				claims["amr"] = tc.amr
			}
			code, _ := bindWithToken(t, r, "", p.token(t, claims))
			if got := code == ldap.LDAPResultSuccess; got != tc.want {
				t.Errorf("%s: bound=%v, want %v (answered %d)\n%s", tc.what, got, tc.want, code, r.out.String())
			}
		})
	}
}

// A mechanism this server does not speak is refused with the code that means
// "not this way", which sends a client somewhere different from "wrong
// password".
func TestAnUnknownMechanismSaysSoRatherThanRefusingCredentials(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")

	c, err := ldap.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	code, _, _ := c.SASLBind("", "GSSAPI", []byte("whatever"))
	if code != ldap.LDAPResultAuthMethodNotSupported {
		t.Errorf("answered %d, want authMethodNotSupported (%d)", code, ldap.LDAPResultAuthMethodNotSupported)
	}
}

// A server with no oidc block answers every SASL bind the same way: not this
// way. It does not refuse credentials, because none were judged.
func TestWithNoOIDCBlockEverySASLBindIsUnsupported(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }
`)
	c, err := ldap.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	code, _, _ := c.SASLBind("", oauthBearer, oauthBearerCredentials("", "anything"))
	if code != ldap.LDAPResultAuthMethodNotSupported {
		t.Errorf("answered %d, want authMethodNotSupported", code)
	}
}

// RFC 7628 3.2.3: a refusal is a JSON error the client answers with a single
// ^A, and only then does the exchange end. A client that follows the standard
// must reach a final failure rather than hang.
func TestTheFailureExchangeEndsTheWayTheStandardSaysItDoes(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")

	c, err := ldap.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	code, creds, _ := c.SASLBind("", oauthBearer, oauthBearerCredentials("", "not a token"))
	if code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("a refusal answered %d, want saslBindInProgress so the client can finish", code)
	}
	if !strings.Contains(string(creds), `"status":"invalid_token"`) {
		t.Errorf("the challenge is %q", creds)
	}
	if !strings.Contains(string(creds), "openid-configuration") {
		t.Errorf("the challenge does not say where to ask: %q", creds)
	}

	// The dummy response that ends it.
	code, _, _ = c.SASLBind("", oauthBearer, []byte(kvsep))
	if code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("the exchange ended with %d, want invalidCredentials", code)
	}
}

// ⛔ A bearer token needs no second half: whoever reads it off the wire is
// that person until it expires. The default refuses the mechanism on a
// connection that is not encrypted, and says which code means that.
func TestATokenIsRefusedInTheClearByDefault(t *testing.T) {
	p := newProvider(t)
	r := start(t, fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }

oidc {
  issuer   = %q
  audience = "ldap"
}
`, p.issuer()))

	tok := p.token(t, map[string]any{"preferred_username": "alice"})
	code, _ := bindWithToken(t, r, "", tok)
	if code != ldap.LDAPResultConfidentialityRequired {
		t.Errorf("answered %d, want confidentialityRequired (%d)", code, ldap.LDAPResultConfidentialityRequired)
	}
	if !strings.Contains(r.out.String(), "not encrypted") {
		t.Errorf("the server did not say why:\n%s", r.out.String())
	}
}

// `check` is read before a restart, by somebody deciding whether to do one.
// It has to say that tokens are accepted, and the two things about them that
// surprise people.
func TestCheckSaysWhatATokenBuys(t *testing.T) {
	p := newProvider(t)
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", `
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

	for _, want := range []string{
		"or a token from " + p.issuer(),
		oauthBearer,
		"amr",             // a token counts for what the issuer says it did
		"allow_plaintext", // and this configuration lets one cross in the clear
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check never mentions %q:\n%s", want, out)
		}
	}
}
