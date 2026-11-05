// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"

	"github.com/go-authn/ldap"
)

// Security audit 2026-11-05. Behind a federation proxy (eduGAIN through
// MyAccessID, eduTEAMS, a Keycloak broker) one issuer vouches for people of
// many institutions, and "alice" at univ-b.example is not the local alice.
// The server mapped an UNSCOPED tok.Username() straight onto directory names,
// so any institution's "alice" bound as the local alice.
func TestATokenOfAnotherInstitutionsAliceDoesNotBindAsTheLocalAlice(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")

	tok := p.token(t, map[string]any{
		"preferred_username":       "alice",
		"eduperson_principal_name": "alice@univ-b.example",
	})
	if code, creds := bindWithToken(t, r, "", tok); code == ldap.Success {
		t.Fatalf("alice of univ-b.example bound as the local alice (%s)", creds)
	}
}

func TestOnlyAScopedNameOfAnAllowedDomainBinds(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "  username_claim = \"eduperson_principal_name\"\n", "")
	for _, tc := range []struct {
		eppn string
		ok   bool
	}{
		{"alice@univ-a.example", true},
		{"Alice@UNIV-A.example", true},                 // a uid and a scope are caseIgnoreMatch
		{"alice", false},                               // unscoped: whose alice?
		{"alice@univ-b.example", false},                // another institution's
		{"alice@univ-a.example@univ-b.example", false}, // two @
		{"admin@evil.example@univ-a.example", false},
	} {
		t.Run(tc.eppn, func(t *testing.T) {
			tok := p.token(t, map[string]any{"eduperson_principal_name": tc.eppn})
			code, _ := bindWithToken(t, r, "", tok)
			if (code == ldap.Success) != tc.ok {
				t.Errorf("%q answered %s, bound = %v, want %v\n%s", tc.eppn, code, code == ldap.Success, tc.ok, r.out.String())
			}
		})
	}
}

// A person of another domain is published under the whole local@scope name,
// and only that name reaches them.
func TestAPersonOfAnotherAllowedDomainIsLookedUpByTheWholeName(t *testing.T) {
	p := newProvider(t)
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice"                { password = "hunter2" }
user "alice@univ-b.example" { password = "correct horse" }
oidc {
  issuer          = "`+p.issuer()+`"
  audience        = "ldap"
  allow_plaintext = true
  domains         = ["univ-a.example", "univ-b.example"]
  local_domain    = "univ-a.example"
}
`)
	for eppn, want := range map[string]bool{"alice@univ-a.example": true, "alice@univ-b.example": true, "bob@univ-b.example": false} {
		tok := p.token(t, map[string]any{"preferred_username": eppn})
		if code, _ := bindWithToken(t, r, "", tok); (code == ldap.Success) != want {
			t.Errorf("%s answered %s, want bound = %v\n%s", eppn, code, want, r.out.String())
		}
	}
}

// No domain configured: the server does not start, rather than guess.
func TestAnOIDCBlockWithNoDomainIsRefused(t *testing.T) {
	p := newProvider(t)
	for name, block := range map[string]string{
		"none":                       "",
		"a bad scope":                `domains = ["a@b"]`,
		"a local_domain not in list": `domains = ["univ-a.example"]` + "\n" + `local_domain = "univ-b.example"`,
	} {
		t.Run(name, func(t *testing.T) {
			path := write(t, t.TempDir(), "c.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }
oidc {
  issuer   = "`+p.issuer()+`"
  audience = "ldap"
  `+block+`
}
`)
			out, err := execute(t, "check", path)
			if err == nil {
				t.Fatalf("check accepted it:\n%s", out)
			}
			if !strings.Contains(err.Error()+out, "domains") && !strings.Contains(err.Error()+out, "local_domain") {
				t.Errorf("the refusal does not name the setting: %v\n%s", err, out)
			}
		})
	}
}
