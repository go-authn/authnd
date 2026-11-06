// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"github.com/go-authn/ldap"
)

// Security audit 2026-11-06 (untracked proof). oidc.ScopedName folds ASCII
// only ("U+212A is not a k"), but the bind's fallback (oidc.go:237-241) looks
// the name up with strings.EqualFold, a Unicode fold: a token naming
// "Kate@univ-a.example" (KELVIN SIGN) -- a different account at the
// issuer -- binds as the local "kate".
func TestSecAuditKelvinSignBindsAsKate(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", `user "kate" { password = "kates own" }`)
	tok := p.token(t, map[string]any{"preferred_username": "Kate@univ-a.example"})
	if code, _ := bindWithToken(t, r, "", tok); code == ldap.Success {
		t.Errorf("a token for \\u212Aate bound as kate; the server said: %s", r.out.String())
	}
}
