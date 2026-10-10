//go:build !nosql

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/go-authn/ldap"
)

// A refused password change names the person's OWN source. v0.9.6 named the
// whole set -- "dora is served from the configuration file, then a sqlite
// database" -- a file that does not hold her.
func TestAPasswordRefusalNamesThePersonsOwnSource(t *testing.T) {
	r := start(t, peopleConfig(t, t.TempDir(), ""))
	dora := "uid=dora,ou=people,dc=example,dc=org"
	res, err := r.srv.Modify(context.Background(), session{dn: dora},
		&ldap.ModifyRequest{DN: dora, Changes: safeChange("hunter2", "x")})
	if err != nil || res.Code != ldap.UnwillingToPerform {
		t.Fatalf("a person from the database: %s %v", res.Code, err)
	}
	if want := "dora is served from " + peopleFrom + ","; !strings.Contains(res.Diagnostic, want) {
		t.Errorf("want %q in the refusal, got %q", want, res.Diagnostic)
	}
	if strings.Contains(res.Diagnostic, "configuration file") {
		t.Errorf("the refusal names the configuration file, which does not hold dora: %q", res.Diagnostic)
	}
}
