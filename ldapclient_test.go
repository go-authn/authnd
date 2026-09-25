// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/go-authn/ldap/ldaptest"
)

// The wire client comes from go-authn/ldap/ldaptest now.
//
// ⛔ It is not the judge. OpenLDAP's own ldapsearch is, and it is what the
// tests in tls_test.go and roundtrip_test.go use: a client from the same
// module as the server can agree with it about a misreading of the protocol
// and both be wrong. This is for the questions ldapsearch cannot ask -- a
// SASL bind with an arbitrary mechanism, and two binds on ONE connection.
func client(t *testing.T, r *running) *ldaptest.Client {
	t.Helper()
	c, err := ldaptest.Dial(r.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Every exchange is bounded, so a server that stops answering FAILS
	// rather than hangs: a test that hangs is one somebody cancels, and a
	// cancelled test is never diagnosed.
	if err := c.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// upgraded dials and completes a StartTLS, for the tests about what a
// protected connection may do that a plaintext one may not.
func upgraded(t *testing.T, r *running) *ldaptest.Client {
	t.Helper()
	c := client(t, r)
	res, err := c.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("StartTLS: %v", err)
	}
	if !res.Code.OK() {
		t.Fatalf("StartTLS answered %s", res.Code)
	}
	return c
}
