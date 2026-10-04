// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-authn/ldap"
)

// ⛔ A password change proves the password it replaces.
//
// A session can be bound by something that is not the password: an
// OAUTHBEARER token is short-lived, may be single-factor, and is held by
// whatever the identity provider handed it to. Before this, such a session
// could set a PERMANENT password that then worked for LDAP binds and for kinit
// alike -- a bearer token turned into a password nobody had to know.
//
// The policy is OpenLDAP's ppolicy with pwdSafeModify set (slapo-ppolicy(5)),
// which RFC 3062 section 3 allows: "If oldPasswd is not present, the server
// MAY use other policy to determine whether or not to change the password."
// A present one that "cannot be verified or is incorrect" already obliges the
// server not to change it. The result codes are the ones ppolicy.c returns:
//
//   - the old password missing:  insufficientAccessRights
//     ("Must supply old password to be changed as well as new one")
//   - the old password wrong:    unwillingToPerform
//     ("Must supply correct old password to change to new one")

// passwdModifyWithOld is an RFC 3062 value carrying oldPasswd. An empty
// identity is left out, which means "this connection".
func passwdModifyWithOld(identity, old, newPassword string) []byte {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	if identity != "" {
		seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
			ber.Tag(tagUserIdentity), identity, ""))
	}
	seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
		ber.Tag(tagOldPasswd), old, ""))
	seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
		ber.Tag(tagNewPasswd), newPassword, ""))
	return seq.Bytes()
}

// safeChange is the RFC 4511 4.6 shape that proves the old value: delete it,
// then add the new one, in ONE modify -- atomic, so the delete fails, and the
// whole request with it, unless the value deleted is the one held.
func safeChange(old, newPassword string) []ldap.Change {
	return []ldap.Change{
		{Operation: ldap.DeleteValues,
			Attribute: &ldap.Attribute{Name: "userPassword", Values: [][]byte{[]byte(old)}}},
		{Operation: ldap.AddValues,
			Attribute: &ldap.Attribute{Name: "userPassword", Values: [][]byte{[]byte(newPassword)}}},
	}
}

func TestPasswordModifyRequiresTheOldPassword(t *testing.T) {
	t.Parallel()
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }
`)
	alice := "uid=alice,ou=people,dc=example,dc=org"
	c := client(t, r)
	defer c.Close()
	if res, _ := c.Bind(alice, "hunter2"); res.Code != ldap.Success {
		t.Fatalf("binding: %s", res.Code)
	}

	// No oldPasswd at all.
	if res, err := c.Extended(ldap.OIDPasswordModify,
		passwdModifyValue("", "taken over")); err != nil || res.Code != ldap.InsufficientAccessRights {
		t.Errorf("no old password: %s %v", res.Code, err)
	} else if !strings.Contains(res.Diagnostic, "old password") {
		t.Errorf("the refusal does not say what is missing: %q", res.Diagnostic)
	}
	// A wrong one, and an empty one, which is present and wrong.
	for _, old := range []string{"hunter3", ""} {
		if res, err := c.Extended(ldap.OIDPasswordModify,
			passwdModifyWithOld("", old, "taken over")); err != nil || res.Code != ldap.UnwillingToPerform {
			t.Errorf("old password %q: %s %v", old, res.Code, err)
		}
	}
	fresh := client(t, r)
	defer fresh.Close()
	if res, _ := fresh.Bind(alice, "hunter2"); res.Code != ldap.Success {
		t.Fatalf("a refused change changed the password anyway: %s", res.Code)
	}

	// The right one.
	if res, err := c.Extended(ldap.OIDPasswordModify,
		passwdModifyWithOld(alice, "hunter2", "correct horse")); err != nil || res.Code != ldap.Success {
		t.Fatalf("with the right old password: %s %v", res.Code, err)
	}
	if res, _ := fresh.Bind(alice, "correct horse"); res.Code != ldap.Success {
		t.Errorf("the new password does not bind: %s", res.Code)
	}
	// ⛔ The proof is checked against the password held NOW: the one just
	// replaced proves nothing any more.
	if res, err := c.Extended(ldap.OIDPasswordModify,
		passwdModifyWithOld("", "hunter2", "again")); err != nil || res.Code != ldap.UnwillingToPerform {
		t.Errorf("the previous password as proof: %s %v", res.Code, err)
	}
}

func TestModifyRequiresDeleteOfTheOldValueAndAddOfTheNew(t *testing.T) {
	t.Parallel()
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }
`)
	alice := "uid=alice,ou=people,dc=example,dc=org"
	ctx := context.Background()
	modify := func(changes []ldap.Change) ldap.WriteResult {
		t.Helper()
		res, err := r.srv.Modify(ctx, session{dn: alice}, &ldap.ModifyRequest{DN: alice, Changes: changes})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	if res := modify(replace("userPassword", "taken over")); res.Code != ldap.InsufficientAccessRights {
		t.Errorf("a bare replace: %s %q", res.Code, res.Diagnostic)
	}
	if res := modify(safeChange("hunter3", "taken over")); res.Code != ldap.UnwillingToPerform {
		t.Errorf("deleting a value that is not the password: %s %q", res.Code, res.Diagnostic)
	}
	// A delete of EVERY value names nothing, so it proves nothing.
	deleteAll := []ldap.Change{
		{Operation: ldap.DeleteValues, Attribute: &ldap.Attribute{Name: "userPassword"}},
		{Operation: ldap.AddValues,
			Attribute: &ldap.Attribute{Name: "userPassword", Values: [][]byte{[]byte("taken over")}}},
	}
	if res := modify(deleteAll); res.Code == ldap.Success {
		t.Errorf("delete-all then add was accepted")
	}
	// The add before the delete is a different request: RFC 4511 applies the
	// changes in order, and that one adds a second password before removing
	// one.
	backwards := safeChange("hunter2", "taken over")
	backwards[0], backwards[1] = backwards[1], backwards[0]
	if res := modify(backwards); res.Code == ldap.Success {
		t.Errorf("add then delete was accepted")
	}

	c := client(t, r)
	defer c.Close()
	if res, _ := c.Bind(alice, "hunter2"); res.Code != ldap.Success {
		t.Fatalf("a refused change changed the password anyway: %s", res.Code)
	}

	if res := modify(safeChange("hunter2", "correct horse")); res.Code != ldap.Success {
		t.Fatalf("delete the old, add the new: %s %q", res.Code, res.Diagnostic)
	}
	if res, _ := c.Bind(alice, "correct horse"); res.Code != ldap.Success {
		t.Errorf("the new password does not bind: %s", res.Code)
	}
}

// The audit's case: a session bound with a token, not a password.
func TestATokenBoundSessionMustStillProveThePassword(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")
	alice := "uid=alice,ou=people,dc=example,dc=org"

	c := client(t, r)
	defer c.Close()
	step, err := c.BindSASL(oauthBearer, oauthBearerCredentials("",
		p.token(t, map[string]any{"preferred_username": "alice"})))
	if err != nil || step.Code != ldap.Success {
		t.Fatalf("the token bind: %s %v\n%s", step.Code, err, r.out.String())
	}
	if res, err := c.Extended(ldap.OIDPasswordModify,
		passwdModifyValue("", "a permanent one")); err != nil || res.Code == ldap.Success {
		t.Errorf("a token alone set a password: %s %v", res.Code, err)
	}
	fresh := client(t, r)
	defer fresh.Close()
	if res, _ := fresh.Bind(alice, "a permanent one"); res.Code == ldap.Success {
		t.Fatal("the password a token set binds")
	}
	// Knowing the password is what it takes, however the session was bound.
	if res, err := c.Extended(ldap.OIDPasswordModify,
		passwdModifyWithOld("", "hunter2", "a permanent one")); err != nil || res.Code != ldap.Success {
		t.Errorf("a token-bound session that knows the password: %s %v", res.Code, err)
	}
}

// ⛔ Somebody with no password at all is proved only by a token, and a token
// may not become the first password either: there is nothing to prove, and a
// bearer token is not a password.
func TestNoFirstPasswordFromAToken(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", `user "olga" {}`+"\n")
	olga := "uid=olga,ou=people,dc=example,dc=org"

	c := client(t, r)
	defer c.Close()
	step, err := c.BindSASL(oauthBearer, oauthBearerCredentials("",
		p.token(t, map[string]any{"preferred_username": "olga"})))
	if err != nil || step.Code != ldap.Success {
		t.Fatalf("the token bind: %s %v\n%s", step.Code, err, r.out.String())
	}
	for name, value := range map[string][]byte{
		"no old password":     passwdModifyValue("", "first"),
		"an empty old one":    passwdModifyWithOld("", "", "first"),
		"an invented old one": passwdModifyWithOld(olga, "anything", "first"),
	} {
		res, err := c.Extended(ldap.OIDPasswordModify, value)
		if err != nil || res.Code != ldap.UnwillingToPerform {
			t.Errorf("%s: %s %v", name, res.Code, err)
			continue
		}
		if !strings.Contains(res.Diagnostic, "bearer token is not a password") {
			t.Errorf("%s: the refusal does not say why: %q", name, res.Diagnostic)
		}
	}
	res, err := r.srv.Modify(context.Background(), session{dn: olga},
		&ldap.ModifyRequest{DN: olga, Changes: replace("userPassword", "first")})
	if err != nil || res.Code != ldap.UnwillingToPerform ||
		!strings.Contains(res.Diagnostic, "bearer token is not a password") {
		t.Errorf("modify: %s %q %v", res.Code, res.Diagnostic, err)
	}
	if got, _ := client(t, r).Bind(olga, "first"); got.Code == ldap.Success {
		t.Error("a first password set from a token binds")
	}
}

// constantTimeEqual compares digests, so inputs of different lengths reach
// subtle.ConstantTimeCompare as two 32-byte values. The timing is not
// something a unit test can measure; what it can hold is that hashing first
// changed no answer.
func TestConstantTimeEqualAnswersLikeEquality(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"hunter2", "hunter2", true},
		{"", "", true},
		{"hunter2", "hunter3", false},
		{"hunter2", "hunter23", false},
		{"hunter2", "", false},
		{"", "hunter2", false},
	} {
		if got := constantTimeEqual(tc.a, tc.b); got != tc.want {
			t.Errorf("constantTimeEqual(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

// ⛔ The proof is checked without the lock and the write is made under it, so
// two changes sent with the same old password can both pass the check. The
// second must not then be written: its proof is the password the first one
// replaced.
func TestTwoChangesWithTheSameProofDoNotBothSucceed(t *testing.T) {
	t.Parallel()
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }
user "bob"   { password = "hunter2" }
`)
	first, _, ok := r.srv.provesPassword("alice", "hunter2", true)
	second, _, ok2 := r.srv.provesPassword("alice", "hunter2", true)
	if !ok || !ok2 {
		t.Fatal("the right old password did not prove it")
	}
	r.srv.mu.Lock()
	defer r.srv.mu.Unlock()
	if res, ok := r.srv.writeProved("alice", first, "hunter2", "one"); !ok {
		t.Fatalf("the first change: %s %q", res.Code, res.Diagnostic)
	}
	if res, ok := r.srv.writeProved("alice", second, "hunter2", "two"); ok || res.Code != ldap.UnwillingToPerform {
		t.Errorf("the second change, proved by the password the first replaced: %s %v", res.Code, ok)
	}
	// Somebody ELSE's change rebuilds every identity the file holds, and must
	// not refuse a proof that is still right.
	bob, _, _ := r.srv.provesPassword("bob", "hunter2", true)
	if _, ok := r.srv.writeProved("alice", r.srv.who()["alice"], "one", "three"); !ok {
		t.Fatal("alice's next change")
	}
	if res, ok := r.srv.writeProved("bob", bob, "hunter2", "bob's new"); !ok {
		t.Errorf("bob's change after alice's: %s %q", res.Code, res.Diagnostic)
	}
	// And somebody this server does not serve proves nothing.
	if _, res, ok := r.srv.provesPassword("nobody", "x", true); ok || res.Code != ldap.InsufficientAccessRights {
		t.Errorf("nobody: %s %v", res.Code, ok)
	}
}
