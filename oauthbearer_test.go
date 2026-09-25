// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"

	"github.com/go-authn/mfa"
)

// ⛔ Everything here is a byte string a client can send to an unauthenticated
// bind. The parser's refusals were the least-tested code in this server --
// which is the wrong way round, because a refusal that is wrong either lets
// something through or rejects somebody who should be let in, and neither
// announces itself.
func TestTheCredentialsThatAreNotCredentials(t *testing.T) {
	for _, tc := range []struct {
		what  string
		creds string
		says  string
	}{
		{"nothing at all", "", "no credentials at all"},
		{"no separator", "n,,auth=Bearer x", "carry no"},
		{"a GS2 header with no comma", "n\x01auth=Bearer x\x01\x01", "no comma in it"},
		{"a GS2 header that ends early", "n,\x01auth=Bearer x\x01\x01", "ends early"},
		{"a flag that is not one", "z,,\x01auth=Bearer x\x01\x01", "not a channel-binding flag"},
		{"something that is not an authzid", "n,b=alice,\x01auth=Bearer x\x01\x01", "not an authzid"},
		{"an auth scheme that is not Bearer", "n,,\x01auth=Basic abc\x01\x01", "carries a Bearer token"},
		{"an auth key with no scheme at all", "n,,\x01auth=justatoken\x01\x01", "carries a Bearer token"},
		{"an empty token", "n,,\x01auth=Bearer \x01\x01", "empty token"},
		{"no auth key", "n,,\x01host=example.org\x01\x01", "no auth key"},
	} {
		_, _, err := parseOAuthBearer([]byte(tc.creds))
		if err == nil {
			t.Errorf("%s was accepted", tc.what)
			continue
		}
		if !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s was refused for the wrong reason: %v", tc.what, err)
		}
	}
}

// ⛔ "p=" means the client INSISTS on channel binding. Accepting it while
// binding nothing is how a downgrade goes unnoticed: the client believes the
// channel was checked and it was not.
func TestAClientThatDemandsChannelBindingIsRefused(t *testing.T) {
	_, _, err := parseOAuthBearer([]byte("p=tls-unique,,\x01auth=Bearer x\x01\x01"))
	if err == nil {
		t.Fatal("a demand for channel binding was accepted by a server that does none")
	}
	if !strings.Contains(err.Error(), "channel binding") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	// "y" is the client saying it believes the server does not support it,
	// which this server may answer.
	if _, _, err := parseOAuthBearer([]byte("y,,\x01auth=Bearer x\x01\x01")); err != nil {
		t.Errorf("a `y` flag was refused: %v", err)
	}
}

// RFC 7628 3.1: "Unknown key/value pairs MUST be ignored by the server." A
// parser that refused them would break the first time a provider added one.
func TestUnknownKeysAreIgnoredRatherThanRefused(t *testing.T) {
	authzid, token, err := parseOAuthBearer([]byte(
		"n,a=alice,\x01host=example.org\x01port=636\x01auth=Bearer tok\x01future=whatever\x01\x01"))
	if err != nil {
		t.Fatalf("a credential carrying extra keys was refused: %v", err)
	}
	if token != "tok" || authzid != "alice" {
		t.Errorf("came back as authzid=%q token=%q", authzid, token)
	}
	// A field with no '=' at all is skipped, not fatal: it is what the
	// trailing separator leaves behind.
	if _, tok, err := parseOAuthBearer([]byte("n,,\x01\x01auth=Bearer tok\x01\x01")); err != nil || tok != "tok" {
		t.Errorf("an empty field broke the parse: %v", err)
	}
}

// ⛔ RFC 5801 4: "=2C" is a comma and "=3D" an equals sign, because both are
// separators in a GS2 header. A name that arrives with either left unescaped
// is a DIFFERENT name from the one that was sent -- and this one is compared
// against the token's username to decide whether somebody is asking to act
// as somebody else.
func TestTheAuthzidIsUnescaped(t *testing.T) {
	for _, tc := range []struct{ sent, want string }{
		{"alice", "alice"},
		{"Smith=2C John", "Smith, John"},
		{"a=3Db", "a=b"},
		{"=2C=3D", ",="},
	} {
		got, _, err := parseOAuthBearer([]byte("n,a=" + tc.sent + ",\x01auth=Bearer t\x01\x01"))
		if err != nil {
			t.Errorf("%q: %v", tc.sent, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q came back as %q, want %q", tc.sent, got, tc.want)
		}
	}
	// And what this package WRITES survives its own reader.
	for _, name := range []string{"alice", "Smith, John", "a=b", ""} {
		got, _, err := parseOAuthBearer(oauthBearerCredentials(name, "tok"))
		if err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		if got != name {
			t.Errorf("%q round-tripped to %q", name, got)
		}
	}
}

// ⛔ RFC 8176's methods, mapped to the kinds a policy counts. The mapping is
// the whole of what a token is worth: get `fpt` wrong and a fingerprint
// stops being a factor of its own kind, so a two-factor policy either
// refuses somebody who satisfied it or accepts somebody who did not.
func TestEveryAuthenticationMethodLandsInAKind(t *testing.T) {
	for _, tc := range []struct {
		method string
		want   mfa.Kind
	}{
		{"pwd", mfa.Knowledge}, {"pin", mfa.Knowledge}, {"kba", mfa.Knowledge}, {"mca", mfa.Knowledge},
		{"otp", mfa.Possession}, {"hwk", mfa.Possession}, {"swk", mfa.Possession},
		{"sms", mfa.Possession}, {"tel", mfa.Possession}, {"sc", mfa.Possession},
		{"fpt", mfa.Inherence}, {"face", mfa.Inherence}, {"iris", mfa.Inherence},
		{"retina", mfa.Inherence}, {"vbm", mfa.Inherence}, {"geo", mfa.Inherence},
		{"PWD", mfa.Knowledge}, // the registry is lower-case; a provider may not be
		{"quantum", mfa.Unknown},
		{"", mfa.Unknown},
	} {
		if got := amrKind(tc.method); got != tc.want {
			t.Errorf("amr %q is %v, want %v", tc.method, got, tc.want)
		}
	}
	// ⛔ An Unknown method must never satisfy a distinct-kinds policy: an
	// unclassified factor cannot be shown to DIFFER from another one.
	if amrKind("quantum") != mfa.Unknown {
		t.Error("a method nothing here classifies was given a kind")
	}
}

// Mechanisms is what the root DSE advertises. A mechanism missing there is
// one nothing will ever try; one advertised that the server cannot answer
// sends a client down a path ending in authMethodNotSupported.
func TestOnlyAConfiguredServerAdvertisesTheMechanism(t *testing.T) {
	if got := (&server{}).Mechanisms(); got != nil {
		t.Errorf("a server with no oidc block advertises %v", got)
	}
	s := &server{oidc: &oidcAuth{cfg: &oidcBlock{}}}
	got := s.Mechanisms()
	if len(got) != 1 || got[0] != oauthBearer {
		t.Errorf("a configured server advertises %v", got)
	}
}
