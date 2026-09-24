// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-authn/ldap"
	"github.com/go-authn/mfa"
	"github.com/go-authn/oidc"
)

// OIDC at the bind, in the field a token belongs in.
//
// ⛔ A simple bind carries a name and a password and nothing else, so an
// appliance that accepts a token puts it in the password field. That works
// once and then stops: the password field is also where this server's `mfa`
// block takes the one-time code off the end, and a token cannot be both. The
// choice is not between "token in the password" and "no OIDC" -- it is
// between reusing a field that is already spoken for and using the one the
// protocol has for exactly this.
//
// RFC 7628 is that field. A SASL bind's credentials are an OCTET STRING of
// the mechanism's own shape, and OAUTHBEARER's shape is a GS2 header followed
// by key/value pairs of which one is `auth=Bearer <token>`. The password
// field is left alone, which is the whole point: a deployment can keep asking
// for a password and a code from the people who bind that way, and accept a
// token from the ones who do not.
//
// The library this server uses refused every SASL bind until go-authn taught
// it the optional SASLBinder interface; see the comment on BindSASL.

// The mechanism name, from the IANA SASL mechanism registry.
const oauthBearer = "OAUTHBEARER"

// kvsep is RFC 7628's separator: a single ^A between the GS2 header, each
// key/value pair, and the end.
const kvsep = "\x01"

// oidcBlock is the `oidc` block of the configuration.
type oidcBlock struct {
	// Issuer is the "iss" a token must carry, and where discovery starts.
	Issuer string `hcl:"issuer"`
	// Audience is what the token must be addressed to: this server's client
	// id at the provider.
	Audience string `hcl:"audience"`

	// JWKSURL skips discovery for a provider that does not publish one.
	JWKSURL string `hcl:"jwks_url,optional"`
	// UsernameClaim is which claim names the person in THIS directory.
	// go-authn/oidc's default order is preferred_username, email, sub.
	UsernameClaim string `hcl:"username_claim,optional"`

	// AllowPlaintext lets a token be accepted over a connection that is not
	// encrypted.
	//
	// ⛔ A bearer token is a credential that needs no other half: whoever
	// reads it off the wire is that person until it expires. A password at
	// least has to be replayed against this server, which can notice. The
	// default is to refuse the mechanism on a plain connection, and this
	// exists for a deployment that terminates TLS in front of this process
	// -- where the statement being made is "the link this process sees is
	// not the link the client sees", which is the deployment's to make.
	AllowPlaintext bool `hcl:"allow_plaintext,optional"`
}

// oidcAuth is what a configured `oidc` block became.
type oidcAuth struct {
	cfg      *oidcBlock
	verifier *oidc.Verifier
	// discovery is the URL a failed bind points the client at, so a client
	// that got a token for the wrong issuer can find out where to ask.
	discovery string
}

// openOIDC prepares to verify tokens, at startup.
//
// Discovery happens HERE and not at the first bind, for the reason
// go-authn/oidc gives: a server whose provider is unreachable should fail to
// start, where somebody is watching, rather than fail every bind at three in
// the morning.
func openOIDC(b *oidcBlock) (*oidcAuth, error) {
	if b == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v, err := oidc.New(ctx, oidc.Config{
		Issuer:        b.Issuer,
		Audience:      b.Audience,
		JWKSURL:       b.JWKSURL,
		UsernameClaim: b.UsernameClaim,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc %q: %w", b.Issuer, err)
	}
	return &oidcAuth{
		cfg:       b,
		verifier:  v,
		discovery: strings.TrimSuffix(b.Issuer, "/") + "/.well-known/openid-configuration",
	}, nil
}

// BindSASL answers a SASL bind, which for this server means OAUTHBEARER.
//
// It is the optional half of the library's Binder. A server with no `oidc`
// block answers authMethodNotSupported to every mechanism, which tells a
// client "not this way" rather than "wrong password" -- and those send it to
// different places: one is a reason to try again, the other is not.
func (s *server) BindSASL(_, mechanism string, credentials []byte, conn net.Conn) (ldap.SASLBindResult, error) {
	s.mu.Lock()
	s.binds++
	s.mu.Unlock()

	if s.oidc == nil || mechanism != oauthBearer {
		return ldap.SASLBindResult{Code: ldap.LDAPResultAuthMethodNotSupported}, nil
	}
	// RFC 7628 3.2.3: after a failure the server sends a JSON error and the
	// client answers with a single ^A, which exists only to let the exchange
	// end tidily. Anything that arrives as a lone ^A is that, or is a client
	// that started at the end; both are refused, and neither needs this
	// server to remember anything about the connection.
	if string(credentials) == kvsep {
		return ldap.SASLBindResult{Code: ldap.LDAPResultInvalidCredentials}, nil
	}
	if _, ok := conn.(*tls.Conn); !ok && !s.oidc.cfg.AllowPlaintext {
		s.refused("a token", fmt.Errorf("%s was offered over a connection that is not encrypted, and allow_plaintext is not set", oauthBearer))
		return ldap.SASLBindResult{Code: ldap.LDAPResultConfidentialityRequired}, nil
	}

	authzid, token, err := parseOAuthBearer(credentials)
	if err != nil {
		s.refused("a token", err)
		return s.oidcChallenge("invalid_request"), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := s.oidc.verifier.Verify(ctx, token)
	if err != nil {
		s.refused("a token", err)
		return s.oidcChallenge("invalid_token"), nil
	}

	name := tok.Username()
	if name == "" {
		s.refused("a token", fmt.Errorf("the token names nobody: no %s, email or sub", s.oidc.cfg.UsernameClaim))
		return s.oidcChallenge("invalid_token"), nil
	}
	// ⛔ The GS2 header may name somebody to act AS, which is a different
	// request from "this is me" -- RFC 5801 calls it the authzid. Nothing
	// here grants it, so a token for one person carrying a request to be
	// another is refused rather than quietly treated as the first.
	if authzid != "" && !strings.EqualFold(authzid, name) {
		s.refused(name, fmt.Errorf("the token is for %q and asks to act as %q; this server does not delegate", name, authzid))
		return s.oidcChallenge("insufficient_scope"), nil
	}
	id, ok := s.who[name]
	if !ok {
		// The token is good and the person is not here. Said to the log,
		// because a client that learns which names exist has been handed the
		// directory one guess at a time.
		s.refused(name, fmt.Errorf("the token verified, and no source here publishes anybody by that name"))
		return s.oidcChallenge("invalid_token"), nil
	}

	if s.wantsCode() {
		code, err := s.decide(name, tokenFactors(tok))
		if err != nil || code != ldap.LDAPResultSuccess {
			return ldap.SASLBindResult{Code: code}, err
		}
	}
	return ldap.SASLBindResult{
		Code: ldap.LDAPResultSuccess,
		// RFC 4513 5.2.1: the name field of a SASL bind is ignored, so the
		// DN the connection is now bound as comes from here and nowhere
		// else. It is spelled the way every other entry this server
		// publishes is, so that a search afterwards finds the same person.
		BoundDN: "uid=" + id.Name() + "," + s.peopleDN,
		// An empty serverSaslCreds rather than none: RFC 7628 has the server
		// say nothing on success, and "nothing" is a zero-length message,
		// not an absent field.
		ServerCreds: []byte{},
	}, nil
}

// oidcChallenge is RFC 7628 3.2.3's failure: a JSON error in serverSaslCreds,
// returned as saslBindInProgress so that the client can answer with the ^A
// that ends the exchange.
//
// ⛔ It says the status and where to go, and never why the token was
// refused. Which check caught it -- expiry, audience, signature, an unknown
// key id -- is in this server's own output. A client that sent a token it
// should not have is not owed the difference between "this is not for us"
// and "this is not signed by anyone we know".
func (s *server) oidcChallenge(status string) ldap.SASLBindResult {
	body, err := json.Marshal(struct {
		Status        string `json:"status"`
		Configuration string `json:"openid-configuration,omitempty"`
	}{Status: status, Configuration: s.oidc.discovery})
	if err != nil {
		return ldap.SASLBindResult{Code: ldap.LDAPResultInvalidCredentials}
	}
	return ldap.SASLBindResult{Code: ldap.LDAPResultSaslBindInProgress, ServerCreds: body}
}

// parseOAuthBearer reads the client's initial response (RFC 7628 3.1).
//
//	client-resp = (gs2-header kvsep *kvpair kvsep) / kvsep
//	gs2-header  = gs2-cb-flag "," [ gs2-authzid ] ","
//	kvpair      = key "=" value kvsep
//
// Typically: "n,a=alice,\x01auth=Bearer eyJ...\x01\x01".
func parseOAuthBearer(creds []byte) (authzid, token string, err error) {
	if len(creds) == 0 {
		return "", "", fmt.Errorf("an %s bind with no credentials at all", oauthBearer)
	}
	parts := strings.Split(string(creds), kvsep)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("the credentials carry no %q separator, so they are not %s", "\\x01", oauthBearer)
	}
	authzid, err = gs2Authzid(parts[0])
	if err != nil {
		return "", "", err
	}
	for _, p := range parts[1:] {
		// The trailing kvsep leaves an empty final field, and RFC 7628 says
		// unknown keys MUST be ignored -- so anything that is neither is
		// skipped rather than refused, which is what lets a provider add a
		// key without breaking this.
		key, value, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		if !strings.EqualFold(key, "auth") {
			continue
		}
		scheme, tok, ok := strings.Cut(value, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return "", "", fmt.Errorf("the auth key says %q; %s carries a Bearer token", value, oauthBearer)
		}
		if tok == "" {
			return "", "", fmt.Errorf("the auth key carries an empty token")
		}
		return authzid, tok, nil
	}
	return "", "", fmt.Errorf("the credentials carry no auth key, so there is no token in them")
}

// gs2Authzid reads the GS2 header (RFC 5801 4) and returns the authzid it
// names, which is usually nothing.
func gs2Authzid(header string) (string, error) {
	flag, rest, ok := strings.Cut(header, ",")
	if !ok {
		return "", fmt.Errorf("the GS2 header %q has no comma in it", header)
	}
	switch {
	case flag == "n", flag == "y":
	case strings.HasPrefix(flag, "p="):
		// ⛔ "p=" means the client insists on channel binding. Accepting it
		// while binding nothing is how a channel-binding downgrade goes
		// unnoticed: the client believes the channel was checked.
		return "", fmt.Errorf("this server does not do channel binding, and the client asked for %q", flag)
	default:
		return "", fmt.Errorf("the GS2 header starts with %q, which is not a channel-binding flag", flag)
	}
	id, _, ok := strings.Cut(rest, ",")
	if !ok {
		return "", fmt.Errorf("the GS2 header %q ends early", header)
	}
	if id == "" {
		return "", nil
	}
	name, ok := strings.CutPrefix(id, "a=")
	if !ok {
		return "", fmt.Errorf("the GS2 header carries %q, which is not an authzid", id)
	}
	// RFC 5801 4: "=2C" is a comma and "=3D" an equals sign, because both
	// are separators here. A name that arrives with either left unescaped is
	// a different name from the one that was sent.
	return strings.NewReplacer("=2C", ",", "=3D", "=").Replace(name), nil
}

// tokenFactors is what the issuer says it checked, as factors the `mfa` block
// can count.
//
// ⛔ A token is not automatically one factor or two. RFC 8176 has the issuer
// say what it did, in "amr", and that is the only evidence there is: a policy
// that asks for two DISTINCT kinds is answered by a token whose amr says
// ["pwd","otp"] and refused by one that says nothing. Deciding otherwise here
// would mean this server inventing a second factor nobody performed.
//
// The trust involved is the same trust the rest of the bind already rests on.
// A server that believes the issuer about WHO this is has no separate ground
// for disbelieving it about HOW it checked.
func tokenFactors(tok *oidc.Token) []mfa.Factor {
	var methods []string
	if err := tok.Claim("amr", &methods); err != nil || len(methods) == 0 {
		// No amr: the token itself is the one thing that answered. It is
		// something the person HAS -- a bearer credential is held, not
		// known -- and it is one factor, which a two-factor policy will
		// refuse, correctly.
		return []mfa.Factor{issuerFactor{name: "your identity provider", kind: mfa.Possession}}
	}
	seen := map[mfa.Kind]bool{}
	var out []mfa.Factor
	for _, m := range methods {
		k := amrKind(m)
		if seen[k] {
			// Two methods of one kind are one factor, which is the whole
			// point of counting by kind rather than by name.
			continue
		}
		seen[k] = true
		out = append(out, issuerFactor{name: "your identity provider (" + m + ")", kind: k})
	}
	return out
}

// amrKind classifies an RFC 8176 authentication method.
//
// A method this table does not know is Unknown, which never satisfies a
// policy that asks for distinct kinds -- an unclassified factor cannot be
// shown to differ from another one.
func amrKind(method string) mfa.Kind {
	switch strings.ToLower(method) {
	case "pwd", "pin", "kba", "mca":
		return mfa.Knowledge
	case "otp", "hwk", "swk", "sms", "tel", "sc", "pop", "user", "wia", "mfa":
		return mfa.Possession
	case "fpt", "face", "iris", "retina", "vbm", "geo":
		return mfa.Inherence
	}
	return mfa.Unknown
}

// issuerFactor is something the issuer says it checked. It cannot be asked
// again -- the check happened somewhere else, before the token existed -- so
// Verify says yes. What it carries is the KIND, which is what a policy counts.
type issuerFactor struct {
	name string
	kind mfa.Kind
}

func (f issuerFactor) Name() string                 { return f.name }
func (f issuerFactor) Kind() mfa.Kind               { return f.kind }
func (f issuerFactor) Verify(context.Context) error { return nil }

// oauthBearerCredentials builds a client's initial response. It is here
// rather than in a test so that the shape this server parses and the shape it
// documents are the same bytes.
func oauthBearerCredentials(authzid, token string) []byte {
	var b bytes.Buffer
	b.WriteString("n,")
	if authzid != "" {
		b.WriteString("a=" + strings.NewReplacer(",", "=2C", "=", "=3D").Replace(authzid))
	}
	b.WriteString(",")
	b.WriteString(kvsep)
	b.WriteString("auth=Bearer " + token)
	b.WriteString(kvsep)
	b.WriteString(kvsep)
	return b.Bytes()
}
