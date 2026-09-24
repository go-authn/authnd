// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A real provider, small.
//
// ⛔ It signs with a real key and publishes a real key set, and the tokens
// are checked by go-authn/oidc itself -- nothing here is stubbed. A fake
// verifier that said yes would make every test below pass while proving that
// this server accepts anything: the one thing worth knowing is whether a
// token that is wrong is REFUSED, and only the real verifier can answer that.
type provider struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{key: key, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   p.srv.URL,
			"jwks_uri": p.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA",
			"kid": p.kid,
			"use": "sig",
			"alg": "RS256",
			"n":   b64(p.key.N.Bytes()),
			"e":   b64(big.NewInt(int64(p.key.E)).Bytes()),
		}}})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *provider) issuer() string { return p.srv.URL }

// token signs a token for this provider. claims override the defaults, so a
// test can say exactly the one thing it is about.
func (p *provider) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	now := time.Now()
	c := map[string]any{
		"iss": p.srv.URL,
		"aud": "ldap",
		"sub": "0000-0000",
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	for k, v := range claims {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return p.signWith(t, p.key, map[string]any{"alg": "RS256", "typ": "JWT", "kid": p.kid}, c)
}

// signWith is the signing half on its own, so that a test can sign with a key
// this provider does not publish.
func (p *provider) signWith(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// oidcConfig is the `oidc` block for this provider, for a test to paste into
// a configuration.
func (p *provider) block(extra string) string {
	return fmt.Sprintf(`
oidc {
  issuer   = %q
  audience = "ldap"
  allow_plaintext = true
%s}
`, p.issuer(), extra)
}
