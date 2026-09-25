// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"log/slog"

	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/go-authn/kdc"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
	"github.com/go-authn/mfa"
	"github.com/go-authn/totp"

	ldap "github.com/go-authn/ldap"
)

// A server answers LDAP from the sources a configuration named.
type server struct {
	cfg *config
	out io.Writer

	dir *directory.Set
	// who is everybody, by name, read once at startup. A change in a source
	// is picked up by a restart -- see the note on reading in
	// github.com/go-authn/directory, which is where that decision lives.
	who     map[string]*directory.Identity
	readers map[string]string // bind DN, lower-cased, to password
	// readerSecrets is the one-time-code secret for a reader that carries
	// one. A service account usually has no phone, so this is usually empty
	// and the mfa block says whether readers are asked at all.
	readerSecrets map[string][]byte

	peopleDN, groupsDN string

	// policy is what a bind must satisfy, and codes remembers which one-time
	// codes have been used -- a code is valid for a whole step, so a server
	// that accepts one twice accepts a replay.
	policy mfa.Policy
	codes  *totp.Verifier

	ldap *ldap.Server
	ln   net.Listener

	// oidc is the token half, present only when the configuration asks for
	// one. Without it this server does not implement ldap.SASLBinder's
	// mechanism at all and every SASL bind is answered
	// authMethodNotSupported -- see BindSASL.
	oidc *oidcAuth

	// realm is the KDC half, present only when the configuration asks for
	// one. A directory that issues tickets is still a directory.
	realm *realm

	mu      sync.Mutex
	binds   int
	serving bool
	closed  bool
}

// open reads every source and builds the answers, before anything listens.
func open(cfg *config, out io.Writer) (*server, error) {
	s := &server{
		cfg: cfg, out: out,
		who:           map[string]*directory.Identity{},
		readers:       map[string]string{},
		readerSecrets: map[string][]byte{},
		peopleDN:      "ou=people," + cfg.BaseDN,
		groupsDN:      "ou=groups," + cfg.BaseDN,
	}
	if m := cfg.MFA; m != nil {
		s.policy = mfa.Policy{Count: m.Factors, DistinctKinds: m.DistinctKinds}
		if s.policy.Count == 0 {
			s.policy.Count = 2
		}
		s.codes = &totp.Verifier{Options: totp.Options{
			Digits: m.Digits,
			Period: time.Duration(m.Period) * time.Second,
			Window: m.Window,
		}}
	}
	for _, r := range cfg.Readers {
		pw, err := secret(r.Password, r.PasswordFile, "reader "+r.DN)
		if err != nil {
			return nil, err
		}
		s.readers[strings.ToLower(r.DN)] = pw
		if r.TOTPSecret != "" {
			secret, err := directory.ParseTOTPSecret(r.TOTPSecret)
			if err != nil {
				return nil, fmt.Errorf("reader %q: %w", r.DN, err)
			}
			s.readerSecrets[strings.ToLower(r.DN)] = secret
		}
	}

	// Discovery happens here, before anything listens: a provider that
	// cannot be reached should stop a server from starting, where somebody
	// is watching, rather than refuse every bind later.
	auth, err := openOIDC(cfg.OIDC)
	if err != nil {
		return nil, err
	}
	s.oidc = auth

	local, err := s.localSource()
	if err != nil {
		return nil, err
	}
	s.dir = directory.NewSet(local)
	srcs, err := hcldir.OpenAll(cfg.Directories)
	if err != nil {
		s.dir.Close()
		return nil, err
	}
	for _, src := range srcs {
		s.dir.Add(src)
	}
	ids, err := s.dir.Identities()
	if err != nil {
		s.dir.Close()
		return nil, err
	}
	for _, id := range ids {
		s.who[id.Name()] = id
	}
	for _, g := range cfg.Groups {
		for _, m := range g.Members {
			if _, ok := s.who[m]; !ok {
				s.dir.Close()
				return nil, fmt.Errorf("group %q has %q in it, who is not in %s", g.Name, m, s.dir.Describe())
			}
		}
	}
	return s, nil
}

// localSource is the user and group blocks: a small site's whole list, or the
// service accounts a big one keeps out of its directory.
func (s *server) localSource() (directory.Source, error) {
	static := &directory.Static{Name: "the configuration file", Groups: map[string][]string{}}
	for _, g := range s.cfg.Groups {
		static.Groups[g.Name] = g.Members
	}
	for _, u := range s.cfg.Users {
		opts := []directory.Option{directory.From("the configuration file")}
		pw, err := secret(u.Password, u.PasswordFile, "user "+u.Name)
		if err != nil {
			return nil, err
		}
		if pw != "" {
			opts = append(opts, directory.WithPassword(pw))
		}
		if u.NTHash != "" {
			hash, err := directory.ParseNTHash(u.NTHash)
			if err != nil {
				return nil, fmt.Errorf("user %q: %w", u.Name, err)
			}
			opts = append(opts, directory.WithNTHash(hash))
		}
		if u.TOTPSecret != "" {
			secret, err := directory.ParseTOTPSecret(u.TOTPSecret)
			if err != nil {
				return nil, fmt.Errorf("user %q: %w", u.Name, err)
			}
			opts = append(opts, directory.WithTOTPSecret(secret))
		}
		keys, err := authorizedKeys(u)
		if err != nil {
			return nil, err
		}
		if len(keys) > 0 {
			opts = append(opts, directory.WithPublicKeys(keys...))
		}
		static.People = append(static.People, directory.NewIdentity(u.Name, opts...))
	}
	return static, nil
}

// Close stops the server and gives back whatever the sources hold.
//
// The listener is not enough: glauth's Serve blocks on its own Quit channel
// and closing the socket only ends the accept goroutine, leaving Serve --
// and whoever waits for it -- exactly where it was. So a server that is
// SERVING is stopped through the library, and one that never listened is
// stopped by closing what it opened.
func (s *server) Close() error {
	s.mu.Lock()
	serving, closed := s.serving, s.closed
	s.closed = true
	s.mu.Unlock()
	if closed {
		return nil
	}
	switch {
	case serving:
		s.ldap.Close() // sends on Quit, and waits for Serve to acknowledge
	case s.ln != nil:
		s.ln.Close()
	}
	s.realm.close()
	if s.dir != nil {
		return s.dir.Close()
	}
	return nil
}

// listen starts answering, and says where.
func (s *server) listen() error {
	// go-authn/ldap owns the protocol: the framing, the filter, the scope,
	// the attribute selection and the root DSE. What is left here is the
	// only part that is ours -- who may bind, who may read, and what this
	// directory publishes about each person.
	srv := &ldap.Server{
		Bind:   s,
		Search: s,
		Log:    slog.New(slog.NewTextHandler(s.out, &slog.HandlerOptions{Level: slog.LevelInfo})),
		// What the root DSE tells a client before it has bound: where to
		// search, and who this is.
		NamingContexts: []string{s.cfg.BaseDN},
		Vendor:         "go-authn/authnd",
		VendorVersion:  version(),
	}
	if s.oidc != nil {
		srv.SASL = s
	}
	s.ldap = srv

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	if s.cfg.tls() {
		cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
		if err != nil {
			ln.Close()
			return fmt.Errorf("the certificate: %w", err)
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		srv.TLSConfig = cfg
		// ⛔ StartTLS is asked for by the CLIENT, so offering it promises
		// nothing. RequireTLS makes the library refuse every operation until
		// the connection has been upgraded -- which is what turns cert_file
		// from an offer into the guarantee publish_nt_hash relies on. The
		// root DSE is the one exception, and has to be: it is where StartTLS
		// is advertised.
		srv.RequireTLS = s.cfg.StartTLS
		// One or the other. Wrapping the listener AND setting TLSConfig
		// reads like belt and braces and is not: the wrapped listener
		// handshakes before a byte of LDAP is spoken, so the StartTLS the
		// TLSConfig enables is never reached by anybody.
		if !s.cfg.StartTLS {
			ln = tls.NewListener(ln, cfg)
		}
	}
	s.ln = ln
	fmt.Fprintf(s.out, "%s on %s, serving %d %s from %s\n",
		s.scheme(), ln.Addr(), len(s.who), plural(len(s.who), "person", "people"), s.dir.Describe())

	r, err := s.openRealm()
	if err != nil {
		s.ln.Close()
		return err
	}
	if r != nil {
		if err := r.listen(); err != nil {
			s.ln.Close()
			return err
		}
		s.realm = r
		fmt.Fprintf(s.out, "realm %s on %s (udp and tcp)\n", r.cfg.Realm, r.cfg.Listen)
	}
	return nil
}

// serve answers until Close is called.
//
// The directory and the realm are equals: whichever stops first ends this,
// because a server that kept answering LDAP after its KDC died would look
// healthy to everything that does not speak Kerberos.
func (s *server) serve() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.serving = true
	r := s.realm
	s.mu.Unlock()

	ldapDone := make(chan error, 1)
	go func() { ldapDone <- s.ldap.Serve(s.ln) }()
	// A nil channel blocks forever in a select, which is exactly right when
	// there is no realm to wait on.
	var realmDone <-chan error
	if r != nil {
		realmDone = r.serve()
	}

	var err error
	select {
	case err = <-ldapDone:
	case err = <-realmDone:
		if errors.Is(err, kdc.ErrClosed) {
			err = nil
		}
	}
	s.mu.Lock()
	s.serving = false
	s.mu.Unlock()
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}
func (s *server) scheme() string {
	switch {
	case s.cfg.tls() && s.cfg.StartTLS:
		return "ldap+starttls"
	case s.cfg.tls():
		return "ldaps"
	}
	return "ldap"
}

// Addr is where this server actually listens, which is not the address asked
// for when the port was 0.
func (s *server) Addr() string {
	if s.ln == nil {
		return s.cfg.Listen
	}
	return s.ln.Addr().String()
}

// Binds is how many binds have been attempted, successful or not.
func (s *server) Binds() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binds
}

// Bind proves somebody, or does not.
func (s *server) Bind(_ context.Context, _ ldap.Session, req *ldap.BindRequest) (ldap.Result, error) {
	s.mu.Lock()
	s.binds++
	s.mu.Unlock()

	bindDN, password := req.Name, string(req.Simple)

	// ⛔ RFC 4513 has TWO empty-password binds and they are one field apart.
	//
	//   5.1.1 ANONYMOUS, an empty name AND an empty password, means "I am
	//         nobody". It is legitimate, and it is what a client sends
	//         before it has discovered anything -- including the root DSE
	//         that tells it how to authenticate at all.
	//
	//   5.1.2 UNAUTHENTICATED, a NAME with an empty password, means the same
	//         thing while NAMING somebody. A server that passes it through
	//         as proof lets anybody in as anybody, and the client cannot
	//         tell it from a real success.
	//
	// This used to refuse both, which locked out every anonymous client.
	// Nothing noticed because nothing here was anonymous-readable until the
	// root DSE existed.
	if password == "" {
		if bindDN == "" {
			return ldap.Result{Code: ldap.Success}, nil
		}
		// ⛔ unwillingToPerform, not invalidCredentials. RFC 4513 5.1.2:
		// "Servers SHOULD by default fail Unauthenticated Bind requests with
		// a resultCode of unwillingToPerform."
		//
		// The difference is what the client does next. invalidCredentials
		// means "that password was wrong", so a client retries and a person
		// starts doubting their password. unwillingToPerform means "this
		// server does not do that at all", which is the true statement and
		// the one that stops the retry.
		return ldap.Refuse(ldap.UnwillingToPerform,
			"an unauthenticated bind proves nothing, and this server does not accept one"), nil
	}
	if want, ok := s.readers[strings.ToLower(bindDN)]; ok {
		// A reader is a service account with no phone, so it carries a code
		// only where the configuration says its readers do.
		if s.wantsCode() && s.cfg.MFA.Readers {
			return s.bindWithCode(bindDN, password, s.readerFactors(bindDN, want))
		}
		// Constant time: the comparison is against a secret, and the
		// difference between "wrong at byte 1" and "wrong at byte 12" is
		// measurable over a network.
		if subtle.ConstantTimeCompare([]byte(password), []byte(want)) == 1 {
			return ldap.Result{Code: ldap.Success}, nil
		}
		return ldap.Result{Code: ldap.InvalidCredentials}, nil
	}
	name, ok := s.nameOf(bindDN)
	if !ok {
		return ldap.Result{Code: ldap.InvalidCredentials}, nil
	}
	id, ok := s.who[name]
	if !ok {
		return ldap.Result{Code: ldap.InvalidCredentials}, nil
	}
	if s.wantsCode() {
		factors, err := s.factorsFor(id, password)
		if err != nil {
			// Said to the SERVER's own output, not to the client: somebody who
			// has not proved who they are is told that the bind failed and
			// nothing else.
			s.refused(name, err)
			return ldap.Result{Code: ldap.InvalidCredentials}, nil
		}
		return s.decide(name, factors)
	}
	// The identity answers, whichever way its source can: a comparison here,
	// or a bind against the directory that holds the password and will not
	// give it up.
	if err := verifyPassword(id, password); err != nil {
		return ldap.Result{Code: ldap.InvalidCredentials}, nil
	}
	return ldap.Result{Code: ldap.Success}, nil
}

// bindWithCode is the reader's version: the same policy, over a password this
// server holds rather than an identity a directory answers for.
func (s *server) bindWithCode(who, given string, make func(string) ([]mfa.Factor, error)) (ldap.Result, error) {
	factors, err := make(given)
	if err != nil {
		s.refused(who, err)
		return ldap.Result{Code: ldap.InvalidCredentials}, nil
	}
	return s.decide(who, factors)
}

// decide asks the policy and turns its answer into an LDAP result.
//
// The client is told one thing -- invalid credentials -- whichever factor
// refused. WHICH one is a fact about the account, and telling somebody who has
// not proved anything narrows their next guess.
func (s *server) decide(who string, factors []mfa.Factor) (ldap.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := mfa.Verify(ctx, s.policy, factors...)
	if err != nil {
		// The RESULT carries what each factor said, and a factor that could
		// not be asked keeps its reason in its own error -- mfa's summary
		// renders that as "not available", which is true and not actionable.
		// An administrator reading this wants "nobody enrolled an
		// authenticator for this person".
		s.refused(who, err)
		for _, a := range r.Answers {
			if a.Unavailable() {
				fmt.Fprintf(s.out, "  %s: %v\n", a.Name, a.Err)
			}
		}
		return ldap.Result{Code: ldap.InvalidCredentials}, nil
	}
	return ldap.Result{Code: ldap.Success}, nil
}

// refused writes why a bind failed where an administrator can read it, and
// nowhere a client can.
func (s *server) refused(who string, err error) {
	fmt.Fprintf(s.out, "%s was refused: %v\n", who, err)
}

// readerFactors is the password this server holds, plus the code, for a
// service account the configuration asked to carry one.
func (s *server) readerFactors(dn, want string) func(string) ([]mfa.Factor, error) {
	return func(given string) ([]mfa.Factor, error) {
		digits := s.mfaDigits()
		password, code, ok := splitCode(given, digits)
		if !ok {
			return nil, fmt.Errorf("what was typed is %d characters, and the last %d of it are the code",
				len(given), digits)
		}
		secret := s.readerSecrets[strings.ToLower(dn)]
		return []mfa.Factor{
			knowledge{name: "the reader password", verify: func(given string) error {
				if !constantTimeEqual(given, want) {
					return fmt.Errorf("wrong")
				}
				return nil
			}, given: password},
			totp.Factor(dn, secret, []byte(code), s.codes),
		}, nil
	}
}

// Search answers a reader, and nobody else.
func (s *server) Search(ctx context.Context, sess ldap.Session, req *ldap.SearchRequest, w ldap.EntryWriter) (ldap.Result, error) {
	if _, ok := s.readers[strings.ToLower(sess.BoundDN())]; !ok {
		// A directory that answers everybody has published its people to
		// everybody. Binding proves who you are; reading the list is a
		// separate thing to be allowed.
		return ldap.Refuse(ldap.InsufficientAccessRights, "only a reader may search"), nil
	}
	// ⛔ The scope test is the library's. This used to be a pair of
	// HasSuffix calls in both directions, which is the shape that puts
	// ou=morepeople into a search for ou=people -- and the library's version
	// is the one with the table of cases behind it.
	//
	// The filter and the attribute selection are the library's too: this
	// server publishes entries and does not decide which of them a question
	// was about.
	for _, e := range append(s.peopleEntries(), s.groupEntries()...) {
		if err := ctx.Err(); err != nil {
			return ldap.Result{}, err
		}
		if !ldap.InScope(e.DN, req.BaseObject, req.Scope) || !req.Filter.Matches(e) {
			continue
		}
		if err := w.Entry(e); err != nil {
			return ldap.Result{}, err
		}
	}
	return ldap.Result{Code: ldap.Success}, nil
}

// peopleEntries is everybody, as posixAccount entries.
func (s *server) peopleEntries() []*ldap.Entry {
	var out []*ldap.Entry
	for _, id := range s.sorted() {
		attrs := []*ldap.Attribute{
			ldap.StringAttribute("objectClass", "top", "person", "posixAccount"),
			ldap.StringAttribute("uid", id.Name()),
			ldap.StringAttribute("cn", id.Name()),
		}
		// ⛔ Published only when asked for, because it IS the credential:
		// whoever holds MD4(UTF16LE(password)) authenticates as that person
		// over NTLMv2 without ever learning the password. The configuration
		// refuses to turn this on where it would cross a network in the clear.
		if s.cfg.PublishNTHash {
			if key, err := id.NTKey(); err == nil {
				attrs = append(attrs, ldap.StringAttribute("sambaNTPassword",
					strings.ToUpper(hex.EncodeToString(key))))
			}
		}
		if keys := id.Keys(); len(keys) > 0 {
			attrs = append(attrs, ldap.StringAttribute("sshPublicKey", keys...))
		}
		out = append(out, &ldap.Entry{DN: s.dnOf(id.Name()), Attributes: attrs})
	}
	return out
}

// groupEntries is every group any source knows, as posixGroup entries.
func (s *server) groupEntries() []*ldap.Entry {
	var out []*ldap.Entry
	for _, name := range s.groupNames() {
		members, err := s.dir.Members(name)
		if err != nil {
			continue
		}
		out = append(out, &ldap.Entry{
			DN: "cn=" + name + "," + s.groupsDN,
			Attributes: []*ldap.Attribute{
				ldap.StringAttribute("objectClass", "top", "posixGroup"),
				ldap.StringAttribute("cn", name),
				ldap.StringAttribute("memberUid", members...),
			},
		})
	}
	return out
}

// dnOf is where somebody's entry is.
func (s *server) dnOf(name string) string { return "uid=" + name + "," + s.peopleDN }

// nameOf is the uid in a bind DN, if it is one of ours. A DN this server did
// not publish belongs to nobody here, whatever it parses as.
func (s *server) nameOf(dn string) (string, bool) {
	lower := strings.ToLower(dn)
	if !strings.HasSuffix(lower, ","+strings.ToLower(s.peopleDN)) {
		return "", false
	}
	first := strings.SplitN(dn, ",", 2)[0]
	name, ok := strings.CutPrefix(strings.ToLower(first), "uid=")
	if !ok {
		return "", false
	}
	// The value is returned with the case the CLIENT wrote, because a name is
	// looked up in a map that a source filled: "Alice" and "alice" are two
	// keys, and guessing which is a way to let somebody in as the other.
	return strings.SplitN(first, "=", 2)[1], name != ""
}
