// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"log/slog"

	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/go-authn/kdc"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
	"github.com/go-authn/mfa"
	"github.com/go-authn/totp"

	ldap "github.com/go-authn/ldap"
)

// A server answers LDAP from the sources a configuration named.
type server struct {
	// cfg is the configuration this server started with, and it does not
	// change while the server runs: a password change re-reads the files
	// for the user blocks and for nothing else.
	cfg *config
	out io.Writer

	dir *directory.Set
	// local is the first source in dir: the user blocks, swapped whole when
	// a password change is written, so that everything reading through dir
	// -- the KDC included -- sees the password the change wrote.
	local *liveSource
	// people is everybody, by name, read once at startup and swapped whole
	// after a password change. A change in a source somebody else owns is
	// picked up by a restart -- see the note on reading in
	// github.com/go-authn/directory, which is where that decision lives.
	//
	// ⛔ Swapped, never edited. Every connection reads it without a lock,
	// and a map written while another goroutine ranges over it ends the
	// process. Read it through who(), once per operation.
	people  atomic.Pointer[roster]
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
			if err := secretLongEnough(secret); err != nil {
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

	local, err := localSource(cfg)
	if err != nil {
		return nil, err
	}
	s.local = &liveSource{}
	s.local.p.Store(local)
	s.dir = directory.NewSet(s.local)
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
	people, err := newRoster(ids, local.People...)
	if err != nil {
		s.dir.Close()
		return nil, err
	}
	s.people.Store(people)
	for _, g := range cfg.Groups {
		for _, m := range g.Members {
			if _, ok := people.byName[m]; !ok {
				s.dir.Close()
				return nil, fmt.Errorf("group %q has %q in it, who is not in %s", g.Name, m, s.dir.Describe())
			}
		}
	}
	return s, nil
}

// localSource is the user and group blocks: a small site's whole list, or the
// service accounts a big one keeps out of its directory.
func localSource(cfg *config) (*directory.Static, error) {
	static := &directory.Static{Name: "the configuration file", Groups: map[string][]string{}}
	for _, g := range cfg.Groups {
		static.Groups[g.Name] = g.Members
	}
	for _, u := range cfg.Users {
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
// The listener is not enough, and the reason changed when the library did.
// go-authn/ldap's Close stops the listeners AND closes every established
// connection: a server that stopped accepting and left the established ones
// answering looks stopped and is not, which is the shape of a restart that
// does not take. So a server that is SERVING is stopped through the library,
// and one that never listened is stopped by closing what it opened.
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
	// ⛔ And the listener WE opened, whatever the library did with it.
	//
	// go-authn/ldap tracks a listener inside Serve, and refuses to track one
	// once Close has been called:
	//
	//	func (s *Server) track(ln) bool { if s.closing { return false } ... }
	//	func (s *Server) Serve(ln) error { if !s.track(ln) { return net.ErrClosed } ... }
	//
	// Our serve() sets `serving` BEFORE ldap.Serve reaches track. A Close that
	// lands in that window reads serving=true, takes the branch above, and
	// closes the listeners the library knows about -- which is none of them
	// yet. Serve then returns ErrClosed without closing the listener either,
	// and the port stays held by a server that reported a clean stop.
	//
	// The window is nanoseconds on a native runner and open on an emulated
	// one: TestShutdownWaitsForTheServerToActuallyStop failed this way on
	// riscv64 and on s390x, on three different branches including main.
	//
	// Closing it twice is harmless; closing it never is the defect.
	if s.ln != nil {
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
		// ⛔ Modify and the RFC 3062 extended operation only. add, delete
		// and modifyDN exist in the library and are deliberately not wired:
		// this server edits a password in a file it owns, and nothing else
		// in a site's configuration.
		Modify:   s,
		Extended: s,
		Log:      slog.New(slog.NewTextHandler(s.out, &slog.HandlerOptions{Level: slog.LevelInfo})),
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
		s.scheme(), ln.Addr(), len(s.who()), plural(len(s.who()), "person", "people"), s.dir.Describe())

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
			// ⛔ The reader's NAME, the key it was found by, not the bytes
			// the client sent: the codes it used and the guesses it made are
			// counted against it, and a DN in another case is the same
			// reader, not a fresh one with a clean slate.
			reader := strings.ToLower(bindDN)
			return s.bindWithCode(reader, password, s.readerFactors(reader, want))
		}
		// Constant time: the comparison is against a secret, and the
		// difference between "wrong at byte 1" and "wrong at byte 12" is
		// measurable over a network. So is the length, which is why this is
		// constantTimeEqual and not ConstantTimeCompare on the raw bytes.
		if constantTimeEqual(password, want) {
			return ldap.Result{Code: ldap.Success}, nil
		}
		return ldap.Result{Code: ldap.InvalidCredentials}, nil
	}
	name, ok := s.nameOf(bindDN)
	if !ok {
		return ldap.Result{Code: ldap.InvalidCredentials}, nil
	}
	id, ok := s.who()[name]
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
		pw := &knowledge{name: "the reader password", verify: func(given string) error {
			if !constantTimeEqual(given, want) {
				return fmt.Errorf("wrong")
			}
			return nil
		}, given: password}
		return []mfa.Factor{pw, s.codeBehind(pw, dn, secret, code)}, nil
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

// Modify answers RFC 4511 4.6, for exactly one thing: a person changing their
// own password.
//
// ⛔ THE POLICY IS THE NARROWEST ONE THAT IS STILL USEFUL, and it is a policy
// rather than a limitation of the protocol half: go-authn/ldap carries add,
// delete and modifyDN too, and none of them is wired here. Widening this is a
// decision about who may edit a site's configuration file, which is not a
// decision a bind should be able to make.
func (s *server) Modify(ctx context.Context, sess ldap.Session, req *ldap.ModifyRequest) (ldap.WriteResult, error) {
	who := sess.BoundDN()
	if who == "" {
		// RFC 4511 4.6 on an anonymous connection. Saying "insufficient
		// access" would be the wrong half of the truth: nothing was proved.
		return ldap.WriteResult{Result: ldap.Refuse(ldap.InsufficientAccessRights,
			"an anonymous connection has not said who it is")}, nil
	}
	target, refusal, ok := s.ownPassword(who, req.DN)
	if !ok {
		return ldap.WriteResult{Result: refusal}, nil
	}

	change, err := onlyAPasswordChange(req.Changes)
	if err != nil {
		return ldap.WriteResult{Result: ldap.Refuse(ldap.UnwillingToPerform, "%s", err)}, nil
	}
	id, refusal, ok := s.provesPassword(target, change.old, change.haveOld)
	if !ok {
		return ldap.WriteResult{Result: refusal}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if res, ok := s.writeProved(target, id, change.old, change.new); !ok {
		return ldap.WriteResult{Result: res}, nil
	}
	return ldap.WriteResult{Result: ldap.Result{Code: ldap.Success}}, nil
}

// passwordChange is what a modify asked for: the new password, and the old
// one when the request carried it.
type passwordChange struct {
	old, new string
	haveOld  bool
}

// onlyAPasswordChange is the password change in a modify that asks for that
// and nothing else.
//
// Two shapes are understood:
//
//   - replace userPassword with one value, which proves nothing and is
//     refused later for anybody who has a password (see provesPassword);
//   - delete userPassword's ONE current value, then add the new one, which is
//     RFC 4511 4.6's way of proving the old value: the changes are applied in
//     order and atomically, so the delete -- and the whole request with it --
//     fails unless the value deleted is the one held. It is also what
//     OpenLDAP's ppolicy requires under pwdSafeModify.
//
// A delete with no value deletes every value, names none, and proves nothing.
// An add before the delete is a different request: it holds two passwords for
// a moment and proves nothing either.
//
// ⛔ RFC 4511 4.6 makes a modify ATOMIC: "the entire list of modifications is
// performed, or none of it". A request that replaces userPassword AND adds a
// group cannot be half-honoured, so one this cannot do entirely it refuses
// entirely -- rather than doing the password and dropping the rest, which
// would report success for something nobody asked for.
func onlyAPasswordChange(changes []ldap.Change) (passwordChange, error) {
	for _, c := range changes {
		if !strings.EqualFold(c.Attribute.Name, "userPassword") {
			return passwordChange{}, fmt.Errorf("this server changes userPassword and nothing else, not %s",
				c.Attribute.Name)
		}
	}
	one := func(c ldap.Change, what string) (string, error) {
		if len(c.Attribute.Values) != 1 {
			return "", fmt.Errorf("%s is one value, and %d were given", what, len(c.Attribute.Values))
		}
		return string(c.Attribute.Values[0]), nil
	}
	switch {
	case len(changes) == 1 && changes[0].Operation == ldap.ReplaceValues:
		pw, err := one(changes[0], "a password")
		return passwordChange{new: pw}, err
	case len(changes) == 2 && changes[0].Operation == ldap.DeleteValues &&
		changes[1].Operation == ldap.AddValues:
		old, err := one(changes[0], "the old password deleted")
		if err != nil {
			return passwordChange{}, err
		}
		pw, err := one(changes[1], "the new password added")
		return passwordChange{old: old, new: pw, haveOld: true}, err
	}
	return passwordChange{}, fmt.Errorf("this server changes a password and nothing else: " +
		"delete the old value and add the new one, in that order and in one modify")
}

// provesPassword is the identity at target, if the request proved the password
// it holds now.
//
// ⛔ The bind does not count. A session may have been bound by something that
// is not the password -- an OAUTHBEARER token, short-lived and possibly
// single-factor -- and a change of password is what turns whatever bound the
// session into a credential that outlives it and also works for kinit. So the
// old password is asked for whatever the bind was, as OpenLDAP's ppolicy does
// with pwdSafeModify set (slapo-ppolicy(5)), and as RFC 3062 section 3 allows:
// "If oldPasswd is not present, the server MAY use other policy to determine
// whether or not to change the password."
//
// The result codes are ppolicy.c's: insufficientAccessRights when the old
// password is missing, unwillingToPerform when it is wrong. The manual page
// does not list them; the source does, in ppolicy_modify
// (servers/slapd/overlays/ppolicy.c, OpenLDAP commit 2b8cbe0a).
//
// Somebody with no password at all has nothing to prove, and is refused a
// first one: such a person can only have bound with a token -- a simple bind
// is a password check, and theirs has nothing to check against -- and a
// bearer token is not a password. A first password is an administrator's to
// set, in the configuration.
//
// go-authn/ldap's Session does not say how it was bound, and this does not
// need it to: the rule is the same for every bind.
func (s *server) provesPassword(target, old string, haveOld bool) (*directory.Identity, ldap.Result, bool) {
	id := s.who()[target]
	if id == nil {
		return nil, ldap.Refuse(ldap.InsufficientAccessRights,
			"a password may be changed only by the person it belongs to"), false
	}
	if !id.Can(directory.Verifier) {
		return nil, ldap.Refuse(ldap.UnwillingToPerform,
			"%s has no password, and this session was bound with a token: "+
				"a bearer token is not a password, and does not set the first one", target), false
	}
	if !haveOld {
		return nil, ldap.Refuse(ldap.InsufficientAccessRights,
			"a password change must send the old password with the new one"), false
	}
	if err := id.Verify(old); err != nil {
		fmt.Fprintf(s.out, "%s's password change was refused: the old password did not verify: %v\n", target, err)
		return nil, ldap.Refuse(ldap.UnwillingToPerform,
			"the old password sent is not the current one"), false
	}
	return id, ldap.Result{}, true
}

// writeProved writes a change provesPassword accepted. Callers hold s.mu.
//
// ⛔ The proof was checked without the lock -- a check may be a bind against
// another directory, and no other password change should wait on that -- so
// it is checked again here if the identity changed in between. Two changes
// sent with the same old password must not both succeed: the second one's
// proof is the password the first one replaced.
func (s *server) writeProved(target string, proved *directory.Identity, old, password string) (ldap.Result, bool) {
	if now := s.who()[target]; now != proved {
		if now == nil || now.Verify(old) != nil {
			return ldap.Refuse(ldap.UnwillingToPerform,
				"the old password sent is not the current one"), false
		}
	}
	return s.writePassword(target, password)
}

// reloadLocal re-reads the configuration files and refreshes the people this
// server holds ITSELF.
//
// ⛔ The comment on `people` says sources are read once at startup and a change
// is picked up by a restart. That is right for a source somebody else owns --
// polling a directory is a decision with a cost. It is WRONG for a change this
// process just made: answering Success to a password change and then going on
// accepting the old password until a restart is reporting something that did
// not happen.
//
// So only the local people are rebuilt, from the files on disk rather than
// from what was written, which is the difference between believing the write
// and checking it. Sources reached over a network are not touched and not
// reopened.
//
// ⛔ Nothing is edited in place. The new people are built beside the old ones
// and swapped in whole: connections read them without a lock, and the KDC
// reads the local source through s.dir, so both see the change at once and
// neither ever sees half of one. The configuration this server started with
// stays the configuration it runs with -- the files are re-read for the user
// blocks and nothing else, so an unrelated edit waiting on disk does not take
// effect halfway because somebody changed a password. Callers hold s.mu, which
// is what keeps two rebuilds from racing each other.
func (s *server) reloadLocal() error {
	cfg, err := loadConfig(s.cfg.files)
	if err != nil {
		return err
	}
	local, err := localSource(cfg)
	if err != nil {
		return err
	}
	fresh, err := local.Identities()
	if err != nil {
		return err
	}
	// The local source is asked first, so it owns every name it has; the
	// others keep what they had at startup.
	owned := map[string]bool{}
	for _, id := range fresh {
		owned[id.Name()] = true
	}
	ids := slices.Clone(fresh)
	before := s.people.Load()
	for name, id := range before.byName {
		// Somebody the file held before and holds no longer is gone, as
		// they are from the source set the KDC reads.
		if !owned[name] && !before.local[name] {
			ids = append(ids, id)
		}
	}
	people, err := newRoster(ids, fresh...)
	if err != nil {
		return err
	}
	s.local.p.Store(local)
	s.people.Store(people)
	return nil
}

// ownPassword is the person whose password a session may change at dn: the
// one it bound as, and nobody else.
//
// ⛔ The comparison is of IDENTITIES, not of DNs. ldap.EqualDN folds case, as
// a DN comparison must (RFC 4514, and uid is caseIgnoreMatch in RFC 4519), so
// a session bound as uid=Backup passed it for uid=backup -- two people to the
// map they are kept in, one person to the DN comparison. The session's own
// name is resolved exactly as Bind resolved it, must still be somebody this
// server serves, and must be the target byte for byte. The DN comparison
// stays as well, for the structure: "uid=alice, ou=people,dc=example" and
// "uid=alice,ou=people,dc=example" are the same DN and differ as strings.
func (s *server) ownPassword(bound, dn string) (string, ldap.Result, bool) {
	target, ok := s.nameOf(dn)
	if !ok {
		return "", ldap.Refuse(ldap.NoSuchObject, "%s is not a person this server publishes", dn), false
	}
	self, ok := s.nameOf(bound)
	if !ok || s.who()[self] == nil || self != target || !ldap.EqualDN(bound, s.dnOf(target)) {
		return "", ldap.Refuse(ldap.InsufficientAccessRights,
			"a password may be changed only by the person it belongs to"), false
	}
	return target, ldap.Result{}, true
}

// ExtendedNames is the extended operations this server answers, which the
// library publishes as supportedExtension in the root DSE.
func (s *server) ExtendedNames() []string { return []string{ldap.OIDPasswordModify} }

// Extended answers RFC 3062, the password modify operation.
//
// ⛔ This exists because the Modify above, correct as it is, is not what the
// tool reaches for: `ldappasswd` sends this extended operation and answers
// "this server answers no extended operation 1.3.6.1.4.1.4203.1.11.1" without
// it. A write path nobody's client speaks is a write path nobody has.
func (s *server) Extended(ctx context.Context, sess ldap.Session, req *ldap.ExtendedRequest) (ldap.ExtendedResult, error) {
	if req.Name != ldap.OIDPasswordModify {
		return ldap.ExtendedResult{Result: ldap.Refuse(ldap.ProtocolError,
			"this server answers no extended operation %s", req.Name)}, nil
	}
	pm, err := decodePasswdModify(req.Value)
	if err != nil {
		return ldap.ExtendedResult{Result: ldap.Refuse(ldap.ProtocolError, "%s", err)}, nil
	}

	who := sess.BoundDN()
	if who == "" {
		return ldap.ExtendedResult{Result: ldap.Refuse(ldap.InsufficientAccessRights,
			"an anonymous connection has not said who it is")}, nil
	}
	// RFC 3062: an absent userIdentity means "the connection's own identity".
	dn := who
	if pm.haveIdentity {
		dn = pm.identity
	}
	target, refusal, ok := s.ownPassword(who, dn)
	if !ok {
		return ldap.ExtendedResult{Result: refusal}, nil
	}
	if pm.new == "" {
		// ⛔ RFC 3062 lets a server GENERATE one and return it. This does not:
		// a password this server invented would have to be sent back over the
		// connection and then written down by whoever received it, and the
		// one place it is certain to end up is a terminal's scrollback.
		return ldap.ExtendedResult{Result: ldap.Refuse(ldap.UnwillingToPerform,
			"this server does not generate passwords: send the one you want")}, nil
	}
	id, refusal, ok := s.provesPassword(target, pm.old, pm.haveOld)
	if !ok {
		return ldap.ExtendedResult{Result: refusal}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if res, ok := s.writeProved(target, id, pm.old, pm.new); !ok {
		return ldap.ExtendedResult{Result: res}, nil
	}
	return ldap.ExtendedResult{Result: ldap.Result{Code: ldap.Success}}, nil
}

// writePassword is the half Modify and Extended share: write it, reload, and
// turn a failure into the refusal a client should see.
//
// ⛔ Shared deliberately. The same rule stated at two call sites drifts, and
// the two here would drift in the direction that matters -- one of them
// eventually forgetting the reload, and answering Success while the running
// server kept the old password.
func (s *server) writePassword(target, password string) (ldap.Result, bool) {
	if err := hcldir.SetPassword(s.cfg.files, target, password); err != nil {
		if errors.Is(err, hcldir.ErrNotDeclared) {
			return ldap.Refuse(ldap.UnwillingToPerform,
				"%s is served from %s, which this server reads and does not write",
				target, s.dir.Describe()), false
		}
		fmt.Fprintf(s.out, "changing the password for %s: %v\n", target, err)
		return ldap.Refuse(ldap.Other, "the password could not be written"), false
	}
	if err := s.reloadLocal(); err != nil {
		fmt.Fprintf(s.out, "the password for %s was written but this server did not reload it: %v\n", target, err)
		return ldap.Refuse(ldap.Other,
			"the password was written but this server did not reload it"), false
	}
	fmt.Fprintf(s.out, "%s changed their own password\n", target)
	return ldap.Result{Code: ldap.Success}, true
}
