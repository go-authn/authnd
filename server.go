// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"

	ldap "github.com/glauth/ldap"
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

	peopleDN, groupsDN string

	ldap *ldap.Server
	ln   net.Listener

	mu      sync.Mutex
	binds   int
	serving bool
	closed  bool
}

// open reads every source and builds the answers, before anything listens.
func open(cfg *config, out io.Writer) (*server, error) {
	s := &server{
		cfg: cfg, out: out,
		who:      map[string]*directory.Identity{},
		readers:  map[string]string{},
		peopleDN: "ou=people," + cfg.BaseDN,
		groupsDN: "ou=groups," + cfg.BaseDN,
	}
	for _, r := range cfg.Readers {
		pw, err := secret(r.Password, r.PasswordFile, "reader "+r.DN)
		if err != nil {
			return nil, err
		}
		s.readers[strings.ToLower(r.DN)] = pw
	}

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
	if s.dir != nil {
		return s.dir.Close()
	}
	return nil
}

// listen starts answering, and says where.
func (s *server) listen() error {
	srv := ldap.NewServer()
	// The library applies the filter, the scope and the attribute selection
	// (RFC 4511 4.5.1, RFC 4515). Doing it here would be a second
	// implementation of a search filter evaluator, with its own bugs, in the
	// one place where a bug means answering a question nobody asked.
	srv.EnforceLDAP = true
	srv.BindFunc("", s)
	srv.SearchFunc("", s)
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
		ln = tls.NewListener(ln, cfg)
	}
	s.ln = ln
	fmt.Fprintf(s.out, "%s on %s, serving %d %s from %s\n",
		s.scheme(), ln.Addr(), len(s.who), plural(len(s.who), "person", "people"), s.dir.Describe())
	return nil
}

// serve answers until Close is called.
func (s *server) serve() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.serving = true
	s.mu.Unlock()
	err := s.ldap.Serve(s.ln)
	s.mu.Lock()
	s.serving = false
	s.mu.Unlock()
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}

func (s *server) scheme() string {
	if s.cfg.tls() {
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
func (s *server) Bind(bindDN, password string, _ net.Conn) (ldap.LDAPResultCode, error) {
	s.mu.Lock()
	s.binds++
	s.mu.Unlock()

	// ⛔ The unauthenticated bind. RFC 4513 5.1.2: a bind with a name and an
	// EMPTY password is answered success by a real directory, and it means "I
	// am anonymous" -- not "I proved this name". A server that passes it
	// through as proof lets anybody in as anybody, and the client that asked
	// cannot tell the difference from a real success.
	if password == "" {
		return ldap.LDAPResultInvalidCredentials, nil
	}
	if want, ok := s.readers[strings.ToLower(bindDN)]; ok {
		// Constant time: the comparison is against a secret, and the
		// difference between "wrong at byte 1" and "wrong at byte 12" is
		// measurable over a network.
		if subtle.ConstantTimeCompare([]byte(password), []byte(want)) == 1 {
			return ldap.LDAPResultSuccess, nil
		}
		return ldap.LDAPResultInvalidCredentials, nil
	}
	name, ok := s.nameOf(bindDN)
	if !ok {
		return ldap.LDAPResultInvalidCredentials, nil
	}
	id, ok := s.who[name]
	if !ok {
		return ldap.LDAPResultInvalidCredentials, nil
	}
	// The identity answers, whichever way its source can: a comparison here,
	// or a bind against the directory that holds the password and will not
	// give it up.
	if err := id.Verify(password); err != nil {
		return ldap.LDAPResultInvalidCredentials, nil
	}
	return ldap.LDAPResultSuccess, nil
}

// Search answers a reader, and nobody else.
func (s *server) Search(boundDN string, req ldap.SearchRequest, _ net.Conn) (ldap.ServerSearchResult, error) {
	if _, ok := s.readers[strings.ToLower(boundDN)]; !ok {
		// A directory that answers everybody has published its people to
		// everybody. Binding proves who you are; reading the list is a
		// separate thing to be allowed.
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights},
			fmt.Errorf("only a reader may search")
	}
	base := strings.ToLower(req.BaseDN)
	var entries []*ldap.Entry
	// Both trees are offered unless the base names one of them: the library
	// applies the scope afterwards, and a base of dc=example,dc=org is a
	// legitimate way to ask for everything.
	if base == "" || strings.HasSuffix(strings.ToLower(s.peopleDN), base) || strings.HasSuffix(base, strings.ToLower(s.peopleDN)) {
		entries = append(entries, s.peopleEntries()...)
	}
	if base == "" || strings.HasSuffix(strings.ToLower(s.groupsDN), base) || strings.HasSuffix(base, strings.ToLower(s.groupsDN)) {
		entries = append(entries, s.groupEntries()...)
	}
	return ldap.ServerSearchResult{Entries: entries, ResultCode: ldap.LDAPResultSuccess}, nil
}

// peopleEntries is everybody, as posixAccount entries.
func (s *server) peopleEntries() []*ldap.Entry {
	var out []*ldap.Entry
	for _, id := range s.sorted() {
		attrs := []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "person", "posixAccount"}},
			{Name: "uid", Values: []string{id.Name()}},
			{Name: "cn", Values: []string{id.Name()}},
		}
		// ⛔ Published only when asked for, because it IS the credential:
		// whoever holds MD4(UTF16LE(password)) authenticates as that person
		// over NTLMv2 without ever learning the password. The configuration
		// refuses to turn this on where it would cross a network in the clear.
		if s.cfg.PublishNTHash {
			if key, err := id.NTKey(); err == nil {
				attrs = append(attrs, &ldap.EntryAttribute{
					Name: "sambaNTPassword", Values: []string{strings.ToUpper(hex.EncodeToString(key))},
				})
			}
		}
		if keys := id.Keys(); len(keys) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "sshPublicKey", Values: keys})
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
			Attributes: []*ldap.EntryAttribute{
				{Name: "objectClass", Values: []string{"top", "posixGroup"}},
				{Name: "cn", Values: []string{name}},
				{Name: "memberUid", Values: members},
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
