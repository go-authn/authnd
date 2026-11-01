// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// certStore serves the certificate to every handshake, and reads cert_file and
// key_file again when they change.
//
// ⛔ The certificate used to be read once, at startup, and a renewed one (ACME,
// every 60 to 90 days) needed a restart: a directory whose certificate expired
// at 03:00 stopped being trusted by every client until somebody noticed. The
// store looks at the two files' identity (the SHA-256 of their content, which
// sees a renewer renaming a new file over the old one as well as one rewriting
// it in place) at most once per `recheck`, on the first
// handshake after that, and on SIGHUP. It does not need the refresh tick,
// which `refresh = "0"` turns off.
//
// A new pair that does not load -- half written, a key that does not match, a
// garbage file -- changes nothing: the certificate being served stays, the
// failure is logged ONCE per state of the files, and the next change is tried
// again. Bibliography: crypto/tls Config.GetCertificate (Go 1.27): called for
// every ClientHello when Certificates is empty, so a new pair needs no
// listener restart.
type certStore struct {
	certFile, keyFile string
	out               io.Writer
	now               func() time.Time
	recheck           time.Duration

	mu      sync.Mutex
	cert    *tls.Certificate
	served  fileIdentity // the files the served certificate came from
	failed  fileIdentity // the files a load last failed on
	checked time.Time
}

// fileIdentity is what says a file was replaced or rewritten.
type fileIdentity struct {
	cert, key fileStamp
}

// fileStamp is the SHA-256 of a file's content. ⛔ It used to be (size,
// modification time, inode): a renewed certificate of the same size, written
// within the filesystem's timestamp tick into a recycled inode, looked
// unchanged, and was not served (seen under qemu on CI). The files are a few
// kilobytes and are read at most once per `recheck`; the content is the only
// identity that cannot collide.
type fileStamp struct {
	sum [sha256.Size]byte
	ok  bool
}

func stampOf(path string) fileStamp {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > maxCertFile {
		return fileStamp{}
	}
	return fileStamp{sum: sha256.Sum256(b), ok: true}
}

// maxCertFile bounds what is read to look at a certificate or key file.
const maxCertFile = 1 << 20

func (s *certStore) identity() fileIdentity {
	return fileIdentity{cert: stampOf(s.certFile), key: stampOf(s.keyFile)}
}

// newCertStore loads the pair, as startup does: a pair that does not load is
// an error here and nowhere later.
func newCertStore(certFile, keyFile string, out io.Writer) (*certStore, error) {
	s := &certStore{certFile: certFile, keyFile: keyFile, out: out, now: time.Now, recheck: 5 * time.Second}
	id := s.identity()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("the certificate: %w", err)
	}
	s.cert, s.served, s.checked = &cert, id, s.now()
	return s, nil
}

// get is tls.Config.GetCertificate.
func (s *certStore) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A negative elapsed time (a clock stepped back, an emulated CPU whose
	// threads disagree by a few nanoseconds) is not "recently checked": look.
	if d := s.now().Sub(s.checked); d >= s.recheck || d < 0 {
		s.reloadLocked(false)
	}
	return s.cert, nil
}

// Reload looks at the files now, whatever the last look was (SIGHUP).
func (s *certStore) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadLocked(true)
}

func (s *certStore) reloadLocked(force bool) {
	s.checked = s.now()
	id := s.identity()
	if id == s.served && !force {
		return
	}
	if id == s.failed && !force {
		return // this state of the files was tried, and said so
	}
	// Read the files at the identity we stamped. A renewer that replaces the
	// two files one after the other is seen half done on the first look, which
	// fails (or, for a matching pair, succeeds), and again after the second.
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		if id != s.failed || force {
			fmt.Fprintf(s.out, "certificate not reloaded, still serving the previous one: %v\n", err)
		}
		s.failed = id
		return
	}
	if id == s.served { // forced, and nothing changed
		return
	}
	s.cert, s.served, s.failed = &cert, id, fileIdentity{}
	fmt.Fprintf(s.out, "certificate reloaded from %s (expires %s)\n", s.certFile, expiry(&cert))
}

func expiry(c *tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return "unknown"
	}
	if leaf := c.Leaf; leaf != nil {
		return leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	return "unknown"
}
