package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// running is a server under test, with the address it actually got.
type running struct {
	addr string
	out  *safeBuffer
	srv  *server
}

// start opens a configuration and serves it on a port the kernel picks.
func start(t *testing.T, body string) *running {
	t.Helper()
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	out := &safeBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if err := srv.listen(); err != nil {
		srv.Close()
		t.Fatalf("listening: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.serve() }()
	t.Cleanup(func() {
		srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the server did not stop")
		}
	})
	r := &running{addr: srv.Addr(), out: out, srv: srv}
	waitFor(t, r.addr)
	return r
}

func (r *running) url() string { return "ldap://" + r.addr }

func waitFor(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing is listening on %s", addr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// safeBuffer is a buffer a test can read while a server writes it. Two
// goroutines and one bytes.Buffer is a data race whatever the buffer holds.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// hclPath is a path as HCL wants it: Windows separators are escapes in a
// quoted string, and a configuration written with them does not parse.
func hclPath(p string) string { return filepath.ToSlash(p) }

// execute runs the command as a person would, and gives back what it printed.
func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// ldapsearch is OpenLDAP's own client: a judge that knows nothing about this
// program. macOS ships it; a Linux runner installs ldap-utils.
func ldapsearch() (string, bool) {
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/usr/bin/ldapsearch"); err == nil {
			return "/usr/bin/ldapsearch", true
		}
	}
	p, err := exec.LookPath("ldapsearch")
	return p, err == nil
}

func needLDAPSearch(t *testing.T) string {
	t.Helper()
	p, ok := ldapsearch()
	if !ok {
		t.Skip("no ldapsearch here: the foreign judge is OpenLDAP's own client")
	}
	return p
}

// search runs a search and gives back everything printed, plus the error.
func search(bin, url, bindDN, password, base, filter string, attrs ...string) (string, error) {
	args := []string{"-x", "-H", url, "-D", bindDN, "-w", password, "-b", base, filter}
	out, err := exec.Command(bin, append(args, attrs...)...).CombinedOutput()
	return string(out), err
}

// unfold undoes LDIF line folding (RFC 2849 §2): a line longer than about 78
// columns is continued on the next one, which begins with a single space. A
// test asserting on a long value -- an SSH key, a DN -- has to put it back
// together or it is asserting on where the client chose to break.
func unfold(ldif string) string {
	return strings.ReplaceAll(ldif, "\n ", "")
}

func contains(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("output does not contain %q:\n%s", w, out)
		}
	}
}
