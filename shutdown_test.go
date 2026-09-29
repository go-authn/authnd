// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ⛔ The shutdown path runs during every restart, and until now no test could
// reach it: reaching it meant sending this process a SIGTERM and ending the
// run it is part of. The signal was never the interesting part -- what the
// loop does when the context ends is -- so the loop now takes a context and
// the signal stays in `serve`.
//
// What it has to get right is the thing a restart depends on: it must not
// return until the server has ACTUALLY stopped. A shutdown that returns
// early reports success while connections are still being answered, and the
// next start fails with "address already in use" -- which is then blamed on
// the port, the orchestrator, or anything but the thing that lied.
func TestShutdownWaitsForTheServerToActuallyStop(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "dora" { password = "hunter2" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	out := &lockedBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.listen(); err != nil {
		t.Fatal(err)
	}
	addr := srv.Addr()

	// The control: it really is answering before we stop it.
	if c, err := net.DialTimeout("tcp", addr, 5*time.Second); err != nil {
		t.Fatalf("nothing was listening, so this test proves nothing: %v", err)
	} else {
		c.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { returned <- runUntil(ctx, out, srv) }()

	cancel()
	select {
	case err := <-returned:
		if err != nil {
			t.Errorf("a clean shutdown returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the shutdown never returned")
	}

	// It said so, where an operator watching a restart would see it.
	if !strings.Contains(out.String(), "stopping") {
		t.Errorf("the shutdown said nothing:\n%s", out.String())
	}

	// ⛔ And the port is FREE. This is the assertion the whole refactor is
	// for: "returned" is not "stopped", and only the port can tell them
	// apart.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the port is still held after shutdown returned: %v", err)
	}
	ln.Close()
}

// A server that stops on its own -- a listener that died, a port taken from
// under it -- returns its own error rather than waiting for a signal that is
// never coming.
func TestAServerThatStopsOnItsOwnReportsWhy(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "dora" { password = "hunter2" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	out := &lockedBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.listen(); err != nil {
		t.Fatal(err)
	}

	// Nothing will cancel this context: the only way out is the server
	// ending, which is the branch under test.
	returned := make(chan error, 1)
	go func() { returned <- runUntil(context.Background(), out, srv) }()

	// Stop it from underneath, the way a closed listener would.
	time.Sleep(50 * time.Millisecond)
	srv.Close()

	select {
	case <-returned:
		// Whatever it returned, it RETURNED -- it did not sit waiting for a
		// signal that was never coming.
	case <-time.After(10 * time.Second):
		t.Fatal("the loop did not notice the server had stopped")
	}
	// And it did not announce a shutdown it did not perform.
	if strings.Contains(out.String(), "stopping") {
		t.Errorf("it announced a shutdown nobody asked for:\n%s", out.String())
	}
}

// lockedBuffer is a buffer a test can read while a server writes it. Two
// goroutines and one bytes.Buffer is a data race whatever the buffer holds --
// measured in a sibling repository, where it passed locally and CI's race
// detector caught it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestCloseFreesTheListenerTheLibraryNeverTracked pins the window that made
// TestShutdownWaitsForTheServerToActuallyStop fail on riscv64 and on s390x --
// on three different branches, one of them main, so it was never about the
// dependency bump that happened to be under it.
//
// go-authn/ldap tracks a listener inside Serve and refuses to track one once
// Close has been called:
//
//	func (s *Server) track(ln) bool  { if s.closing { return false } ... }
//	func (s *Server) Serve(ln) error { if !s.track(ln) { return net.ErrClosed } ... }
//
// serve() sets `serving` BEFORE ldap.Serve reaches track. A Close landing in
// that window read serving=true, closed the listeners the library knew about
// -- none -- and Serve then returned ErrClosed without closing the listener
// either. The port stayed held by a server that had reported a clean stop.
//
// Rather than race for that window, this names the state directly: the library
// is already closing, and our server believes it is serving.
func TestCloseFreesTheListenerTheLibraryNeverTracked(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "dora" { password = "hunter2" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &lockedBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.listen(); err != nil {
		t.Fatal(err)
	}
	addr := srv.Addr()

	// The control: the port really is taken, or the assertion below is free.
	if ln, err := net.Listen("tcp", addr); err == nil {
		ln.Close()
		t.Fatal("the port was never held, so this test proves nothing")
	}

	// The window, stated rather than raced for.
	srv.ldap.Close()
	srv.mu.Lock()
	srv.serving = true
	srv.mu.Unlock()

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the listener leaked: %v", err)
	}
	ln.Close()
}
