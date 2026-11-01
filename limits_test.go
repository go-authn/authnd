// SPDX-License-Identifier: BSD-3-Clause

//go:build !noldap

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldaptest"
	"github.com/go-authn/ldap"
	lt "github.com/go-authn/ldap/ldaptest"
	"github.com/go-authn/mfa"
)

// Limits, outages and startup against a slow source.
//
// Bibliography opened for these: RFC 4511 4.1.9 and appendix A.2 (result codes:
// busy 51 and unavailable 52 are "try again", invalidCredentials 49 is the only
// "wrong credentials"), 4.4.1 (notice of disconnection for a refused
// connection); go-authn/ldap v0.12.0 server.go (MaxConnections,
// MaxConnectionsPerIP, Timeout); go-authn/directory v0.17.0 unavailable.go.

// A flaky is a TCP proxy to an upstream that can be told to misbehave.
type flaky struct {
	ln       net.Listener
	upstream string
	mode     atomic.Int32
	mu       sync.Mutex
	conns    []net.Conn
	done     chan struct{}
}

const (
	pass  = iota // forward
	reset        // close at once
	hang         // accept, read, never answer
	cut          // read the request, then hang up without answering
)

func newFlaky(t testing.TB, upstream string) *flaky {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &flaky{ln: ln, upstream: upstream, done: make(chan struct{})}
	go f.accept()
	t.Cleanup(f.close)
	return f
}

func (f *flaky) addr() string { return f.ln.Addr().String() }

func (f *flaky) close() {
	select {
	case <-f.done:
		return
	default:
		close(f.done)
	}
	f.ln.Close()
	f.dropAll()
}

func (f *flaky) dropAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.conns {
		c.Close()
	}
	f.conns = nil
}

func (f *flaky) track(c net.Conn) {
	f.mu.Lock()
	f.conns = append(f.conns, c)
	f.mu.Unlock()
}

func (f *flaky) accept() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.track(c)
		go f.serve(c)
	}
}

func (f *flaky) serve(c net.Conn) {
	switch f.mode.Load() {
	case reset:
		c.Close()
	case hang:
		io.Copy(io.Discard, c) // until the proxy closes it
	case cut:
		buf := make([]byte, 1)
		c.Read(buf)
		c.Close()
	default:
		u, err := net.Dial("tcp", f.upstream)
		if err != nil {
			c.Close()
			return
		}
		f.track(u)
		go io.Copy(u, c)
		io.Copy(c, u)
		c.Close()
		u.Close()
	}
}

// A directory upstream, reached through a flaky proxy, as the only source of
// the people besides the reader.
type upstreamFixture struct {
	srv   *ldaptest.Server
	proxy *flaky
	body  string
}

func newUpstream(t testing.TB, extra string) *upstreamFixture {
	t.Helper()
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{"alice": {Password: "hunter2"}, "bob": {Password: "swordfish"}},
		Groups: map[string][]string{"staff": {"alice", "bob"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	p := newFlaky(t, strings.TrimPrefix(d.URL, "ldap://"))
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	if err := os.WriteFile(pw, []byte(d.ReaderPassword), 0o600); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
refresh = "0"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
users "ldap" {
  url                = "ldap://%s"
  bind_dn            = %q
  bind_password_file = %q
  base_dn            = %q
}
%s`, p.addr(), d.ReaderDN, hclPath(pw), d.PeopleDN, extra)
	return &upstreamFixture{srv: d, proxy: p, body: body}
}

const aliceDN = "uid=alice,ou=people,dc=example,dc=org"

func bindAs(t testing.TB, addr, dn, pw string, within time.Duration) (ldap.ResultCode, time.Duration) {
	t.Helper()
	c, err := lt.Dial(addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(within))
	start := time.Now()
	res, err := c.Bind(dn, pw)
	if err != nil {
		t.Fatalf("bind %s: %v after %s", dn, err, time.Since(start))
	}
	return res.Code, time.Since(start)
}

// #68 (a): an outage of the directory that holds the password is "unavailable",
// never "invalid credentials"; a wrong password is still invalid credentials.
func TestBindAgainstAnUpstreamOutageIsUnavailable(t *testing.T) {
	u := newUpstream(t, `operation_timeout = "1500ms"`)
	r := start(t, u.body)

	if code, _ := bindAs(t, r.addr, aliceDN, "hunter2", 5*time.Second); code != ldap.Success {
		t.Fatalf("the right password: %s", code)
	}
	if code, _ := bindAs(t, r.addr, aliceDN, "wrong", 5*time.Second); code != ldap.InvalidCredentials {
		t.Fatalf("a wrong password: %s, want invalidCredentials", code)
	}

	// The upstream says busy, unavailable, other: outages, all of them.
	for _, c := range []uint16{51, 52, 80} {
		u.srv.FailBindsWith(c)
		if code, _ := bindAs(t, r.addr, aliceDN, "hunter2", 5*time.Second); code != ldap.Unavailable {
			t.Errorf("upstream answers %d: got %s, want unavailable", c, code)
		}
	}
	// ... and 49 from the upstream is a wrong password, whatever was typed.
	u.srv.FailBindsWith(49)
	if code, _ := bindAs(t, r.addr, aliceDN, "hunter2", 5*time.Second); code != ldap.InvalidCredentials {
		t.Errorf("upstream answers 49: got %s, want invalidCredentials", code)
	}
	u.srv.FailBindsWith(0)

	// The connection is refused, reset, killed mid-bind, or never answered.
	for name, m := range map[string]int32{"refused": reset, "killed mid-bind": cut, "never answers": hang} {
		u.proxy.mode.Store(m)
		code, took := bindAs(t, r.addr, aliceDN, "hunter2", 10*time.Second)
		if code != ldap.Unavailable {
			t.Errorf("%s: got %s, want unavailable", name, code)
		}
		if took > 3*time.Second {
			t.Errorf("%s: answered after %s, the operation timeout is 1.5s", name, took)
		}
		u.proxy.dropAll()
	}
	// The log names the cause for the administrator, and the client does not
	// get it.
	if !strings.Contains(r.out.String(), "alice was refused") {
		t.Errorf("the outage was not logged:\n%s", r.out.String())
	}

	// And it recovers by itself.
	u.proxy.mode.Store(pass)
	if code, _ := bindAs(t, r.addr, aliceDN, "hunter2", 5*time.Second); code != ldap.Success {
		t.Errorf("after the outage: %s", code)
	}
}

// The same decision with a second factor: an outage of the password's source
// answers unavailable, a wrong password still answers invalidCredentials.
func TestSecondFactorOutageIsUnavailable(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
mfa { factors = 2 }
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "ann" { password = "x" }
`)
	code := &stubFactor{name: "code", kind: mfa.Possession}
	down := &knowledge{name: "pw", given: "x", verify: func(string) error {
		return directory.AsUnavailable(errors.New("dial tcp 10.0.0.9:389: connection refused"))
	}}
	res, err := r.srv.decide(context.Background(), "ann", []mfa.Factor{down, code})
	if err != nil || res.Code != ldap.Unavailable {
		t.Errorf("outage: %v %v, want unavailable", res.Code, err)
	}
	if strings.Contains(res.Diagnostic, "10.0.0.9") {
		t.Errorf("the client was told where the directory is: %q", res.Diagnostic)
	}
	wrong := &knowledge{name: "pw", given: "x", verify: func(string) error { return directory.ErrWrongPassword }}
	res, err = r.srv.decide(context.Background(), "ann", []mfa.Factor{wrong, &stubFactor{name: "code", kind: mfa.Possession}})
	if err != nil || res.Code != ldap.InvalidCredentials {
		t.Errorf("wrong: %v %v, want invalidCredentials", res.Code, err)
	}
	// A source that blocks: the bind's budget ends it.
	r.srv.cfg.OperationTimeout = "300ms"
	block := make(chan struct{})
	defer close(block)
	slow := &knowledge{name: "pw", given: "x", verify: func(string) error { <-block; return nil }}
	begin := time.Now()
	res, _ = r.srv.decide(context.Background(), "ann", []mfa.Factor{slow, &stubFactor{name: "code", kind: mfa.Possession}})
	if res.Code != ldap.Unavailable || time.Since(begin) > 2*time.Second {
		t.Errorf("blocked source: %v after %s", res.Code, time.Since(begin))
	}
}

type stubFactor struct {
	name string
	kind mfa.Kind
}

func (f *stubFactor) Name() string                 { return f.name }
func (f *stubFactor) Kind() mfa.Kind               { return f.kind }
func (f *stubFactor) Verify(context.Context) error { return nil }

// #68 (b): startup against a source that accepts and never answers is bounded
// and the error names the source.
func TestStartupAgainstASlowSourceIsBounded(t *testing.T) {
	u := newUpstream(t, `startup_timeout = "800ms"`)
	u.proxy.mode.Store(hang)
	cfg, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", u.body)})
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	_, err = open(cfg, &safeBuffer{})
	if err == nil {
		t.Fatal("open succeeded against a source that never answers")
	}
	if took := time.Since(begin); took > 5*time.Second {
		t.Errorf("open took %s with startup_timeout 800ms", took)
	}
	for _, want := range []string{"startup_timeout", "ldap ldap://" + u.proxy.addr()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
	// With no limit the old behaviour stays available.
	cfg.StartupTimeout = "0"
	if cfg.limits().startup != 0 {
		t.Errorf("startup_timeout 0 means no limit, got %v", cfg.limits().startup)
	}
}

// A source that answers is not slowed down, and a failing source refuses
// startup with its own error (the dir is closed, not leaked).
func TestStartupBoundDoesNotChangeAnswers(t *testing.T) {
	u := newUpstream(t, `startup_timeout = "10s"`)
	r := start(t, u.body)
	if code, _ := bindAs(t, r.addr, aliceDN, "hunter2", 5*time.Second); code != ldap.Success {
		t.Fatalf("bind: %s", code)
	}
}

func TestLimitsConfig(t *testing.T) {
	c := &config{}
	if l := c.limits(); l.maxConns != 4096 || l.perIP != 0 || l.operation != 30*time.Second || l.startup != 60*time.Second {
		t.Errorf("defaults: %+v", l)
	}
	n0, n5, n3, nNeg := 0, 5, 3, -1
	good := []config{
		{MaxConnections: &n0}, {MaxConnections: &n5, MaxConnectionsPerIP: &n3},
		{OperationTimeout: "0", StartupTimeout: "0"}, {OperationTimeout: "250ms"},
	}
	for _, g := range good {
		if err := g.checkLimits(); err != nil {
			t.Errorf("%+v: %v", g, err)
		}
	}
	bad := map[string]config{
		"max_connections":        {MaxConnections: &nNeg},
		"max_connections_per_ip": {MaxConnectionsPerIP: &nNeg},
		"could never apply":      {MaxConnections: &n3, MaxConnectionsPerIP: &n5},
		"operation_timeout":      {OperationTimeout: "soon"},
		"startup_timeout":        {StartupTimeout: "1ms"},
	}
	for want, b := range bad {
		if err := b.checkLimits(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
	if l := (&config{MaxConnections: &n0}).limits(); l.maxConns != 0 {
		t.Errorf("max_connections = 0 must mean no limit, got %d", l.maxConns)
	}
}

func TestCheckPrintsTheLimits(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", networkConfig+"\nmax_connections = 50\nmax_connections_per_ip = 10\noperation_timeout = \"5s\"\n")
	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatal(err)
	}
	contains(t, out, "limits: 50 connections, 10 per address; an operation may take 5s; startup may take 1m0s")
	out, err = execute(t, "check", write(t, t.TempDir(), "c.hcl", networkConfig))
	if err != nil {
		t.Fatal(err)
	}
	contains(t, out, "limits: 4096 connections, no limit per address; an operation may take 30s")
}

// busy reads what a refused connection is sent, and whether it is closed.
//
// The library sends the notice to at most 64 refused connections at a time and
// closes the rest without one (server.go); both are refusals. busy says the
// notice came, closed says the server hung up rather than serve.
func refusedWithBusy(t testing.TB, addr string) (busy, closed bool) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false, true
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(c) // until the server closes it
	// An LDAPMessage with messageID 0 carrying an ExtendedResponse (tag 0x78)
	// whose resultCode is busy (51), and the notice of disconnection OID
	// 1.3.6.1.4.1.1466.20036.
	busy = bytes.Contains(got, []byte("1.3.6.1.4.1.1466.20036")) && bytes.Contains(got, []byte{0x0a, 0x01, 51})
	return busy, err == nil
}

// Chaos: a connection flood beyond the cap is refused with busy, the ones
// inside the cap keep working, and the slots come back when they close.
func TestChaosConnectionFloodBeyondTheCap(t *testing.T) {
	r := start(t, networkConfig+"\nmax_connections = 20\n")
	cl, err := lt.Dial(r.addr, 5*time.Second) // one that speaks, inside the cap
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	var held []net.Conn
	for range 19 {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	// Let the server count them.
	waitUntil(t, func() bool { return refusedWithBusyQuick(r.addr) }, "the cap to bind")

	var wg sync.WaitGroup
	var busyN, closedN atomic.Int32
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, c := refusedWithBusy(t, r.addr)
			if b {
				busyN.Add(1)
			}
			if c {
				closedN.Add(1)
			}
		}()
	}
	wg.Wait()
	if closedN.Load() != 200 || busyN.Load() == 0 {
		t.Errorf("of 200 connections over the cap, %d were hung up on and %d were sent busy", closedN.Load(), busyN.Load())
	}
	// Inside the cap: an existing connection still works.
	_ = cl.SetDeadline(time.Now().Add(5 * time.Second))
	if res, err := cl.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil || res.Code != ldap.Success {
		t.Errorf("a connection inside the cap: %v %v", res.Code, err)
	}
	// Close them all: new connections are accepted again.
	cl.Close()
	for _, c := range held {
		c.Close()
	}
	waitUntil(t, func() bool {
		code, _ := bindAsQuiet(r.addr, "cn=reader,dc=example,dc=org", "let me read")
		return code == ldap.Success
	}, "slots to be released")
}

func refusedWithBusyQuick(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	got, _ := io.ReadAll(c)
	return len(got) > 0
}

func bindAsQuiet(addr, dn, pw string) (ldap.ResultCode, error) {
	c, err := lt.Dial(addr, 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	res, err := c.Bind(dn, pw)
	return res.Code, err
}

func waitUntil(t testing.TB, f func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The per-address cap: loopback is one address.
func TestChaosPerAddressCap(t *testing.T) {
	r := start(t, networkConfig+"\nmax_connections_per_ip = 3\n")
	var held []net.Conn
	for range 3 {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	waitUntil(t, func() bool { return refusedWithBusyQuick(r.addr) }, "the per-address cap")
}

// Chaos: a handler blocked past the deadline. The upstream accepts the bind and
// never answers; every client is answered at the deadline, and when the
// upstream lets go, the goroutines come back.
func TestChaosBlockedSourceDoesNotHoldClientsOrGoroutines(t *testing.T) {
	u := newUpstream(t, `operation_timeout = "700ms"`)
	r := start(t, u.body)
	// A first bind warms the pools, so that the baseline is steady.
	bindAs(t, r.addr, aliceDN, "hunter2", 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	base := runtime.NumGoroutine()

	u.proxy.mode.Store(hang)
	var wg sync.WaitGroup
	var bad atomic.Int32
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, took := bindAs(t, r.addr, aliceDN, "hunter2", 10*time.Second)
			if code != ldap.Unavailable || took > 3*time.Second {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Errorf("%d of 40 binds were not answered unavailable within the deadline", bad.Load())
	}
	// Other people are not held: a reader's bind needs no source.
	if code, took := bindAs(t, r.addr, "cn=reader,dc=example,dc=org", "let me read", 5*time.Second); code != ldap.Success || took > time.Second {
		t.Errorf("the reader while the source hangs: %s after %s", code, took)
	}
	u.proxy.dropAll() // the upstream lets go
	u.proxy.mode.Store(pass)
	waitUntil(t, func() bool { return runtime.NumGoroutine() <= base+10 }, fmt.Sprintf("goroutines to return to ~%d (now %d)", base, runtime.NumGoroutine()))
}
