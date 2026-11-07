// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// ⛔ #18: returned means stopped. When runUntil (or Close) returns, the LDAP
// listener and, with a realm, both Kerberos sockets are closed and serve() has
// returned, so that a restart under systemd can bind at once.
//
// The witness is the sockets themselves, not a port number: a port released by
// a test is taken by another test's connection within milliseconds (#81), so a
// re-bind says nothing. An Accept or a ReadFrom on a closed socket returns
// net.ErrClosed at once; on an open one it blocks.

// closedSoon reports whether op returns net.ErrClosed within a second.
func closedSoon(op func() error) (closed bool, err error) {
	ch := make(chan error, 1)
	go func() { ch <- op() }()
	select {
	case err := <-ch:
		return errors.Is(err, net.ErrClosed), err
	case <-time.After(time.Second):
		return false, nil
	}
}

func assertStopped(t *testing.T, srv *server, pc net.PacketConn, rln net.Listener, ln net.Listener) {
	t.Helper()
	for _, c := range []struct {
		name string
		op   func() error
	}{
		{"ldap listener", func() error { _, err := ln.Accept(); return err }},
		{"kerberos udp", func() error { _, _, err := pc.ReadFrom(make([]byte, 1)); return err }},
		{"kerberos tcp", func() error { _, err := rln.Accept(); return err }},
	} {
		if c.name != "ldap listener" && pc == nil {
			continue
		}
		if ok, err := closedSoon(c.op); !ok {
			t.Errorf("%s is still open after the shutdown returned (accept/read: %v)", c.name, err)
		}
	}
	srv.mu.Lock()
	serving := srv.serving
	srv.mu.Unlock()
	if serving {
		t.Error("serve() had not returned")
	}
}

func TestReturnedMeansStopped(t *testing.T) {
	for _, c := range []struct {
		name  string
		realm bool
		after bool // cancel only once the server answers
	}{
		{"ldap, cancelled at once", false, false},
		{"ldap and realm, cancelled at once", true, false},
		{"ldap and realm, cancelled once serving", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			krb := ""
			if c.realm {
				krb = `kerberos {
  realm  = "` + testRealm + `"
  listen = "127.0.0.1:0"
  keytab = "` + hclPath(writeKeytab(t, dir)) + `"
}`
			}
			cfg, err := loadConfig([]string{write(t, dir, "c.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "dora" { password = "hunter2" }
`+krb)})
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
			ln := srv.ln
			var pc net.PacketConn
			var rln net.Listener
			if srv.realm != nil {
				pc, rln = srv.realm.pc, srv.realm.ln
			}
			ctx, cancel := context.WithCancel(context.Background())
			returned := make(chan error, 1)
			go func() { returned <- runUntil(ctx, out, srv) }()
			if c.after {
				waitFor(t, srv.Addr())
			}
			cancel()
			select {
			case err := <-returned:
				if err != nil {
					t.Errorf("a clean shutdown returned %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the shutdown never returned")
			}
			assertStopped(t, srv, pc, rln, ln)
		})
	}
}
