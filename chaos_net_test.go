// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/ldap"
	"github.com/go-authn/ldap/ldaptest"
)

// Chaos: clients that misbehave on the wire. go-authn/ldap owns the limits
// (frame.go: 4 MiB a message, 16384 BER elements; server.go: IdleTimeout
// 5 minutes by default, MaxPending 100 and 1000 per connection); authnd sets
// none of them, so these tests are about the defaults it inherits.

func aliveWithin(t *testing.T, r *running, d time.Duration) {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		c, err := ldaptest.Dial(r.addr, d)
		if err != nil {
			done <- "dial: " + err.Error()
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(d))
		res, err := c.Bind("cn=reader,dc=example,dc=org", "let me read")
		if err != nil || res.Code != ldap.Success {
			done <- "bind: " + res.Code.String()
			return
		}
		done <- ""
	}()
	select {
	case msg := <-done:
		if msg != "" {
			t.Fatalf("the server is not answering: %s", msg)
		}
	case <-time.After(d + time.Second):
		t.Fatal("the server did not answer in time")
	}
}

const networkConfig = `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "ann" { password = "x" }
`

// Hundreds of connections that open and never speak do not stop anybody else
// from binding.
func TestChaosSlowlorisDoesNotBlockOthers(t *testing.T) {
	r := start(t, networkConfig)
	var held []net.Conn
	for range 300 {
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
	aliveWithin(t, r, 5*time.Second)
}

// A BER length near 2^31 is refused before anything that size is allocated:
// the connection is closed, promptly, and the server goes on.
func TestChaosOversizedBERLength(t *testing.T) {
	r := start(t, networkConfig)
	for _, head := range [][]byte{
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},                         // SEQUENCE, 2^31-1 bytes
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},                         // 2^32-1
		{0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 8 length bytes
	} {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(head); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		_, err = c.Read(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Errorf("%x: the connection was held open waiting for %d bytes it will never get", head, 1<<31)
		}
		c.Close()
	}
	aliveWithin(t, r, 5*time.Second)
}

// A filter nested as deep as one message can hold neither overflows a stack
// nor holds the server.
func TestChaosDeeplyNestedFilter(t *testing.T) {
	r := start(t, networkConfig)
	for _, depth := range []int{1000, 5000, 20000} {
		c := client(t, r)
		if res, err := c.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil || res.Code != ldap.Success {
			t.Fatal(res.Code, err)
		}
		f := strings.Repeat("(!", depth) + "(uid=ann)" + strings.Repeat(")", depth)
		start := time.Now()
		got, err := c.Search(ldaptest.Search{Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree, Filter: f})
		t.Logf("depth %d: %v, code %v, %d entries, %s", depth, err, got.Result.Code, len(got.Entries), time.Since(start))
		c.Close()
	}
	aliveWithin(t, r, 5*time.Second)
}
