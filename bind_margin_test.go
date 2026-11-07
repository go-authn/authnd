// SPDX-License-Identifier: BSD-3-Clause

//go:build !noldap

package main

import (
	"testing"
	"time"

	"github.com/go-authn/ldap"
)

func TestBindMargin(t *testing.T) {
	for _, c := range []struct{ op, want time.Duration }{
		{300 * time.Millisecond, 150 * time.Millisecond}, // the floor, capped at half
		{40 * time.Millisecond, 20 * time.Millisecond},   // never more than half
		{time.Second, 250 * time.Millisecond},            // the floor
		{30 * time.Second, 3 * time.Second},              // a tenth
		{time.Nanosecond, 0},
	} {
		if got := bindMargin(c.op); got != c.want {
			t.Errorf("bindMargin(%s) = %s, want %s", c.op, got, c.want)
		}
		if c.op > 0 && c.op-bindMargin(c.op) <= 0 && c.op > 1 {
			t.Errorf("the budget of %s is not positive", c.op)
		}
	}
}

// #91: the answer to a bind against a hung upstream is decided by a margin, not
// by how fast the host schedules. Here the check wakes 100 ms after its budget
// ended, as on a loaded runner: with a margin of a tenth of 300 ms (30 ms) the
// library's own deadline answered timeLimitExceeded first, every time.
func TestAHungUpstreamIsUnavailableEvenWhenTheCheckWakesLate(t *testing.T) {
	u := newUpstream(t, `operation_timeout = "300ms"`)
	r := start(t, u.body)
	bindAs(t, r.addr, aliceDN, "hunter2", 5*time.Second) // warm the pools
	u.proxy.mode.Store(hang)
	late := func() { time.Sleep(100 * time.Millisecond) }
	afterBudget.Store(&late)
	t.Cleanup(func() { afterBudget.Store(nil) })
	for range 3 {
		if code, _ := bindAs(t, r.addr, aliceDN, "hunter2", 10*time.Second); code != ldap.Unavailable {
			t.Fatalf("a bind against a hung upstream, its check waking 100ms late, answered %s, want unavailable", code)
		}
	}
	u.proxy.dropAll()
	u.proxy.mode.Store(pass)
}
