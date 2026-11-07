// SPDX-License-Identifier: BSD-3-Clause

//go:build !noldap

package main

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/ldap"
)

// Second-pass audit 2026-11 (traced, then proven). within() answers when the
// bind budget ends but cannot stop the check it started: Identity.Verify takes
// no context, so the goroutine and its upstream connection live until the
// upstream answers or its own client gives up. Against an upstream that
// accepts and never answers, every bind added one, without bound: an
// unauthenticated client could pile them up as fast as it could bind.
//
// Now at most maxPendingPerSource checks may be outstanding per source; past
// that a bind is answered unavailable at once and starts nothing.
func TestAHungUpstreamCannotAccumulateChecksWithoutBound(t *testing.T) {
	u := newUpstream(t, `operation_timeout = "300ms"`)
	r := start(t, u.body)
	bindAs(t, r.addr, aliceDN, "hunter2", 5*time.Second) // warm the pools
	time.Sleep(200 * time.Millisecond)
	base := runtime.NumGoroutine()

	u.proxy.mode.Store(hang)
	const binds = 400
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)
	var mu sync.Mutex
	peak := 0
	for range binds {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			code, _ := bindAs(t, r.addr, aliceDN, "hunter2", 10*time.Second)
			if code != ldap.Unavailable {
				t.Errorf("a bind against a hung upstream answered %s, want unavailable", code)
			}
			mu.Lock()
			if n := runtime.NumGoroutine(); n > peak {
				peak = n
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	// Goroutines still held by checks the upstream has not answered: bounded.
	held := runtime.NumGoroutine() - base
	t.Logf("peak %d, held after %d binds: %d goroutines (cap %d checks)", peak-base, binds, held, maxPendingPerSource)
	// The checks are CANCELLED when the bind's budget ends (directory
	// VerifyContext closes the upstream connection), so nothing is held after the
	// binds have been answered; a few goroutines of slack for the runtime.
	// The goroutines of cancelled checks unwind a moment after the answer (a
	// loaded host, the race detector, qemu: 22 and 33 were seen at the instant
	// of the count), so the bound is waited for, not sampled once (#91).
	if limit := 20; held > limit {
		waitUntil(t, func() bool { return runtime.NumGoroutine()-base <= limit },
			fmt.Sprintf("at most %d goroutines held after %d binds against a hung upstream (%d when counted)", limit, binds, held))
	}
	u.proxy.dropAll()
	u.proxy.mode.Store(pass)
	waitUntil(t, func() bool { return runtime.NumGoroutine() <= base+10 }, "goroutines to return")
}
