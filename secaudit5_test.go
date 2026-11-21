// SPDX-License-Identifier: BSD-3-Clause

package main

// Security audit 2026-11-21 (secaudit5). maxPendingPerSource was written for
// checks that OUTLIVED their bind budget. It used to count every check from the
// moment it started, so 64 binds that were merely in flight -- none late, none
// abandoned -- made the 65th person's correct password answer unavailable at
// once.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/directory"
)

func TestSecaudit5SixtyFourInFlightChecksRefuseTheNextBind(t *testing.T) {
	const source = "secaudit5-source"
	release := make(chan struct{})
	var started atomic.Int32
	var wg sync.WaitGroup
	for range maxPendingPerSource {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// No deadline has passed: this is an ordinary check being computed.
			_ = within(context.Background(), source, func() error { started.Add(1); <-release; return nil })
		}()
	}
	defer func() { close(release); wg.Wait() }()
	deadline := time.Now().Add(30 * time.Second)
	for started.Load() != maxPendingPerSource {
		if time.Now().After(deadline) {
			t.Fatalf("only %d checks started", started.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := within(context.Background(), source, func() error { return nil }); err != nil {
		t.Fatalf("a correct password was answered %q while %d checks were in flight, none past its budget", err, maxPendingPerSource)
	}
}

// The bound still holds for what it was written for: checks past their budget
// that are still running. The 65th is refused without starting, and a finished
// late check frees its place.
func TestSecaudit5LateChecksStillBoundTheSource(t *testing.T) {
	const source = "secaudit5-late"
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range maxPendingPerSource {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := within(ctx, source, func() error { <-release; return nil }); !errors.Is(err, directory.ErrUnavailable) {
				t.Errorf("a late check answered %v, want unavailable", err)
			}
		}()
	}
	wg.Wait() // every one has answered unavailable, none has finished
	var ran atomic.Bool
	err := within(context.Background(), source, func() error { ran.Store(true); return nil })
	if !errors.Is(err, directory.ErrUnavailable) || ran.Load() {
		t.Fatalf("the check after %d late ones: err %v, started %v; want refused unstarted", maxPendingPerSource, err, ran.Load())
	}
	close(release)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := within(context.Background(), source, func() error { return nil }); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("finished late checks still hold their place")
		}
		time.Sleep(10 * time.Millisecond)
	}
	pendingChecks.Lock()
	n := len(pendingChecks.n)
	pendingChecks.Unlock()
	if n != 0 {
		t.Fatalf("%d sources still counted after every check finished", n)
	}
}
