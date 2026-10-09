// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import (
	"strings"
	"syscall"
	"testing"
	"time"
)

// ⛔ A SIGHUP must not end authnd: systemd counts death by SIGHUP as a clean
// exit, so nothing would start it again. The test sends the real signal to
// its own process; without survive, Go's default would kill the test binary.
func TestSIGHUPDoesNotEndTheServer(t *testing.T) {
	var out lockedBuffer
	stop := survive(syscall.SIGHUP, &out)
	defer stop()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "does not reload") {
		if time.Now().After(deadline) {
			t.Fatalf("no word about the signal; printed %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
