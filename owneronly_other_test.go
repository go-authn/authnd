//go:build !windows

package main

import "testing"

// ownerOnly is the mode 0600 the file was written with, off Windows.
func ownerOnly(testing.TB, string) {}
