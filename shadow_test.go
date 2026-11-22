// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"

	"github.com/go-authn/directory"
)

// A name that a later source spells with another case is the same person as the
// earlier source's (directory v0.26.0); the operator is told once, and again
// only when the list changes.
func TestShadowedSpellingIsSaidOnceAndWhenItChanges(t *testing.T) {
	first := &directory.Static{Name: "local", People: []*directory.Identity{directory.NewIdentity("alice")}}
	second := &directory.Static{Name: "ldap", People: []*directory.Identity{directory.NewIdentity("Alice")}}
	var out strings.Builder
	s := &server{dir: directory.NewSet(first, second), out: &out}
	if _, err := s.dir.Identities(); err != nil {
		t.Fatal(err)
	}
	s.noteShadowed()
	got := out.String()
	for _, want := range []string{`"Alice" of ldap`, `"alice" of local`, "shadowed"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q lacks %q", got, want)
		}
	}
	s.noteShadowed()
	if out.String() != got {
		t.Errorf("an unchanged list was said again: %q", out.String())
	}
	second.People = nil
	if _, err := s.dir.Identities(); err != nil {
		t.Fatal(err)
	}
	s.noteShadowed()
	if !strings.Contains(out.String(), "no name is shadowed") {
		t.Errorf("the end of the shadowing was not said: %q", out.String())
	}
}
