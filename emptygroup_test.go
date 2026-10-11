// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"

	"github.com/go-authn/directory"
)

// A group a source has, with nobody in it, is published -- as a posixGroup
// with no memberUid, since an entry's attribute has at least one value (RFC
// 4511 4.1.7) and memberUid is MAY (RFC 2307). Before go-authn/directory
// v0.12.0 it was "no such group" and left out, although a source listed it;
// adopting v0.12.0 as it was would have published an EMPTY memberUid.
func TestAnEmptyGroupIsPublishedWithoutMembers(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "alicepw" }
`)
	r.srv.dir = directory.NewSet(&directory.Static{Groups: map[string][]string{
		"empty": {},
		"staff": {"alice"},
	}})
	entries := map[string]map[string][]string{}
	for _, e := range r.srv.groupEntries() {
		attrs := map[string][]string{}
		for _, a := range e.Attributes {
			var vs []string
			for _, v := range a.Values {
				vs = append(vs, string(v))
			}
			attrs[a.Name] = vs
		}
		entries[e.DN] = attrs
	}
	empty, ok := entries["cn=empty,ou=groups,dc=example,dc=org"]
	if !ok {
		t.Fatalf("the empty group is not published: %v", entries)
	}
	if v, has := empty["memberUid"]; has {
		t.Errorf("the empty group carries a memberUid with %d values; an entry's attribute must have at least one", len(v))
	}
	if strings.Join(entries["cn=staff,ou=groups,dc=example,dc=org"]["memberUid"], ",") != "alice" {
		t.Errorf("staff: %v", entries["cn=staff,ou=groups,dc=example,dc=org"])
	}
}
