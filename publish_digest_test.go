// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// digestOf is every observable of a publication, in order: the entries, with
// their attributes and values, what was dropped and left off, and why an entry
// is not published.
func digestOf(p publication) string {
	h := sha256.New()
	for _, e := range p.all {
		fmt.Fprintf(h, "%s|%v|%s\n", e.DN, e.group, errText(e.invalid))
		for _, a := range e.Attributes {
			fmt.Fprintf(h, " %s=%q\n", a.Name, a.Values)
		}
		for _, d := range e.dropped {
			fmt.Fprintf(h, " dropped %s: %s\n", d.name, d.why)
		}
		for _, l := range e.leftOff {
			fmt.Fprintf(h, " left off %+v\n", l)
		}
		fmt.Fprintf(h, " declared %v\n", e.declared)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// manyPeople is rulesConfig's site with n more people of the four kinds the
// rules treat differently (an account with a description the rule precludes,
// an account that keeps its keys, an inetOrgPerson with and without the
// telephone number its rule requires) and a posixGroup for each ten.
func manyPeople(t *testing.T, n int, schemaFiles ...string) string {
	var b strings.Builder
	b.WriteString(rulesConfig(t, "dc=example,dc=org", schemaFiles...))
	for i := range n {
		switch i % 4 {
		case 0:
			fmt.Fprintf(&b, "user \"p%d\" {\n  password = \"x\"\n  attributes = { uidNumber = \"%d\", gidNumber = \"100\", homeDirectory = \"/home/p%d\", description = \"d\" }\n}\n", i, 2000+i, i)
		case 1:
			fmt.Fprintf(&b, "user \"p%d\" {\n  password = \"x\"\n  authorized_keys = [\""+shapeKey+"\"]\n  attributes = { uidNumber = \"%d\", gidNumber = \"100\", homeDirectory = \"/home/p%d\" }\n}\n", i, 2000+i, i)
		case 2:
			fmt.Fprintf(&b, "user \"p%d\" {\n  password = \"x\"\n  attributes = { sn = \"P%d\", telephoneNumber = \"+33 1 23 45 %02d\", mail = \"p%d@example.org\" }\n}\n", i, i, i%100, i)
		default:
			fmt.Fprintf(&b, "user \"p%d\" {\n  password = \"x\"\n  attributes = { sn = \"P%d\", description = \"no phone\" }\n}\n", i, i)
		}
		if i%10 == 0 {
			fmt.Fprintf(&b, "group \"g%d\" {\n  members = [\"p%d\"]\n  attributes = { gidNumber = \"%d\" }\n}\n", i, i, 500+i)
		}
	}
	return b.String()
}

// Publishing is a pure function of the configuration: this digest was taken
// from v0.13.2, before the work on its allocations, and must not move.
func TestPublishedEntriesAreUnchanged(t *testing.T) {
	rules := testdataPath(t, "rules.schema")
	for _, c := range []struct {
		name, want string
		files      []string
	}{
		{"with the rules", "160b67541d1fb22d52f3a43afb56737e1fef51e3737cd76b4fdc52cbdf4f4260", []string{rules}},
		{"without", "5f6c0a1aba5083c44ef842607886c0b884b34a20d2ebb49b7c4d5b2370ba8743", nil},
	} {
		got := digestOf(publishedFor(t, manyPeople(t, 400, c.files...)))
		if c.want == "" {
			t.Errorf("%s: digest %s", c.name, got)
			continue
		}
		if got != c.want {
			t.Errorf("%s: published entries changed: digest %s, want %s", c.name, got, c.want)
		}
	}
}
