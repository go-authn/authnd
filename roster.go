// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"unicode"

	"github.com/go-authn/directory"
)

// A roster is everybody this server answers for at one moment, by name.
//
// ⛔ It is never edited once it is published. A password change builds a new
// one and swaps it in (server.people), because every connection reads it
// without a lock and the runtime ends a process whose map is written while
// another goroutine ranges over it.
type roster struct {
	byName map[string]*directory.Identity
	// local is the names the configuration file's own user blocks hold, so
	// that a rebuild after a password change can tell its people from the
	// ones a database or a directory published at startup.
	local map[string]bool
}

// newRoster indexes these people, refusing two whose names differ only by
// case.
//
// ⛔ A DN names a person by uid, and a uid is compared ignoring case (RFC 4519
// 2.39, caseIgnoreMatch); go-authn/ldap's EqualDN does the same. A map keyed
// by the exact bytes holds "Backup" and "backup" as two people while every DN
// comparison says they are one, and that disagreement is what let one rewrite
// the other's password. go-authn/directory's "first source owns a name"
// compares bytes too, so both arrive here. Choosing one of them silently would
// be a guess about which person a site meant; refusing to start is the answer
// somebody is there to read.
func newRoster(ids []*directory.Identity, local ...*directory.Identity) (*roster, error) {
	r := &roster{byName: map[string]*directory.Identity{}, local: map[string]bool{}}
	folded := map[string]*directory.Identity{}
	for _, id := range ids {
		key := foldName(id.Name())
		if other, ok := folded[key]; ok && other.Name() != id.Name() {
			return nil, fmt.Errorf("%q (from %s) and %q (from %s) differ only by case, "+
				"and an LDAP name does not tell them apart: a uid is compared ignoring case. "+
				"Rename one of them",
				other.Name(), other.Where(), id.Name(), id.Where())
		}
		folded[key] = id
		r.byName[id.Name()] = id
	}
	for _, id := range local {
		r.local[id.Name()] = true
	}
	return r, nil
}

// foldName is a name reduced to what strings.EqualFold compares -- the same
// equivalence ldap.EqualDN uses -- so that it can key a map: every rune is
// replaced by the smallest rune in its simple case-folding orbit.
func foldName(name string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		return least
	}, name)
}

// who is everybody this server answers for, as of now. Read it once per
// operation: two reads may straddle a password change.
func (s *server) who() map[string]*directory.Identity { return s.people.Load().byName }

// A liveSource is the configuration file's own people, as the source set (and
// the KDC reading through it) sees them.
//
// ⛔ The set is built once, at startup, and the KDC holds it. Before this, a
// password changed over LDAP rebuilt what binds read and left the set's copy
// alone, so kinit went on accepting the old password and refusing the new one.
// The set now holds this, and a password change swaps what it points at.
type liveSource struct {
	p atomic.Pointer[directory.Static]
}

func (l *liveSource) Describe() string { return l.p.Load().Describe() }

func (l *liveSource) Identities() ([]*directory.Identity, error) { return l.p.Load().Identities() }

func (l *liveSource) Members(group string) ([]string, error) { return l.p.Load().Members(group) }

func (l *liveSource) GroupNames() ([]string, error) { return l.p.Load().GroupNames() }
