// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"slices"
	"strings"

	"github.com/go-authn/directory"
)

// sorted is everybody, in a stable order: a listing that reshuffles itself
// between two runs is one nobody can compare.
// servedFrom names the sources somebody here is served from, in the order the
// set asks them.
//
// The set's own Describe names every source it holds, and the configuration
// file is always one -- a password change is written there -- so a server
// with no user block said it served people "from the configuration file, then
// a sqlite database": a file that served nobody. With nobody served at all,
// the set's description is still the truthful answer to "from where".
func (s *server) servedFrom() string {
	where := map[string]bool{}
	for _, id := range s.who() {
		where[id.Where()] = true
	}
	var names []string
	for _, src := range s.dir.Sources() {
		if d := src.Describe(); where[d] {
			names = append(names, d)
			delete(where, d)
		}
	}
	if len(names) == 0 {
		return s.dir.Describe()
	}
	return strings.Join(names, ", then ")
}

func (s *server) sorted() []*directory.Identity { return sortedOf(s.snap.Load().people) }

// sortedOf is the people of one roster, by name.
func sortedOf(r *roster) []*directory.Identity {
	out := make([]*directory.Identity, 0, len(r.byName))
	for _, id := range r.byName {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b *directory.Identity) int { return strings.Compare(a.Name(), b.Name()) })
	return out
}

// groupNames is every group the sources can LIST, plus every one a person's
// own entry named, as read at startup (groups.go).
//
// Listing is a different question from asking about one, and a source may
// answer the second and not the first -- so what this server publishes can be
// fewer groups than it would answer a membership question about. That is the
// honest half: a directory that will not enumerate is not a directory with no
// groups, and `check` says where the list came from.
func (s *server) groupNames() []string { return s.snap.Load().groups.names }

// plural picks the word, so a message can say "1 person" without reading like
// a machine wrote it.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// list reads a set of names as a sentence does.
func list(names []string) string {
	switch len(names) {
	case 0:
		return "nobody"
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// mfaDigits is how long a code is here.
func (s *server) mfaDigits() int {
	if s.cfg.MFA != nil && s.cfg.MFA.Digits != 0 {
		return s.cfg.MFA.Digits
	}
	return 6
}

// wantsCode reports whether this bind must carry one.
func (s *server) wantsCode() bool { return s.policy.Count >= 2 }
