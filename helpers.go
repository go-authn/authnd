// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/go-authn/directory"
	"golang.org/x/crypto/ssh"
)

// sorted is everybody, in a stable order: a listing that reshuffles itself
// between two runs is one nobody can compare.
func (s *server) sorted() []*directory.Identity {
	out := make([]*directory.Identity, 0, len(s.who))
	for _, id := range s.who {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b *directory.Identity) int { return strings.Compare(a.Name(), b.Name()) })
	return out
}

// groupNames is every group the sources can LIST, plus every one a person's
// own entry named.
//
// Listing is a different question from asking about one, and a source may
// answer the second and not the first -- so what this server publishes can be
// fewer groups than it would answer a membership question about. That is the
// honest half: a directory that will not enumerate is not a directory with no
// groups, and `check` says where the list came from.
func (s *server) groupNames() []string {
	names, err := s.dir.GroupNames()
	if err != nil {
		// Reported where a person looks, and not fatal: a set whose second
		// source is down still publishes what its first one holds.
		fmt.Fprintf(s.out, "the groups could not all be listed: %v\n", err)
	}
	for _, id := range s.who {
		names = append(names, id.Groups()...)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// authorizedKeys is a user block's keys, parsed to REFUSE one that does not
// parse: silently ignoring a bad line is how a server ends up denying the
// person it was configured for, with nothing to say why.
func authorizedKeys(u userBlock) ([]string, error) {
	text := strings.Join(u.AuthorizedKeys, "\n")
	if u.AuthorizedKeysFile != "" {
		b, err := os.ReadFile(u.AuthorizedKeysFile)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Name, err)
		}
		text = string(b)
	}
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
			return nil, fmt.Errorf("user %q: %q is not an authorized_keys line: %w", u.Name, line, err)
		}
		lines = append(lines, line)
	}
	return lines, nil
}

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
