// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"slices"

	"github.com/go-authn/directory"
)

// groupFacts is everything the sources said about one group, at startup.
type groupFacts struct {
	members  []string
	attrs    directory.Attributes
	declared directory.ObjectClasses
	// missing is set for a group a person names and no source has.
	missing error
}

// groupSnapshot is every group this server publishes, read once.
//
// ⛔ Groups are read at startup, like the people (server.people), and not at
// every search. They were read at every search: each search ran the groups
// queries again, several full scans per group, so the cost of one search grew
// with the size of the groups tables and a reader could keep a database busy
// by asking in a loop. And a query that failed in the middle of a search left
// the group out of an answer that still said Success -- people from the
// startup snapshot, groups from "now", and the broken half silently missing.
// A client that treats a missing group as "nobody is in it" revokes access.
//
// Built once and never edited, so a connection reads it without a lock. A
// source that cannot be read refuses startup (open), as a people query does.
type groupSnapshot struct {
	names []string
	by    map[string]*groupFacts
}

// readGroups asks every source what groups it has and who is in them.
//
// ⛔ Each source is asked for its own list. directory.Set.GroupNames returns
// the groups the sources that answered named and drops the error of one that
// did not, so a second database that was down would have been a smaller
// directory with nothing saying so.
//
// ⛔ And each source is READ once. Asking a database for the members,
// attributes and classes of each group runs its queries again every time:
// three scans of every membership row per group, which was 2 s of one core for
// 200 groups of 50 and grows with groups x rows, so a site ten times the size
// would not finish inside the refresh period. Set.Frozen reads each source in
// bulk and answers the same questions from memory, with the Set's own merging.
func readGroups(set *directory.Set, people []*directory.Identity) (*groupSnapshot, error) {
	set, err := set.Frozen()
	if err != nil {
		return nil, fmt.Errorf("reading the groups: %w", err)
	}
	var names []string
	for _, src := range set.Sources() {
		lister, ok := src.(directory.GroupLister)
		if !ok {
			continue
		}
		got, err := lister.GroupNames()
		if err != nil {
			return nil, fmt.Errorf("listing the groups of %s: %w", src.Describe(), err)
		}
		names = append(names, got...)
	}
	for _, id := range people {
		names = append(names, id.Groups()...)
	}
	slices.Sort(names)
	names = slices.Compact(names)

	snap := &groupSnapshot{by: map[string]*groupFacts{}}
	for _, name := range names {
		members, err := set.Members(name)
		if errors.Is(err, directory.ErrNoSuchGroup) {
			// Named by a person and described by no source: a source that will
			// not enumerate is not a directory with no groups. It is listed,
			// not published, and `check` says why.
			snap.names = append(snap.names, name)
			snap.by[name] = &groupFacts{missing: err}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading the members of group %q: %w", name, err)
		}
		attrs, err := set.GroupAttributes(name)
		if err != nil && !errors.Is(err, directory.ErrNoSuchGroup) {
			return nil, fmt.Errorf("reading the attributes of group %q: %w", name, err)
		}
		declared, err := set.GroupObjectClasses(name)
		if err != nil && !errors.Is(err, directory.ErrNoSuchGroup) {
			return nil, fmt.Errorf("reading the object classes of group %q: %w", name, err)
		}
		snap.names = append(snap.names, name)
		snap.by[name] = &groupFacts{members: members, attrs: attrs, declared: declared}
	}
	return snap, nil
}
