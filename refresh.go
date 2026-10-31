// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-authn/ldap"
)

// The periodic refresh.
//
// ⛔ v0.13.4 read every source once, at startup, and a person or a member
// removed from a database was served until a restart: a REVOCATION that waits
// for somebody to restart a server is not one. Every `refresh` (60 s unless
// the configuration says otherwise) the people and the groups of every source
// are read again into a NEW snapshot, built and held to the schema entirely
// off the serving path, and swapped in whole. A search loads the snapshot once
// and answers from that one for its whole duration.
//
// A refresh that fails -- a source that cannot be read, a refusal that would
// have refused startup -- changes nothing: the last good snapshot is served,
// the failure is said once per streak with the source named, and max_age says
// when to stop serving it at all.

const defaultRefresh = 60 * time.Second

// refreshEvery is the period, zero for never.
func (c *config) refreshEvery() time.Duration {
	if c.Refresh == "" {
		return defaultRefresh
	}
	d, _ := time.ParseDuration(c.Refresh) // checked by checkRefresh
	return d
}

// maxAge is how old the served data may be, zero for no limit.
func (c *config) maxAge() time.Duration {
	if c.MaxAge == "" {
		return 0
	}
	d, _ := time.ParseDuration(c.MaxAge)
	return d
}

func (c *config) checkRefresh() error {
	if c.Refresh != "" {
		d, err := time.ParseDuration(c.Refresh)
		if err != nil {
			return fmt.Errorf("refresh %q: %w (for example \"60s\", or \"0\" for never)", c.Refresh, err)
		}
		if d < 0 || (d > 0 && d < time.Second) {
			return fmt.Errorf("refresh %q: at least one second, or 0 for never", c.Refresh)
		}
	}
	if c.MaxAge != "" {
		d, err := time.ParseDuration(c.MaxAge)
		if err != nil {
			return fmt.Errorf("max_age %q: %w (for example \"10m\")", c.MaxAge, err)
		}
		if d <= 0 {
			return fmt.Errorf("max_age %q: more than zero; leave it out for no limit", c.MaxAge)
		}
		if r := c.refreshEvery(); r > 0 && d < r {
			return fmt.Errorf("max_age %q is shorter than refresh %q: the data would always be too old", c.MaxAge, r)
		}
	}
	return nil
}

// A snapshot is everybody and every group at one moment, and what is
// published from them. Never edited once it is stored.
type snapshot struct {
	people *roster
	groups *groupSnapshot
	// built is when the sources were last read successfully. A password write
	// keeps it: the file proves nothing about the databases.
	built time.Time

	once  sync.Once
	pub   publication
	lines []string
}

func newSnapshot(p *roster, g *groupSnapshot, built time.Time) *snapshot {
	return &snapshot{people: p, groups: g, built: built}
}

// publication is what a snapshot publishes, built once and kept.
func (s *server) publication(sn *snapshot) publication {
	sn.once.Do(func() {
		sn.pub = s.build(sn)
		sn.lines = leftOutLines(sn.pub)
	})
	return sn.pub
}

// leftOutLines says what is held back or changed, entry by entry: the lines
// startup prints, and that a refresh prints again only when they change.
func leftOutLines(p publication) []string {
	var out []string
	for _, e := range p.rejected() {
		out = append(out, fmt.Sprintf("%s is NOT published: it fails the schema: %s", e.DN, strings.Join(problems(e.invalid), "; ")))
	}
	for _, e := range p.all {
		if e.invalid != nil {
			continue
		}
		if e.noSID != "" {
			out = append(out, fmt.Sprintf("%s is published without sambaNTPassword: %s", e.DN, e.noSID))
		}
		out = append(out, leftOffLines(e, e.DN)...)
		for _, d := range e.dropped {
			out = append(out, fmt.Sprintf("%s is published without %s: %s", e.DN, d.name, d.why))
		}
	}
	return out
}

// checkConfigGroups holds the group blocks to these people: a group that names
// somebody who is not served is a configuration that does not hold together.
func (s *server) checkConfigGroups(people *roster) error {
	for _, g := range s.cfg.Groups {
		for _, m := range g.Members {
			if _, ok := people.byName[m]; !ok {
				return fmt.Errorf("group %q has %q in it, who is not in %s", g.Name, m, s.dir.Describe())
			}
		}
	}
	return nil
}

// read is a snapshot of the sources as they are now: what startup checks, a
// refresh checks again, and a refusal is a refusal.
func (s *server) read() (*snapshot, error) {
	ids, err := s.dir.Identities()
	if err != nil {
		return nil, err
	}
	people, err := newRoster(ids, s.local.p.Load().People...)
	if err != nil {
		return nil, err
	}
	groups, err := readGroups(s.dir, ids)
	if err != nil {
		return nil, err
	}
	if err := s.checkConfigGroups(people); err != nil {
		return nil, err
	}
	sn := newSnapshot(people, groups, s.now())
	s.publication(sn) // validated here, not by the first search
	return sn, nil
}

var errTooOld = errors.New("the directory data is older than max_age and the sources could not be read again")

// tooOld is the answer to give when max_age has run out, and whether to give it.
func (s *server) tooOld() (ldap.Result, bool) {
	max := s.cfg.maxAge()
	if max <= 0 || s.now().Sub(s.snap.Load().built) <= max {
		return ldap.Result{}, false
	}
	return ldap.Refuse(ldap.Unavailable, "%s", errTooOld), true
}

// startRefresh runs the loop, unless the configuration turned it off.
func (s *server) startRefresh() {
	every := s.cfg.refreshEvery()
	if every <= 0 || s.rctx == nil {
		return
	}
	tick, stop := s.ticker(every)
	s.rdone.Add(1)
	go func() {
		defer s.rdone.Done()
		defer stop()
		for {
			select {
			case <-s.rctx.Done():
				return
			case <-tick:
				s.refreshOnce(s.rctx, every)
			}
		}
	}()
}

// refreshOnce reads the sources again and swaps the result in. It never
// overlaps itself, and never waits longer than the period for a source: a
// source that is slow is a refresh that failed, and serving goes on.
func (s *server) refreshOnce(parent context.Context, every time.Duration) {
	if !s.refreshing.CompareAndSwap(false, true) {
		s.mu.Lock()
		first := !s.failing
		s.failing = true
		s.mu.Unlock()
		if first {
			fmt.Fprintf(s.out, "refresh skipped: the previous one is still running (a source is slow); serving the data read at %s\n",
				s.snap.Load().built.Format(time.RFC3339))
		}
		return
	}
	ctx, cancel := context.WithTimeout(parent, every)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer s.refreshing.Store(false)
		s.noteRefresh(s.refreshTry())
	}()
	select {
	case <-done:
	case <-ctx.Done():
		if parent.Err() == nil {
			s.noteRefresh(fmt.Errorf("it did not finish within %s: a source is slow", every))
		}
	}
}

// refreshTry is one read and one swap, again if a password write got in between.
func (s *server) refreshTry() error {
	for range 3 {
		gen := s.gen.Load()
		sn, err := s.read()
		if err != nil {
			return err
		}
		if s.beforeSwap != nil {
			s.beforeSwap()
		}
		s.swapMu.Lock()
		if s.gen.Load() != gen {
			// A password was written after the sources were read: this
			// snapshot holds the old one. Read again rather than merge.
			s.swapMu.Unlock()
			continue
		}
		before := s.snap.Load()
		s.snap.Store(sn)
		s.swapMu.Unlock()
		s.reportLeftOut(before, sn)
		return nil
	}
	return errors.New("the people kept changing under the refresh")
}

// reportLeftOut says what is held back, when the set of lines changed.
func (s *server) reportLeftOut(before, now *snapshot) {
	s.publication(before)
	a, b := strings.Join(before.lines, "\n"), strings.Join(now.lines, "\n")
	if a == b {
		return
	}
	if b == "" {
		fmt.Fprintln(s.out, "refresh: nothing is held back any more")
		return
	}
	fmt.Fprintf(s.out, "refresh: what is held back changed:\n%s\n", b)
}

// noteRefresh says a failure once per streak, and when it ends.
func (s *server) noteRefresh(err error) {
	s.mu.Lock()
	was := s.failing
	s.failing = err != nil
	s.mu.Unlock()
	switch {
	case err != nil && !was:
		fmt.Fprintf(s.out, "refresh failed, serving the data read at %s: %v\n", s.snap.Load().built.Format(time.RFC3339), err)
	case err == nil && was:
		fmt.Fprintln(s.out, "refresh works again")
	}
}
