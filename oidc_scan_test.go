// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/ldap"
)

// Security audit 2026-11-21 suspicion: for a name the roster does not hold by
// its exact bytes, BindSASL scans the whole roster (oidc.go, the
// EqualASCIIFold fallback), so a roster of 10,000 people would cost every such
// bind 10,000 comparisons -- and, the audit feared, allocations.
//
// Measured, not argued: the allocations of one whole bind (client and server
// in one process) with a roster of 10 and one of 10,000, for a name that is
// not in either (the full scan). The scan allocates nothing, so the two must
// be equal; a scan that allocated per person would differ by thousands.
func TestTheFoldScanAllocatesNothingPerPerson(t *testing.T) {
	p := newProvider(t)
	r := oidcServer(t, p, "", "")
	const runs = 20
	toks := make([]string, 0, 2*(runs+1))
	for i := 0; i < cap(toks); i++ {
		toks = append(toks, p.token(t, map[string]any{"preferred_username": "nobody@univ-a.example", "jti": fmt.Sprint("t", i)}))
	}
	setRoster := func(n int) {
		ids := make([]*directory.Identity, 0, n)
		for i := 0; i < n; i++ {
			ids = append(ids, directory.NewIdentity(fmt.Sprintf("user%05d", i)))
		}
		ro, err := newRoster(ids)
		if err != nil {
			t.Fatal(err)
		}
		old := r.srv.snap.Load()
		r.srv.snap.Store(newSnapshot(ro, old.groups, old.built))
	}
	measure := func(n int, from int) float64 {
		setRoster(n)
		i := from
		return testing.AllocsPerRun(runs, func() {
			if code, _ := bindWithToken(t, r, "", toks[i]); code == ldap.Success {
				t.Error("a token for nobody bound")
			}
			i++
		})
	}
	small := measure(10, 0)
	large := measure(10000, runs+1)
	t.Logf("allocations per bind: roster of 10 = %.0f, roster of 10000 = %.0f", small, large)
	// A few allocations of slack: log lines, scheduling. A per-person
	// allocation would be thousands.
	if large-small > 50 {
		t.Errorf("a roster of 10000 costs %.0f more allocations per bind than one of 10", large-small)
	}
}
