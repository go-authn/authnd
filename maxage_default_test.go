// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"
	"time"

	"github.com/go-authn/ldap"
)

// Second-pass audit 2026-11. max_age defaulted to unlimited, so a person
// removed from a source that then became unreadable kept binding forever:
// revocation failed open. Unset, it is now finite (defaultMaxAge); "0" says
// "no limit" on purpose.
func TestAnUnreadableSourceStopsServingStaleDataByDefault(t *testing.T) {
	r, db, clk, _ := refreshing(t, ``)
	execDB(t, db, `alter table teams rename to teams_gone`)

	clk.Advance(time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if res, _ := client(t, r).Bind("uid=dora,ou=people,dc=example,dc=org", "hunter2"); res.Code != ldap.Success {
		t.Fatalf("refused after one minute of failures: %v", res.Code)
	}

	clk.Advance(48 * time.Hour)
	r.srv.refreshOnce(bg, time.Minute)
	if res, _ := client(t, r).Bind("uid=dora,ou=people,dc=example,dc=org", "hunter2"); res.Code != ldap.Unavailable {
		t.Fatalf("after two days with an unreadable source a person still binds on stale data: %v", res.Code)
	}
}

func TestMaxAgeZeroIsAnExplicitNoLimit(t *testing.T) {
	r, db, clk, _ := refreshing(t, `max_age = "0"`)
	execDB(t, db, `alter table teams rename to teams_gone`)
	clk.Advance(48 * time.Hour)
	r.srv.refreshOnce(bg, time.Minute)
	if res, _ := client(t, r).Bind("uid=dora,ou=people,dc=example,dc=org", "hunter2"); res.Code != ldap.Success {
		t.Fatalf("max_age = \"0\" refused stale data: %v", res.Code)
	}
}
