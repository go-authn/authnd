//go:build !nosql

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
)

// Chaos: the PostgreSQL source of `users "sql"` (#73). The SQLite chaos tests
// (chaos_sql_test.go) cannot lose a connection; a server on the other end of a
// socket can, and the pgx driver, not authnd, decides how that looks.
//
// Every test carries a witness that pgx really talked to something: the
// server's own log (log_statement=all records the people query) or the
// proxy's byte counters. Without it a green run could be a config that never
// reached the database.

const peopleQuery = "select login, secret from staff"

func failures(r *running) int { return strings.Count(r.out.String(), "refresh failed") }

func refreshN(r *running, clk *fakeClock, n int) {
	for range n {
		clk.Advance(time.Minute)
		r.srv.refreshOnce(bg, time.Minute)
	}
}

func wantMembers(t *testing.T, r *running, want ...string) {
	t.Helper()
	if m := membersOf(t, r, "engineers"); !slices.Equal(m, want) {
		t.Fatalf("engineers = %v, want %v", m, want)
	}
}

// 1. The server dies during a refresh.
func TestPGChaosServerStoppedDuringRefresh(t *testing.T) {
	pg := startPG(t)
	pg.exec(pgSchema)
	r, clk := pgRefreshing(t, pgConfig(t, pg.dsn(pg.addr()), ""))

	// Witness: startup read the people from the real server.
	if n := strings.Count(pg.log(), peopleQuery); n == 0 {
		t.Fatalf("the server never saw the people query: pgx did not reach it\n%s", pg.log())
	}
	wantMembers(t, r, "dora", "eli")
	built := r.srv.snap.Load().built

	pg.Stop()
	// Control: the source really cannot be read now.
	if _, err := r.srv.dir.Identities(); err == nil {
		t.Fatal("the source still reads after pg_ctl stop -m immediate: the test proves nothing")
	}
	refreshN(r, clk, 3)

	wantMembers(t, r, "dora", "eli")
	if !r.srv.snap.Load().built.Equal(built) {
		t.Errorf("a failed refresh moved built to %v", r.srv.snap.Load().built)
	}
	out := r.out.String()
	if n := failures(r); n != 1 || !strings.Contains(out, "a pgx database") {
		t.Fatalf("%d failure lines, want one naming the source:\n%s", n, out)
	}

	// The server comes back with a member gone: the next refresh sees it.
	seen := strings.Count(pg.log(), peopleQuery)
	pg.Restart()
	pg.exec(`delete from teams where member = 'eli'`)
	clk.Advance(time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if !strings.Contains(r.out.String(), "refresh works again") {
		t.Fatalf("no recovery line:\n%s", r.out.String())
	}
	wantMembers(t, r, "dora")
	if !r.srv.snap.Load().built.Equal(clk.Now()) {
		t.Errorf("built %v after recovery, clock %v", r.srv.snap.Load().built, clk.Now())
	}
	if strings.Count(pg.log(), peopleQuery) <= seen {
		t.Error("the restarted server never saw the people query")
	}
}

// 2. A connection reset in the middle of a query, through a proxy.
func TestPGChaosConnectionResetMidQuery(t *testing.T) {
	pg := startPG(t)
	pg.exec(pgSchema)
	proxy := newFlaky(t, pg.addr())
	r, clk := pgRefreshing(t, pgConfig(t, pg.dsn(proxy.addr()), ""))

	// Witness: pgx spoke and the server answered, through the proxy.
	if proxy.up.Load() == 0 || proxy.down.Load() == 0 {
		t.Fatalf("the proxy saw up=%d down=%d bytes: startup did not go through it", proxy.up.Load(), proxy.down.Load())
	}
	wantMembers(t, r, "dora", "eli")
	built := r.srv.snap.Load().built

	// From now on the first thing a connection says is the end of it. The
	// pool holds a connection from startup: the refresh's query is sent on it
	// and the answer never comes.
	reset := func([]byte) bool { return false }
	proxy.onUp.Store(&reset)
	accepted := proxy.accepted.Load()
	clk.Advance(time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if proxy.killed.Load() == 0 {
		t.Fatal("no connection was reset: the refresh did not go through the proxy")
	}
	if got := proxy.accepted.Load(); got != accepted {
		t.Errorf("pgx opened %d new connection(s) before failing: the reset hit a handshake, not a query in flight", got-accepted)
	}
	refreshN(r, clk, 2)

	wantMembers(t, r, "dora", "eli")
	if !r.srv.snap.Load().built.Equal(built) {
		t.Errorf("a failed refresh moved built to %v", r.srv.snap.Load().built)
	}
	if n := failures(r); n != 1 || !strings.Contains(r.out.String(), "a pgx database") {
		t.Fatalf("%d failure lines, want one naming the source:\n%s", n, r.out.String())
	}

	// The network heals; the database changed meanwhile.
	proxy.onUp.Store(nil)
	pg.exec(`delete from teams where member = 'eli'`)
	clk.Advance(time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if !strings.Contains(r.out.String(), "refresh works again") {
		t.Fatalf("no recovery line:\n%s", r.out.String())
	}
	wantMembers(t, r, "dora")
}

// 3. startup_timeout against a listener that accepts and never answers.
func TestPGChaosStartupAgainstASilentListener(t *testing.T) {
	// No server binaries needed: the listener is the whole fixture.
	silent := newFlaky(t, "")
	silent.mode.Store(hang)
	dsn := fmt.Sprintf("host=%s port=%s user=postgres dbname=postgres sslmode=disable",
		"127.0.0.1", silent.addr()[strings.LastIndex(silent.addr(), ":")+1:])
	body := pgConfig(t, dsn, `startup_timeout = "800ms"`)
	cfg, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	_, err = open(cfg, &safeBuffer{})
	took := time.Since(begin)
	if err == nil {
		t.Fatal("open succeeded against a listener that never answers")
	}
	if took > 5*time.Second {
		t.Errorf("open took %s with startup_timeout 800ms", took)
	}
	// Witness: pgx connected and spoke; a refusal for another reason would be
	// a different test.
	if silent.accepted.Load() == 0 || silent.up.Load() == 0 {
		t.Fatalf("the listener saw %d connections and %d bytes: pgx never reached it (%v)", silent.accepted.Load(), silent.up.Load(), err)
	}
	for _, want := range []string{"startup_timeout", "opening", "sql pgx"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
}

// 4. The realm during a PostgreSQL outage: answered from the snapshot until
// max_age, then KDC_ERR_SVC_UNAVAILABLE.
func TestPGChaosKerberosDuringAnOutage(t *testing.T) {
	pg := startPG(t)
	pg.exec(pgSchema)
	r, clk := pgRefreshing(t, pgConfig(t, pg.dsn(pg.addr()), fmt.Sprintf(`refresh = "1m"
max_age = "5m"
kerberos {
  realm  = %q
  listen = "127.0.0.1:0"
  keytab = %q
}
`, testRealm, hclPath(writeKeytab(t, t.TempDir())))))

	if strings.Count(pg.log(), peopleQuery) == 0 {
		t.Fatal("the server never saw the people query: pgx did not reach it")
	}
	if got := asReqCode(t, r, "dora"); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Fatalf("before the outage: code %d, want PREAUTH_REQUIRED (25)", got)
	}
	pg.Stop()
	if _, err := r.srv.dir.Identities(); err == nil {
		t.Fatal("the source still reads after the server was stopped: the test proves nothing")
	}

	clk.Advance(2 * time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if failures(r) != 1 {
		t.Fatalf("the refresh did not fail:\n%s", r.out.String())
	}
	if got := asReqCode(t, r, "dora"); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Errorf("outage, within max_age: code %d, want PREAUTH_REQUIRED (25) from the snapshot", got)
	}
	if got := asReqCode(t, r, "nobody"); got != errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN {
		t.Errorf("a name nobody has: code %d, want C_PRINCIPAL_UNKNOWN (6)", got)
	}

	clk.Advance(10 * time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if got := asReqCode(t, r, "dora"); got != errorcode.KDC_ERR_SVC_UNAVAILABLE {
		t.Errorf("outage past max_age: code %d, want SVC_UNAVAILABLE (29)", got)
	}

	pg.Restart()
	clk.Advance(time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if got := asReqCode(t, r, "dora"); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Errorf("after recovery: code %d, want PREAUTH_REQUIRED (25)", got)
	}
}
