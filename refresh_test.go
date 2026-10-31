//go:build !nosql

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/ldap"
	"github.com/go-authn/ldap/ldaptest"
)

// The periodic refresh (refresh.go): a revocation in a database reaches the
// directory within one period, a refresh that fails changes nothing, and no
// search ever sees half of a snapshot.

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// refreshing is a server over the SQLite fixture, with a clock and a ticker
// the test owns.
func refreshing(t *testing.T, extra string) (r *running, db string, clk *fakeClock, tick chan time.Time) {
	t.Helper()
	dir := t.TempDir()
	clk = &fakeClock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	tick = make(chan time.Time)
	r = startWith(t, peopleConfig(t, dir, extra), func(s *server) {
		s.now = clk.Now
		s.ticker = func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} }
		old := s.snap.Load()
		s.snap.Store(newSnapshot(old.people, old.groups, clk.Now()))
	})
	return r, dir + "/people.db", clk, tick
}

func execDB(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func membersOf(t *testing.T, r *running, group string) []string {
	t.Helper()
	for _, e := range readerSearchAll(t, r).Entries {
		if e.DN == "cn="+group+",ou=groups,dc=example,dc=org" {
			m := values(e, "memberUid")
			slices.Sort(m)
			return m
		}
	}
	t.Fatalf("no group %s", group)
	return nil
}

func hasPerson(t *testing.T, r *running, uid string) bool {
	t.Helper()
	return slices.Contains(dnsOf(readerSearchAll(t, r)), "uid="+uid+",ou=people,dc=example,dc=org")
}

var bg = context.Background()

func TestRefreshRevokesAMemberAndAPerson(t *testing.T) {
	r, db, clk, _ := refreshing(t, "")
	if m := membersOf(t, r, "engineers"); !slices.Equal(m, []string{"dora", "eli"}) {
		t.Fatalf("members before: %v", m)
	}
	execDB(t, db, `delete from teams where member = 'eli'`)
	// Nothing changes before the refresh runs.
	if m := membersOf(t, r, "engineers"); len(m) != 2 {
		t.Fatalf("a search changed the answer: %v", m)
	}
	clk.Advance(time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if m := membersOf(t, r, "engineers"); !slices.Equal(m, []string{"dora"}) {
		t.Fatalf("eli is still in engineers: %v", m)
	}
	if !r.srv.snap.Load().built.Equal(clk.Now()) {
		t.Errorf("built %v, clock %v", r.srv.snap.Load().built, clk.Now())
	}

	execDB(t, db, `delete from staff where login = 'eli'`)
	if !hasPerson(t, r, "eli") {
		t.Fatal("eli went before the refresh")
	}
	r.srv.refreshOnce(bg, time.Minute)
	if hasPerson(t, r, "eli") {
		t.Fatal("eli is still published")
	}
	c := client(t, r)
	if res, _ := c.Bind("uid=eli,ou=people,dc=example,dc=org", "swordfish"); res.Code != ldap.InvalidCredentials {
		t.Fatalf("eli can still bind: %v", res.Code)
	}
	if res, _ := c.Bind("uid=dora,ou=people,dc=example,dc=org", "hunter2"); res.Code != ldap.Success {
		t.Fatalf("dora cannot bind: %v", res.Code)
	}
}

// The loop itself: a tick runs a refresh.
func TestRefreshLoopRunsOnTick(t *testing.T) {
	r, db, _, tick := refreshing(t, "")
	execDB(t, db, `delete from teams where member = 'eli'`)
	tick <- time.Now()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if m := membersOf(t, r, "engineers"); len(m) == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a tick did not refresh")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRefreshFailureKeepsTheLastGoodSnapshot(t *testing.T) {
	r, db, clk, _ := refreshing(t, "")
	built := r.srv.snap.Load().built
	execDB(t, db, `alter table teams rename to teams_gone`)
	for range 3 {
		clk.Advance(time.Minute)
		r.srv.refreshOnce(bg, time.Minute)
	}
	if m := membersOf(t, r, "engineers"); len(m) != 2 {
		t.Fatalf("a failed refresh changed the answer: %v", m)
	}
	if !r.srv.snap.Load().built.Equal(built) {
		t.Errorf("a failed refresh moved built to %v", r.srv.snap.Load().built)
	}
	out := r.out.String()
	if n := strings.Count(out, "refresh failed"); n != 1 || !strings.Contains(out, "a sqlite database") {
		t.Fatalf("%d failure lines, want one naming the source:\n%s", n, out)
	}
	execDB(t, db, `alter table teams_gone rename to teams`)
	clk.Advance(time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if !strings.Contains(r.out.String(), "refresh works again") || !r.srv.snap.Load().built.Equal(clk.Now()) {
		t.Fatalf("no recovery:\n%s", r.out.String())
	}
}

func TestMaxAgeRefusesStaleData(t *testing.T) {
	r, db, clk, _ := refreshing(t, `max_age = "5m"`)
	execDB(t, db, `alter table teams rename to teams_gone`)
	clk.Advance(4 * time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if len(readerSearchAll(t, r).Entries) == 0 {
		t.Fatal("refused before max_age")
	}
	clk.Advance(2 * time.Minute)
	r.srv.refreshOnce(bg, time.Minute)

	c := client(t, r)
	if res, _ := c.Bind("cn=reader,dc=example,dc=org", "let me read"); res.Code != ldap.Success {
		t.Fatalf("a reader (configuration) is refused: %v", res.Code)
	}
	got, err := c.Search(ldaptest.Search{Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=*)"})
	if err != nil || got.Result.Code != ldap.Unavailable || len(got.Entries) != 0 {
		t.Fatalf("search: %v %v with %d entries, want unavailable", err, got.Result.Code, len(got.Entries))
	}
	for _, base := range []string{"", "cn=Subschema"} {
		got, err := c.Search(ldaptest.Search{Base: base, Scope: ldap.ScopeBaseObject, Filter: "(objectClass=*)"})
		if err != nil || got.Result.Code != ldap.Success || len(got.Entries) != 1 {
			t.Errorf("base %q: %v %v %d", base, err, got.Result.Code, len(got.Entries))
		}
	}
	c2 := client(t, r)
	if res, _ := c2.Bind("uid=dora,ou=people,dc=example,dc=org", "hunter2"); res.Code != ldap.Unavailable {
		t.Fatalf("a person's bind on stale data: %v", res.Code)
	}
	if res, err := c.Extended(ldap.OIDPasswordModify, nil); err != nil || res.Code != ldap.Unavailable {
		t.Errorf("password modify on stale data: %v %v", res.Code, err)
	}
	// Recovered: fresh data again.
	execDB(t, db, `alter table teams_gone rename to teams`)
	r.srv.refreshOnce(bg, time.Minute)
	if res, _ := client(t, r).Bind("uid=dora,ou=people,dc=example,dc=org", "hunter2"); res.Code != ldap.Success {
		t.Fatalf("still refused after a good refresh: %v", res.Code)
	}
}

// ⛔ No search sees half of a snapshot: the database flips between two
// disjoint sets of people and groups, and every member a group names is a
// person published in the SAME answer.
func TestNoTornSnapshotUnderConcurrentSearches(t *testing.T) {
	dir := t.TempDir()
	dsn := sqliteWith(t, dir, `create table staff (login text primary key, secret text);
create table teams (team text, member text);
insert into staff values ('a1','x'),('a2','x');
insert into teams values ('g','a1'),('g','a2');`)
	body := fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
users "sql" {
  driver = "sqlite"
  dsn_file = %q
  users  = "select login, secret from staff"
  groups = "select team, member from teams"
}
`, hclPath(dsn))
	r := startWith(t, body, func(s *server) {
		s.ticker = func(time.Duration) (<-chan time.Time, func()) { return make(chan time.Time), func() {} }
	})
	db := dir + "/people.db"
	var stop atomic.Bool
	errs := make(chan string, 16)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := client(t, r)
			if res, _ := c.Bind("cn=reader,dc=example,dc=org", "let me read"); res.Code != ldap.Success {
				errs <- "bind"
				return
			}
			for !stop.Load() {
				got, err := c.Search(ldaptest.Search{Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=*)"})
				if err != nil || got.Result.Code != ldap.Success {
					errs <- fmt.Sprint("search ", err, got.Result.Code)
					return
				}
				have := map[string]bool{}
				for _, e := range got.Entries {
					have[e.DN] = true
				}
				for _, e := range got.Entries {
					for _, m := range values(e, "member") {
						if !have[m] {
							errs <- fmt.Sprintf("%s names %s, who is not in the same answer", e.DN, m)
							return
						}
					}
				}
			}
		}()
	}
	for i := range 40 {
		p := "a"
		if i%2 == 0 {
			p = "b"
		}
		execDB(t, db, `delete from staff; delete from teams;`,
			fmt.Sprintf(`insert into staff values ('%s1','x'),('%s2','x')`, p, p),
			fmt.Sprintf(`insert into teams values ('g','%s1'),('g','%s2')`, p, p))
		r.srv.refreshOnce(bg, time.Minute)
	}
	stop.Store(true)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// ⛔ A password written while a refresh is between reading the sources and
// swapping is not lost: the refresh read the old one, so it reads again.
func TestPasswordWriteDuringRefreshIsNotLost(t *testing.T) {
	r, _, _, _ := refreshing(t, "")
	calls := 0
	r.srv.beforeSwap = func() {
		calls++
		if calls == 1 {
			if res, ok := r.srv.writePassword("svc", "rotated"); !ok {
				t.Errorf("the write: %v", res)
			}
		}
	}
	built := r.srv.snap.Load().built
	r.srv.refreshOnce(bg, time.Minute)
	if calls != 2 {
		t.Fatalf("the refresh read %d times, want 2 (once stale, once after the write)", calls)
	}
	svc := r.srv.who()["svc"]
	if svc.Verify("rotated") != nil || svc.Verify("service") == nil {
		t.Fatal("the refresh swapped the old password back in")
	}
	_ = built

	// A write that never lets the refresh settle: it gives up, says so, keeps
	// the password, and the next period tries again.
	n := 0
	r.srv.beforeSwap = func() {
		n++
		if res, ok := r.srv.writePassword("svc", fmt.Sprintf("again-%d", n)); !ok {
			t.Errorf("the write: %v", res)
		}
	}
	r.srv.refreshOnce(bg, time.Minute)
	if !strings.Contains(r.out.String(), "kept changing") {
		t.Fatalf("no failure said:\n%s", r.out.String())
	}
	if r.srv.who()["svc"].Verify(fmt.Sprintf("again-%d", n)) != nil {
		t.Fatal("the last written password is not the one served")
	}
	r.srv.beforeSwap = nil
}

// A password write keeps the age of the data: it says nothing about the databases.
func TestPasswordWriteKeepsBuilt(t *testing.T) {
	r, _, clk, _ := refreshing(t, "")
	built := r.srv.snap.Load().built
	clk.Advance(time.Hour)
	if res, ok := r.srv.writePassword("svc", "rotated"); !ok {
		t.Fatal(res)
	}
	if !r.srv.snap.Load().built.Equal(built) {
		t.Fatal("a password write made the data look fresh")
	}
}

func TestRefreshNeverOverlapsAndSaysSoOnce(t *testing.T) {
	r, _, _, _ := refreshing(t, "")
	r.srv.refreshing.Store(true)
	r.srv.refreshOnce(bg, time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if n := strings.Count(r.out.String(), "refresh skipped"); n != 1 {
		t.Fatalf("%d skip lines, want 1:\n%s", n, r.out.String())
	}
	r.srv.refreshing.Store(false)
}

// A slow source: the refresh gives up after its period, serving goes on, and
// the late answer is taken when it comes.
type slowSource struct{ release chan struct{} }

func (slowSource) Describe() string { return "a slow source" }
func (s slowSource) Identities() ([]*directory.Identity, error) {
	<-s.release
	return nil, nil
}
func (slowSource) Members(string) ([]string, error) { return nil, directory.ErrNoSuchGroup }

func TestSlowSourceCannotBlockServing(t *testing.T) {
	r, _, _, _ := refreshing(t, "")
	slow := slowSource{release: make(chan struct{})}
	r.srv.dir.Add(slow)
	start := time.Now()
	r.srv.refreshOnce(bg, 100*time.Millisecond)
	if time.Since(start) > 3*time.Second {
		t.Fatal("the refresh waited for the slow source")
	}
	if !strings.Contains(r.out.String(), "did not finish within") {
		t.Fatalf("no timeout said:\n%s", r.out.String())
	}
	if len(readerSearchAll(t, r).Entries) == 0 {
		t.Fatal("serving stopped while a source was slow")
	}
	close(slow.release)
	deadline := time.Now().Add(5 * time.Second)
	for r.srv.refreshing.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the late refresh never ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(r.out.String(), "refresh works again") {
		t.Fatalf("the late answer was not taken:\n%s", r.out.String())
	}
}

// refresh = "0" is v0.13.4: nothing runs. The default asks for 60 s.
func TestRefreshOffAndDefault(t *testing.T) {
	for _, tc := range []struct {
		extra string
		want  []time.Duration
	}{{`refresh = "0"`, nil}, {"", []time.Duration{60 * time.Second}}, {`refresh = "2m"`, []time.Duration{2 * time.Minute}}} {
		asked := make(chan time.Duration, 4)
		startWith(t, peopleConfig(t, t.TempDir(), tc.extra), func(s *server) {
			s.ticker = func(d time.Duration) (<-chan time.Time, func()) {
				asked <- d
				return make(chan time.Time), func() {}
			}
		})
		var got []time.Duration
		select {
		case d := <-asked:
			got = append(got, d)
		case <-time.After(300 * time.Millisecond):
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: ticker asked for %v, want %v", tc.extra, got, tc.want)
		}
	}
}

// What is held back is said when the set changes, not every period.
func TestRefreshSaysWhatIsHeldBackOnlyWhenItChanges(t *testing.T) {
	dir := t.TempDir()
	dsn := sqliteWith(t, dir, `create table staff (login text primary key, secret text, sn text);
insert into staff values ('dora','x','Dupont');`)
	r := startWith(t, fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
users "sql" {
  driver = "sqlite"
  dsn_file = %q
  users  = "select login, secret from staff"
  users_attributes = "select login, sn from staff"
}
`, hclPath(dsn)), nil)
	db := dir + "/people.db"
	said := func() int { return strings.Count(r.out.String(), "refresh: what is held back changed") }
	r.srv.refreshOnce(bg, time.Minute)
	if said() != 0 {
		t.Fatalf("a refresh that changed nothing said something:\n%s", r.out.String())
	}
	execDB(t, db, fmt.Sprintf(`insert into staff values ('big','x','%s')`, strings.Repeat("x", 4<<20)))
	r.srv.refreshOnce(bg, time.Minute)
	r.srv.refreshOnce(bg, time.Minute)
	if said() != 1 || !strings.Contains(r.out.String(), "uid=big,ou=people") {
		t.Fatalf("said %d times:\n%s", said(), r.out.String())
	}
	execDB(t, db, `delete from staff where login = 'big'`)
	r.srv.refreshOnce(bg, time.Minute)
	if !strings.Contains(r.out.String(), "refresh: nothing is held back any more") {
		t.Fatalf("no all-clear:\n%s", r.out.String())
	}
}

// Each way reading the sources can fail is a refresh that failed.
func TestReadFailsWhenASourceDoes(t *testing.T) {
	r, _, _, _ := refreshing(t, "")
	good := r.srv.snap.Load()
	// Two people whose names differ only by case.
	r.srv.dir.Add(&directory.Static{Name: "a clash", People: []*directory.Identity{directory.NewIdentity("DORA")}})
	if _, err := r.srv.read(); err == nil || !strings.Contains(err.Error(), "differ only by case") {
		t.Fatalf("a name clash: %v", err)
	}
	// A source that cannot list its groups.
	r2, _, _, _ := refreshing(t, "")
	r2.srv.dir.Add(brokenSource{"names"})
	if _, err := r2.srv.read(); err == nil || !strings.Contains(err.Error(), "listing the groups") {
		t.Fatalf("a groups listing: %v", err)
	}
	// A source that cannot list its people.
	r3, _, _, _ := refreshing(t, "")
	r3.srv.dir.Add(peopleBroken{})
	if _, err := r3.srv.read(); err == nil {
		t.Fatal("a people listing failed silently")
	}
	if r.srv.snap.Load() != good {
		t.Fatal("a failed read replaced the snapshot")
	}
}

type peopleBroken struct{}

func (peopleBroken) Describe() string                           { return "broken people" }
func (peopleBroken) Identities() ([]*directory.Identity, error) { return nil, errBroken }
func (peopleBroken) Members(string) ([]string, error)           { return nil, directory.ErrNoSuchGroup }

// A refresh that would refuse startup refuses: a group block naming somebody
// the sources no longer serve.
func TestRefreshRefusesWhatStartupWouldRefuse(t *testing.T) {
	r, db, _, _ := refreshing(t, `group "ops" { members = ["dora"] }`)
	execDB(t, db, `delete from staff where login = 'dora'`)
	r.srv.refreshOnce(bg, time.Minute)
	if !strings.Contains(r.out.String(), `group "ops" has "dora"`) {
		t.Fatalf("not refused:\n%s", r.out.String())
	}
	if !hasPerson(t, r, "dora") {
		t.Fatal("the refused refresh changed the answer")
	}
}
