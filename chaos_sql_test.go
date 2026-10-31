//go:build !nosql

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-authn/ldap"
	"github.com/go-authn/ldap/ldaptest"
)

// Chaos: the database under a running server.
//
// ⛔ The principle: authnd never publishes a half-updated directory silently.
// It reads its sources ONCE, at startup (server.go, the note on `people`); a
// source it cannot read then refuses startup, and a source that breaks after
// that cannot change an answer, because no search asks it anything. Groups
// used to be the exception: every search re-ran the groups queries (several
// full scans per group) and left a group out, answering Success, when a query
// failed -- people from the startup snapshot, groups from "now", the broken
// half silently missing.

func dsnPath(t *testing.T, dsnFile string) string {
	t.Helper()
	b, err := os.ReadFile(dsnFile)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func readerSearchAll(t *testing.T, r *running) ldaptest.SearchResult {
	t.Helper()
	c := client(t, r)
	if res, err := c.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil || res.Code != ldap.Success {
		t.Fatalf("reader bind: %v %v", res.Code, err)
	}
	got, err := c.Search(ldaptest.Search{Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=*)"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	return got
}

func dnsOf(got ldaptest.SearchResult) []string {
	var out []string
	for _, e := range got.Entries {
		out = append(out, e.DN)
	}
	return out
}

func peopleServer(t *testing.T) (*running, string) {
	t.Helper()
	dir := t.TempDir()
	body := peopleConfig(t, dir, "")
	r := start(t, body)
	return r, filepath.Join(dir, "people.db")
}

// The groups survive the database: dropping the table behind them changes
// nothing a client sees, and what a client sees is never a Success with the
// groups missing.
func TestChaosGroupsTableDroppedMidRun(t *testing.T) {
	r, db := peopleServer(t)
	before := readerSearchAll(t, r)
	if !strings.Contains(strings.Join(dnsOf(before), "\n"), "cn=engineers,ou=groups") {
		t.Fatalf("the baseline has no group: %v", dnsOf(before))
	}
	other, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Exec(`drop table teams; drop table team_ids;`); err != nil {
		t.Fatal(err)
	}
	after := readerSearchAll(t, r)
	if after.Result.Code == ldap.Success && len(after.Entries) != len(before.Entries) {
		t.Fatalf("Success with %d entries where there were %d: a half-updated directory, silently\n before: %v\n after:  %v",
			len(after.Entries), len(before.Entries), dnsOf(before), dnsOf(after))
	}
}

// The file removed from under the server: the open handle keeps answering on
// Unix, and nothing a search reads changes.
func TestChaosDatabaseFileRemovedMidRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not remove a file somebody holds open")
	}
	r, db := peopleServer(t)
	before := readerSearchAll(t, r)
	if err := os.Remove(db); err != nil {
		t.Fatal(err)
	}
	after := readerSearchAll(t, r)
	if after.Result.Code == ldap.Success && len(after.Entries) != len(before.Entries) {
		t.Fatalf("Success with %d entries where there were %d", len(after.Entries), len(before.Entries))
	}
}

// A groups query that does not run refuses startup, like a people query that
// does not, instead of starting with no groups and a line in a journal.
func TestChaosBrokenGroupsQueryRefusesStartup(t *testing.T) {
	dir := t.TempDir()
	dsn := sqliteWith(t, dir, `create table staff (login text primary key, secret text);
insert into staff values ('dora', 'hunter2');`)
	_, err := openBody(t, fmt.Sprintf(`
base_dn = "dc=example,dc=org"
users "sql" {
  driver = "sqlite"
  dsn_file = %q
  users  = "select login, secret from staff"
  groups = "select team, member from no_such_table"
}
`, hclPath(dsn)))
	if err == nil {
		t.Fatal("startup accepted a groups query that fails")
	}
	if !strings.Contains(err.Error(), "group") {
		t.Fatalf("the refusal does not say it is about groups: %v", err)
	}
}

// A database file that is not a database refuses startup.
func TestChaosCorruptedDatabaseRefusesStartup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "people.db")
	if err := os.WriteFile(path, []byte(strings.Repeat("this is not a sqlite file\n", 400)), 0o600); err != nil {
		t.Fatal(err)
	}
	dsn := write(t, dir, "dsn", path+"\n")
	_, err := openBody(t, fmt.Sprintf(`
base_dn = "dc=example,dc=org"
users "sql" {
  driver = "sqlite"
  dsn_file = %q
  users = "select login, secret from staff"
}
`, hclPath(dsn)))
	if err == nil {
		t.Fatal("startup accepted a corrupted database")
	}
}

// Rows a database should not hold: a NULL name, a duplicate login, bytes that
// are not UTF-8, a 10 MB value. The server refuses at startup, or publishes
// something that passes the schema; it never serves a value the schema it
// publishes forbids, and it stays up.
func TestChaosHostileRows(t *testing.T) {
	huge := strings.Repeat("x", 10<<20)
	for _, c := range []struct {
		name, sql string
		args      []any
		refuses   bool
	}{
		{"NULL name", `insert into staff values (null, 'pw', null)`, nil, true},
		{"duplicate login", `insert into staff values ('dora', 'other', null)`, nil, false},
		{"invalid UTF-8 in sn", `insert into staff values ('inva', 'pw', cast(x'66ff6f' as text))`, nil, false},
		{"10 MB sn", `insert into staff values ('big', 'pw', ?)`, []any{huge}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			dsn := sqliteWith(t, dir, `create table staff (login text, secret text, sn text);
insert into staff values ('dora', 'hunter2', 'Dupont');`)
			db, err := sql.Open("sqlite", dsnPath(t, dsn))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(c.sql, c.args...); err != nil {
				t.Fatal(err)
			}
			db.Close()
			body := fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
users "sql" {
  driver = "sqlite"
  dsn_file = %q
  users  = "select login, secret from staff"
  users_attributes = "select login, sn from staff"
}
`, hclPath(dsn))
			cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
			if err != nil {
				t.Fatal(err)
			}
			srv, err := open(cfg, &safeBuffer{})
			if err != nil {
				if !c.refuses {
					t.Logf("refused at startup: %v", err)
				}
				return
			}
			defer srv.Close()
			if c.refuses {
				t.Fatal("startup accepted the row")
			}
			for _, e := range srv.publish().valid() {
				if err := e.Validate(srv.schema); err != nil {
					t.Errorf("%s is published and fails the schema it is published under: %v", e.DN, err)
				}
				for _, a := range e.Attributes {
					for _, v := range a.Values {
						if a.Name == "sn" && !isUTF8(string(v)) {
							t.Errorf("%s: sn is served with bytes that are not UTF-8", e.DN)
						}
					}
				}
			}
		})
	}
}

func isUTF8(s string) bool { return strings.ToValidUTF8(s, "�") == s }

// A 10 MB value over the wire: the server answers (or refuses) and stays up.
func TestChaosHugeValueOverTheWire(t *testing.T) {
	dir := t.TempDir()
	dsn := sqliteWith(t, dir, `create table staff (login text, secret text, sn text);
insert into staff values ('dora', 'hunter2', 'Dupont');`)
	db, err := sql.Open("sqlite", dsnPath(t, dsn))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`insert into staff values ('big', 'pw', ?)`, strings.Repeat("x", 10<<20)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	r := start(t, fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
users "sql" {
  driver = "sqlite"
  dsn_file = %q
  users = "select login, secret from staff"
  users_attributes = "select login, sn from staff"
}
`, hclPath(dsn)))
	c := client(t, r)
	if res, err := c.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil || res.Code != ldap.Success {
		t.Fatal(res.Code, err)
	}
	got, err := c.Search(ldaptest.Search{Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=*)"})
	t.Logf("err=%v code=%v entries=%d", err, got.Result.Code, len(got.Entries))
	for _, e := range got.Entries {
		for _, a := range e.Attributes {
			for _, v := range a.Values {
				if len(v) > 4<<20 {
					t.Errorf("%s: %s carries %d bytes, more than the %d a message may hold", e.DN, a.Name, len(v), ldap.DefaultMaxMessageSize)
				}
			}
		}
	}
	c2 := client(t, r)
	if res, err := c2.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil || res.Code != ldap.Success {
		t.Fatalf("the server did not survive: %v %v", res.Code, err)
	}
}
