//go:build !nosql

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/go-authn/ldap"
	"github.com/go-authn/ldap/ldaptest"
)

// BenchmarkSearchWithGroups is one reader search over a SQLite directory of
// 500 people and 200 groups of 50. Before v0.13.4 every search ran the groups
// queries again, several full scans per group.
func BenchmarkSearchWithGroups(b *testing.B) {
	r := benchFixture(b)
	benchSearch(b, r)
}

// BenchmarkRefresh is one refresh of the same directory: reading 500 people
// and 200 groups of 50 into a snapshot, validating and publishing it.
func BenchmarkRefresh(b *testing.B) {
	r := benchFixture(b)
	b.ResetTimer()
	for range b.N {
		if _, err := r.srv.read(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSearchDuringRefresh is BenchmarkSearchWithGroups with refreshes
// running back to back beside it: the cost a search pays for a refresh in
// flight.
func BenchmarkSearchDuringRefresh(b *testing.B) {
	r := benchFixture(b)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				r.srv.refreshOnce(context.Background(), time.Minute)
			}
		}
	}()
	benchSearch(b, r)
	close(stop)
	<-done
}

func benchSearch(b *testing.B, r *running) {
	c, err := ldaptest.Dial(r.addr, 5*time.Second)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	if res, err := c.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil || res.Code != ldap.Success {
		b.Fatal(res.Code, err)
	}
	b.ResetTimer()
	for range b.N {
		got, err := c.Search(ldaptest.Search{Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree, Filter: "(cn=g0199)"})
		if err != nil || len(got.Entries) != 1 {
			b.Fatalf("%v %d", err, len(got.Entries))
		}
	}
}

func benchFixture(b *testing.B) *running { return benchFixtureOf(b, 500, 200, 50) }

// BenchmarkRefresh10k2k is a refresh of 10,000 people and 2,000 groups of 50
// (100,000 membership rows): a site ten times the size, which the per-group
// reading could not do inside the default period.
func BenchmarkRefresh10k2k(b *testing.B) {
	r := benchFixtureOf(b, 10000, 2000, 50)
	b.ResetTimer()
	for range b.N {
		if _, err := r.srv.read(); err != nil {
			b.Fatal(err)
		}
	}
}

func benchFixtureOf(b *testing.B, people, groups, per int) *running {
	dir := b.TempDir()
	dsn := write(b, dir, "dsn", dir+"/people.db\n")
	db, err := sql.Open("sqlite", dir+"/people.db")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec(`create table staff (login text primary key, secret text);
create table teams (team text, member text);`); err != nil {
		b.Fatal(err)
	}
	tx, _ := db.Begin()
	for p := 0; p < people; p++ {
		tx.Exec(`insert into staff values (?, 'pw')`, fmt.Sprintf("p%05d", p))
	}
	for g := 0; g < groups; g++ {
		for m := 0; m < per; m++ {
			tx.Exec(`insert into teams values (?, ?)`, fmt.Sprintf("g%04d", g), fmt.Sprintf("p%05d", (g*7+m)%people))
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	db.Close()
	r := start(b, fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
users "sql" {
  driver = "sqlite"
  dsn_file = %q
  users  = "select login, secret from staff"
  groups = "select team, member from teams"
}
`, hclPath(dsn)))
	return r
}
