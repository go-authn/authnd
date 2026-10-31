//go:build !nosql

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
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
	for p := 0; p < 500; p++ {
		tx.Exec(`insert into staff values (?, 'pw')`, fmt.Sprintf("p%03d", p))
	}
	for g := 0; g < 200; g++ {
		for m := 0; m < 50; m++ {
			tx.Exec(`insert into teams values (?, ?)`, fmt.Sprintf("g%03d", g), fmt.Sprintf("p%03d", (g*7+m)%500))
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
		got, err := c.Search(ldaptest.Search{Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree, Filter: "(cn=g199)"})
		if err != nil || len(got.Entries) != 1 {
			b.Fatalf("%v %d", err, len(got.Entries))
		}
	}
}
