//go:build !nosql

package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

// The people several tests share, out of a real database.
//
// There is a second version of this next door for `-tags nosql`, writing the
// same people as `user` blocks. What those tests measure is the SERVER --
// binds, searches, refusals -- and it must behave the same however the people
// arrived; a build that leaves out the database should not leave out the tests.
func peopleConfig(t *testing.T, dir string, extra string) string {
	t.Helper()
	// dora has what a posixAccount needs and eli has nothing beyond a
	// password, so the two standard shapes are both here: dora is an
	// account with posixAccount, eli an account without it. engineers has a
	// gidNumber, so it is a posixGroup with memberUid.
	dsn := sqliteWith(t, dir, `
create table staff (login text primary key, secret text, nt_hash text);
insert into staff values ('dora', 'hunter2', null), ('eli', 'swordfish', null);
create table posix (login text primary key, uid integer, gid integer, home text);
insert into posix values ('dora', 1000, 1000, '/home/dora');
create table teams (team text, member text);
insert into teams values ('engineers', 'dora'), ('engineers', 'eli');
create table team_ids (team text primary key, gid integer);
insert into team_ids values ('engineers', 2000);
`)
	return fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

reader "cn=reader,dc=example,dc=org" { password = "let me read" }

user "svc" { password = "service" }

users "sql" {
  driver   = "sqlite"
  dsn_file = %q
  users    = "select login, secret from staff"
  groups   = "select team, member from teams"
  users_attributes  = "select login, cast(uid as text) as uidNumber, cast(gid as text) as gidNumber, home as homeDirectory from posix"
  groups_attributes = "select team, cast(gid as text) as gidNumber from team_ids"
}
%s`, hclPath(dsn), extra)
}

// peopleFrom is what `check` says about where dora came from in this build.
const peopleFrom = "a sqlite database"

// sqliteWith writes a database and returns the file naming its DSN.
func sqliteWith(t *testing.T, dir, schema string) string {
	t.Helper()
	path := filepath.Join(dir, "people.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return write(t, dir, "dsn", path+"\n")
}
