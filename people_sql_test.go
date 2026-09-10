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
	dsn := sqliteWith(t, dir, `
create table staff (login text primary key, secret text, nt_hash text);
insert into staff values ('dora', 'hunter2', null), ('eli', 'swordfish', null);
create table teams (team text, member text);
insert into teams values ('engineers', 'dora'), ('engineers', 'eli');
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
