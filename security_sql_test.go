//go:build !nosql

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"testing"
)

// ⛔ The case collision across sources: a database row "Backup" beside the
// local service account "backup". The source set lets the first source own a
// name, and compares names as bytes, so both used to be served -- and the
// password change, comparing DNs, let either rewrite the other's password.
func TestNamesThatDifferOnlyByCaseAcrossSourcesAreOnePerson(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := sqliteWith(t, dir, `
create table staff (login text primary key, secret text);
insert into staff values ('Backup', 'another-secret');
`)
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "backup" { password = "service-secret" }
users "sql" {
  driver   = "sqlite"
  dsn_file = %q
  users    = "select login, secret from staff"
}
`, hclPath(dsn)))})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	out := &safeBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer srv.Close()
	// directory v0.26.0: the names are one person, the file's source owns it,
	// and the database row is not served -- and the operator is told.
	who := srv.who()
	if _, ok := who["Backup"]; ok || who["backup"] == nil {
		t.Fatalf(`"Backup" from the database was served beside the file's "backup": %v`, who)
	}
	contains(t, out.String(), `"Backup"`, `"backup"`, "shadowed")
}
