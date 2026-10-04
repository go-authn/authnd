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
func TestNamesThatDifferOnlyByCaseAcrossSourcesAreRefused(t *testing.T) {
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
	srv, err := open(cfg, &safeBuffer{})
	if err == nil {
		srv.Close()
		t.Fatal(`"Backup" from the database and "backup" from the file were both served`)
	}
	contains(t, err.Error(), `"backup"`, `"Backup"`, "case")
}
