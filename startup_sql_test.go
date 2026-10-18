//go:build !nosql

package main

import (
	"fmt"
	"strings"
	"testing"
)

// ⛔ The startup line names the sources somebody is served FROM. The set
// always holds the configuration file -- a password change is written there --
// so with no user block at all the line read "serving 5 people from the
// configuration file, then a sqlite database": a file that served nobody.
func TestTheStartupLineNamesOnlySourcesThatServeSomebody(t *testing.T) {
	for _, c := range []struct {
		name, users, want string
	}{
		{"no user block", "", "serving 2 people from a sqlite database\n"},
		{"a user block too", `user "svc" { password = "service" }`, "serving 3 people from the configuration file, then a sqlite database\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			dsn := sqliteWith(t, dir, `
create table staff (login text primary key, secret text);
insert into staff values ('dora', 'hunter2'), ('eli', 'swordfish');
`)
			r := start(t, fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
%s
users "sql" {
  driver   = "sqlite"
  dsn_file = %q
  users    = "select login, secret from staff"
}
`, c.users, hclPath(dsn)))
			if out := r.out.String(); !strings.Contains(out, c.want) {
				t.Errorf("startup output does not say %q:\n%s", c.want, out)
			}
		})
	}
}
