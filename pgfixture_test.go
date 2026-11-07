//go:build !nosql

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A disposable PostgreSQL cluster for the chaos tests (#73).
//
// Source: the server's own `pg_ctl --help` (start/stop, -m immediate: "quit
// without complete shutdown; will lead to recovery on restart", -D, -o, -l, -w)
// and `initdb`; the server is the real one, nothing is mocked.
//
// ⛔ The cluster belongs to the test: `initdb` into t.TempDir(), trust
// authentication, no Unix socket at all (so nothing can collide with another
// cluster's /tmp/.s.PGSQL.5432, and a long temporary path cannot overflow a
// socket name), a port of its own. It never reads PGDATA, PGPORT or any
// environment of the machine's own cluster: every command is given -D.
//
// Without the binaries the tests skip; AUTHND_REQUIRE_PG=1 (set by the Linux CI
// lane) turns the skip into a failure, like AUTHND_REQUIRE_JUDGE.

// pgBin finds the directory holding initdb, pg_ctl and postgres: PATH first,
// then the Debian/Ubuntu layout of a GitHub runner, then Postgres.app.
func pgBin() (string, bool) {
	if p, err := exec.LookPath("initdb"); err == nil {
		return filepath.Dir(p), true
	}
	globs, _ := filepath.Glob("/usr/lib/postgresql/*/bin")
	for i := len(globs) - 1; i >= 0; i-- { // glob is sorted: the newest last
		if _, err := os.Stat(filepath.Join(globs[i], "initdb")); err == nil {
			return globs[i], true
		}
	}
	const app = "/Applications/Postgres.app/Contents/Versions/latest/bin"
	if _, err := os.Stat(filepath.Join(app, "initdb")); err == nil {
		return app, true
	}
	return "", false
}

func needPG(t *testing.T) string {
	t.Helper()
	bin, ok := pgBin()
	if !ok {
		if os.Getenv("AUTHND_REQUIRE_PG") != "" {
			t.Fatal("AUTHND_REQUIRE_PG is set but no PostgreSQL server binaries (initdb, pg_ctl) were found")
		}
		t.Skip("no PostgreSQL server binaries here (initdb, pg_ctl)")
	}
	return bin
}

type pgCluster struct {
	t       *testing.T
	bin     string
	data    string
	logFile string
	port    int
}

// startPG creates a cluster and starts it. The port comes from a listener on
// :0 that is released only to hand the number to postgres; if postgres loses
// the race for it (#81 was this very race, in the KDC) the start is retried
// on another number, and what is reported is the start that worked.
func startPG(t *testing.T) *pgCluster {
	t.Helper()
	bin := needPG(t)
	dir := t.TempDir()
	c := &pgCluster{t: t, bin: bin, data: filepath.Join(dir, "data"), logFile: filepath.Join(dir, "postgres.log")}
	c.run("initdb", "-D", c.data, "-U", "postgres", "-A", "trust", "--no-sync", "-E", "UTF8", "--locale=C")
	var lastErr error
	for range 8 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		c.port = ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		if lastErr = c.start(); lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("postgres did not start: %v\n%s", lastErr, c.log())
	}
	t.Cleanup(func() {
		// Whatever state the test left it in, and only this cluster.
		exec.Command(filepath.Join(bin, "pg_ctl"), "-D", c.data, "-m", "immediate", "stop").Run()
	})
	return c
}

func (c *pgCluster) run(prog string, args ...string) {
	c.t.Helper()
	cmd := exec.Command(filepath.Join(c.bin, prog), args...)
	cmd.Stdin = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		c.t.Fatalf("%s %s: %v\n%s", prog, strings.Join(args, " "), err, out)
	}
}

// start runs pg_ctl start -w on the cluster's port.
func (c *pgCluster) start() error {
	opts := fmt.Sprintf("-p %d -c listen_addresses=127.0.0.1 -c unix_socket_directories= -c fsync=off "+
		"-c log_connections=on -c log_statement=all", c.port)
	out, err := exec.Command(filepath.Join(c.bin, "pg_ctl"), "-D", c.data, "-l", c.logFile, "-o", opts, "-w", "-t", "30", "start").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_ctl start: %v: %s", err, out)
	}
	return nil
}

// Restart brings the same cluster (same data, same port) back after Stop.
func (c *pgCluster) Restart() {
	c.t.Helper()
	if err := c.start(); err != nil {
		c.t.Fatalf("restart: %v\n%s", err, c.log())
	}
}

// Stop kills the server the way a power cut does: no shutdown checkpoint, no
// goodbye to the clients (pg_ctl stop -m immediate).
func (c *pgCluster) Stop() {
	c.t.Helper()
	c.run("pg_ctl", "-D", c.data, "-m", "immediate", "-w", "stop")
}

func (c *pgCluster) log() string {
	b, _ := os.ReadFile(c.logFile)
	return string(b)
}

// dsn is a libpq key/value DSN for host:port; the proxy tests point it at a
// listener of their own.
func (c *pgCluster) dsn(hostport string) string {
	host, port, _ := net.SplitHostPort(hostport)
	return fmt.Sprintf("host=%s port=%s user=postgres dbname=postgres sslmode=disable connect_timeout=5", host, port)
}

func (c *pgCluster) addr() string { return fmt.Sprintf("127.0.0.1:%d", c.port) }

// exec runs statements against the cluster directly, never through a proxy.
func (c *pgCluster) exec(stmts ...string) {
	c.t.Helper()
	db, err := sql.Open("pgx", c.dsn(c.addr()))
	if err != nil {
		c.t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			c.t.Fatalf("%s: %v", s, err)
		}
	}
}

const pgSchema = `
create table staff (login text primary key, secret text);
insert into staff values ('dora', 'hunter2'), ('eli', 'swordfish');
create table teams (team text, member text);
insert into teams values ('engineers', 'dora'), ('engineers', 'eli');
create table team_ids (team text primary key, gid integer);
insert into team_ids values ('engineers', 2000);
`

// pgConfig is peopleConfig over PostgreSQL: the same people and group, the
// DSN in a file of its own (the configuration never holds it).
func pgConfig(t *testing.T, dsn, extra string) string {
	t.Helper()
	dir := t.TempDir()
	file := write(t, dir, "dsn", dsn+"\n")
	return fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

reader "cn=reader,dc=example,dc=org" { password = "let me read" }

users "sql" {
  driver   = "pgx"
  dsn_file = %q
  users    = "select login, secret from staff"
  groups   = "select team, member from teams"
  groups_attributes = "select team, cast(gid as text) as \"gidNumber\" from team_ids"
}
%s`, hclPath(file), extra)
}

// pgRefreshing is a server over body with a clock and a ticker the test owns,
// as refreshing is for SQLite.
func pgRefreshing(t *testing.T, body string) (*running, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	tick := make(chan time.Time)
	r := startWith(t, body, func(s *server) {
		s.now = clk.Now
		s.ticker = func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} }
		old := s.snap.Load()
		s.snap.Store(newSnapshot(old.people, old.groups, clk.Now()))
	})
	return r, clk
}
