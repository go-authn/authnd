//go:build nosql

package main

import (
	"fmt"
	"testing"
)

// The same people, in a build with no database in it.
//
// The tests that use this are about the SERVER: what a bind proves, who may
// search, what is published. None of that changes with where the people came
// from, so a build without SQL still has to pass them -- and a `-tags nosql`
// lane that skipped every test would prove only that the binary links.
func peopleConfig(t *testing.T, dir string, extra string) string {
	t.Helper()
	return fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

reader "cn=reader,dc=example,dc=org" { password = "let me read" }

user "svc"  { password = "service" }
user "dora" { password = "hunter2" }
user "eli"  { password = "swordfish" }

group "engineers" { members = ["dora", "eli"] }
%s`, extra)
}

// peopleFrom is what `check` says about where dora came from in this build.
const peopleFrom = "the configuration file"
