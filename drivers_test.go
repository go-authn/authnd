//go:build !nosql

package main

import (
	"database/sql"
	"slices"
	"testing"
)

// The drivers a configuration may name are the ones this BINARY registered.
//
// No test file imports a driver, deliberately: what this asks is whether the
// PROGRAM did. It went missing once -- the whole SQL half was unusable in a
// build that passed every other test, because the tests brought their own
// driver with them and the shipped binary had none.
func TestTheBinaryHasTheDriversItOffers(t *testing.T) {
	have := sql.Drivers()
	for _, want := range []string{"sqlite", "pgx", "mysql"} {
		if !slices.Contains(have, want) {
			t.Errorf("no %q driver in this binary: a users \"sql\" block naming it cannot open anything (have %v)", want, have)
		}
	}
}
