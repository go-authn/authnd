package main

import (
	"testing"

	"github.com/go-authn/directory/hcldir"
)

func TestTheQueryDeadlineFollowsTheRefreshPeriod(t *testing.T) {
	blocks := []hcldir.Block{
		{Kind: "sql"}, {Kind: "sql", QueryTimeout: "5s"}, {Kind: "sql", QueryTimeout: "0"}, {Kind: "ldap"},
	}
	for _, c := range []struct {
		refresh string
		want    []string
	}{
		{"", []string{"45s", "5s", "0", ""}},    // default period 60s
		{"20s", []string{"15s", "5s", "0", ""}}, // three quarters
		{"0", []string{"", "5s", "0", ""}},      // never refreshing: the library's default
	} {
		cfg := &config{Refresh: c.refresh, Directories: blocks}
		got := withQueryDeadline(cfg)
		for i, b := range got {
			if b.QueryTimeout != c.want[i] {
				t.Errorf("refresh %q, block %d: query_timeout %q, want %q", c.refresh, i, b.QueryTimeout, c.want[i])
			}
		}
	}
	if blocks[0].QueryTimeout != "" {
		t.Error("the configuration's own blocks were changed")
	}
}
