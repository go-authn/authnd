// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"
	"time"
)

func TestRefreshAndMaxAgeConfiguration(t *testing.T) {
	c := &config{}
	if c.refreshEvery() != 60*time.Second || c.maxAge() != 0 {
		t.Fatalf("defaults: refresh %v, max_age %v", c.refreshEvery(), c.maxAge())
	}
	for _, tc := range []struct {
		refresh, maxAge, wantErr string
		every, max               time.Duration
	}{
		{"", "", "", 60 * time.Second, 0},
		{"0", "", "", 0, 0},
		{"30s", "5m", "", 30 * time.Second, 5 * time.Minute},
		{"abc", "", `refresh "abc"`, 0, 0},
		{"-5s", "", "at least one second", 0, 0},
		{"500ms", "", "at least one second", 0, 0},
		{"", "soon", `max_age "soon"`, 0, 0},
		{"", "0s", "more than zero", 0, 0},
		{"60s", "30s", "shorter than refresh", 0, 0},
		{"0", "30s", "", 0, 30 * time.Second},
	} {
		c := &config{Refresh: tc.refresh, MaxAge: tc.maxAge}
		err := c.checkRefresh()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("refresh %q max_age %q: %v", tc.refresh, tc.maxAge, err)
				continue
			}
			if c.refreshEvery() != tc.every || c.maxAge() != tc.max {
				t.Errorf("refresh %q max_age %q: got %v and %v", tc.refresh, tc.maxAge, c.refreshEvery(), c.maxAge())
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("refresh %q max_age %q: got %v, want %q", tc.refresh, tc.maxAge, err, tc.wantErr)
		}
	}
	// And through the configuration's own check, which is what refuses startup.
	bad := &config{BaseDN: "dc=x", Refresh: "nope"}
	if err := bad.check(); err == nil || !strings.Contains(err.Error(), "refresh") {
		t.Errorf("check: %v", err)
	}
}
