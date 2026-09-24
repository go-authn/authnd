// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// ⛔ A search filter is the question a client asked. A server that answers a
// BROADER one has disclosed entries nobody asked for — and says nothing,
// because every entry it returns is a real entry.
//
// This was live: the library evaluated `(uid=svc-*-prod)` as `(uid=svc-*)`
// and returned svc-web-stage. It read only the FIRST component of a
// SubstringFilter, which RFC 4511 4.5.1.7 allows to carry an `initial`, any
// number of `any`, and a `final`.
//
// ⭐ The judge is OpenLDAP's ldapsearch and not this server's own LDAP
// library. The first time I measured this I used that library's client, and
// it reported zero matches — client and server shared the defect, so the
// question was being asked wrong and answered wrong by the same code. A test
// whose judge and subject are one thing cannot see either move.
func TestASubstringFilterIsAnsweredAsAsked(t *testing.T) {
	bin := needLDAPSearch(t)
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

reader "cn=reader,dc=example,dc=org" { password = "let me read" }

user "svc-web-prod"  { password = "a" }
user "svc-web-stage" { password = "b" }
user "svc-db-prod"   { password = "c" }
user "app-web-prod"  { password = "d" }
`)
	ask := func(filter string) []string {
		t.Helper()
		out, _ := exec.Command(bin, "-x", "-H", "ldap://"+r.addr,
			"-D", "cn=reader,dc=example,dc=org", "-w", "let me read",
			"-b", "ou=people,dc=example,dc=org", filter, "uid").CombinedOutput()
		var got []string
		for _, line := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(line, "uid: "); ok {
				got = append(got, v)
			}
		}
		sort.Strings(got)
		return got
	}
	for _, tc := range []struct {
		filter string
		want   []string
	}{
		// The one that was wrong: an interior * with something after it.
		{"(uid=svc-*-prod)", []string{"svc-db-prod", "svc-web-prod"}},
		// Two interior components.
		{"(uid=svc-*-*)", []string{"svc-db-prod", "svc-web-prod", "svc-web-stage"}},
		// The three single-component shapes, which already worked: they are
		// the control. Without them a fix that broke them would look clean.
		{"(uid=svc-*)", []string{"svc-db-prod", "svc-web-prod", "svc-web-stage"}},
		{"(uid=*-prod)", []string{"app-web-prod", "svc-db-prod", "svc-web-prod"}},
		{"(uid=*web*)", []string{"app-web-prod", "svc-web-prod", "svc-web-stage"}},
		{"(uid=svc-web-prod)", []string{"svc-web-prod"}},
	} {
		got := ask(tc.filter)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s\n  returned %v\n  want     %v", tc.filter, got, tc.want)
		}
	}
}
