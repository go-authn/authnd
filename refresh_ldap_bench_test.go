//go:build !nosql && !noldap

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"testing"

	"github.com/go-authn/directory/ldaptest"
)

// BenchmarkRefreshLDAP10k2k is one refreshTry (read, validate, publish, swap)
// of an authnd whose only source is a users "ldap" block over 10,000 people
// and 2,000 groupOfNames of 50 DNs: the shape of go-authn/directory#42. The
// upstream runs in this process, so a -memprofile holds its allocations too;
// they are not authnd's cost in production.
func BenchmarkRefreshLDAP10k2k(b *testing.B) {
	const people, groups, size = 10000, 2000, 50
	const base = "dc=example,dc=org"
	if *refreshProfile != "" {
		runtime.MemProfileRate = 4096
	}
	d :=&ldaptest.Directory{
		People:        map[string]ldaptest.Person{},
		GroupsOfNames: map[string][]string{},
	}
	for i := 0; i < people; i++ {
		d.People[fmt.Sprintf("user%05d", i)] = ldaptest.Person{Password: "pw"}
	}
	for g := 0; g < groups; g++ {
		var m []string
		for j := 0; j < size; j++ {
			m = append(m, fmt.Sprintf("uid=user%05d,ou=people,%s", (g*size+j)%people, base))
		}
		d.GroupsOfNames[fmt.Sprintf("group%04d", g)] = m
	}
	up, err := ldaptest.NewServer(d)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { up.Close() })
	pw := filepath.Join(b.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte(up.ReaderPassword), 0o600); err != nil {
		b.Fatal(err)
	}
	r := start(b, fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
refresh = "0"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
users "ldap" {
  url                = %q
  bind_dn            = %q
  bind_password_file = %q
  base_dn            = %q
  group_base_dn      = %q
  group_filter       = "(objectClass=groupOfNames)"
  group_attribute    = "cn"
}
`, up.URL, up.ReaderDN, hclPath(pw), up.PeopleDN, up.GroupsDN))
	b.ReportAllocs()
	writeAllocs(b, "base")
	b.ResetTimer()
	for range b.N {
		if err := r.srv.refreshTry(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	writeAllocs(b, "after")
}

// refreshProfile names a directory: the benchmark then writes the allocation
// profile before and after the timed refreshes, so that
// `go tool pprof -sample_index=alloc_objects -base base.pb.gz after.pb.gz`
// is the refreshes alone, without the fixture and the startup read.
var refreshProfile = flag.String("refreshprofile", "", "directory for the allocation profiles of BenchmarkRefreshLDAP10k2k")

func writeAllocs(b *testing.B, name string) {
	if *refreshProfile == "" {
		return
	}
	runtime.GC()
	f, err := os.Create(filepath.Join(*refreshProfile, name+".pb.gz"))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	if err := pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
		b.Fatal(err)
	}
}
