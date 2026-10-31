// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// BenchmarkPublish10k is publish on 10,000 people -- accounts with the
// three posix attributes and a description -- with and without the rules
// of testdata/rules.schema (a content rule, name forms, structure rules):
// what the rules cost per entry.
func BenchmarkPublish10k(b *testing.B) {
	const n = 10000
	var people strings.Builder
	for i := range n {
		fmt.Fprintf(&people, "user \"u%d\" {\n  password = \"x\"\n  attributes = { uidNumber = \"%d\", gidNumber = \"100\", homeDirectory = \"/home/u%d\", description = \"d\" }\n}\n", i, 1000+i, i)
	}
	for _, c := range []struct{ name, files string }{
		{"without", ""},
		{"with", fmt.Sprintf("%q", testdataPath(&testing.T{}, "rules.schema"))},
	} {
		b.Run(c.name, func(b *testing.B) {
			body := fmt.Sprintf("listen = \"127.0.0.1:0\"\nbase_dn = \"dc=example,dc=org\"\nschema_files = [%s]\n%s", c.files, people.String())
			cfg, err := loadConfig([]string{write(&testing.T{}, b.TempDir(), "c.hcl", body)})
			if err != nil {
				b.Fatal(err)
			}
			srv, err := open(cfg, io.Discard)
			if err != nil {
				b.Fatal(err)
			}
			defer srv.Close()
			b.ReportAllocs()
			for b.Loop() {
				// build, not publish: publish keeps its answer, and this
				// measures the work of making it.
				if p := srv.build(srv.people.Load()); len(p.valid()) != n {
					b.Fatalf("%d published", len(p.valid()))
				}
			}
		})
	}
}
