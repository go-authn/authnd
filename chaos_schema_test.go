// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Chaos: a schema file cut at every byte offset.
//
// ⛔ The measurement is on the property, not on a list of cases: for EVERY
// prefix of a real file, directorySchema either refuses -- naming the file --
// or builds a schema, and in neither case panics or hands back half of one.
// A prefix that ends on a definition boundary is a valid, shorter file and
// builds; that is not a defect, it is the file a smaller site would write. What
// must never happen is an error that does not say where, or a schema next to
// an error.

// supannSized is a generated file the size and shape of RENATER's SUPANN
// schema (67 attribute types, 8 object classes), so that the test needs no
// download.
func supannSized() string {
	var b strings.Builder
	var names []string
	for i := 1; i <= 67; i++ {
		n := fmt.Sprintf("chaosAttr%02d", i)
		names = append(names, n)
		fmt.Fprintf(&b, "attributetype ( 1.3.6.1.4.1.7135.1.2.1.%d NAME '%s'\n\tDESC 'attribute number %d'\n\tEQUALITY caseIgnoreMatch\n\tSUBSTR caseIgnoreSubstringsMatch\n\tSYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n\n", i, n, i)
	}
	for i := 1; i <= 8; i++ {
		var may []string
		for j := (i - 1) * 8; j < i*8 && j < len(names); j++ {
			may = append(may, names[j])
		}
		fmt.Fprintf(&b, "objectclass ( 1.3.6.1.4.1.7135.1.2.2.%d NAME 'chaosClass%d'\n\tDESC 'class %d'\n\tSUP top AUXILIARY\n\tMAY ( %s ) )\n\n", i, i, i, strings.Join(may, " $ "))
	}
	return b.String()
}

func TestChaosSchemaFileTruncatedAtEveryOffset(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{"supann-sized.schema": []byte(supannSized())}
	for _, name := range []string{"rules.schema", "example.schema", "example.ldif"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = b
	}
	for name, full := range files {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, name)
			refused, built := 0, 0
			for n := 0; n <= len(full); n++ {
				if err := os.WriteFile(path, full[:n], 0o600); err != nil {
					t.Fatal(err)
				}
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("offset %d of %d: panic: %v", n, len(full), r)
						}
					}()
					b, err := directorySchema(&config{SchemaFiles: []string{path}})
					switch {
					case err != nil:
						refused++
						if b != nil {
							t.Fatalf("offset %d: an error AND a schema: half-loaded", n)
						}
						if !strings.Contains(err.Error(), path) {
							t.Fatalf("offset %d: the refusal does not name the file: %v", n, err)
						}
					case b == nil || b.schema == nil:
						t.Fatalf("offset %d: neither an error nor a schema", n)
					default:
						built++
					}
				}()
			}
			if refused == 0 {
				t.Errorf("no prefix of %s was refused: the cut never reached a definition", name)
			}
			if built == 0 {
				t.Errorf("no prefix of %s built, not even the empty one", name)
			}
			t.Logf("%s: %d bytes, %d prefixes refused, %d built", name, len(full), refused, built)
		})
	}
}

// A schema file replaced or removed after `check` and before the server reads
// it is read as it is when the server reads it, once: there is no reload that
// could read it twice (root.go survive), so there is no second chance for the
// file to change under a running server.
func TestChaosSchemaFileGoneBetweenCheckAndServe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "site.schema")
	good, _ := os.ReadFile(filepath.Join("testdata", "example.schema"))
	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("base_dn = \"dc=example,dc=org\"\nschema_files = [%q]\nuser \"a\" { password = \"x\" }\n", hclPath(path))
	if _, err := openBody(t, body); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := openBody(t, body); err == nil || !strings.Contains(err.Error(), "schema_files") {
		t.Fatalf("a removed schema file must refuse startup naming schema_files, got %v", err)
	}
	if err := os.WriteFile(path, good[:len(good)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openBody(t, body); err == nil {
		t.Fatal("a schema file replaced by half of itself must refuse startup")
	}
}
