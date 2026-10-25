//go:build !nosql

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/ldap/schema"
)

// The real SUPANN schema, end to end: RENATER's published OpenLDAP file,
// loaded by schema_files exactly as published, a SQLite source whose
// users_attributes return SUPANN attributes and whose block declares
// supannPerson, and OpenLDAP's ldapsearch reading the people back.
//
// ⛔ The file is DOWNLOADED, only when LDAP_SCHEMA_NETWORK=1, and checked
// against the SHA-256 recorded here (the same sum go-authn/ldap v0.9.0
// records for it). It is never committed: RENATER publishes it without a
// licence. A changed sum fails the test, so that a new version is read
// before it is trusted.
const (
	supannURL = "https://services.renater.fr/_export/code/documentation/supann/courant/recommandations/" +
		"tables_references/schematechnique_openldap?codeblock=0"
	supannSHA256  = "961ba0e6bc38951332abb7335633b5a94ea3ba5f6bccd8516d32182e75f42ea3"
	supannFetched = "2026-10-25"
)

func fetchSupann(t *testing.T) []byte {
	t.Helper()
	if os.Getenv("LDAP_SCHEMA_NETWORK") != "1" {
		t.Skip("the SUPANN schema is downloaded, and LDAP_SCHEMA_NETWORK is not 1")
	}
	req, err := http.NewRequest(http.MethodGet, supannURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// RENATER answers 403 to a client that does not name itself as a browser.
	req.Header.Set("User-Agent", "Mozilla/5.0 (go-authn/authnd schema tests)")
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		t.Fatalf("%s: %v", supannURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %s", supannURL, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, schema.MaxFileSize+1))
	if err != nil {
		t.Fatalf("%s: %v", supannURL, err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != supannSHA256 {
		t.Fatalf("%s changed since %s: SHA-256 %s, recorded %s -- read the change, then record the new sum",
			supannURL, supannFetched, got, supannSHA256)
	}
	return b
}

func TestSupannEndToEnd(t *testing.T) {
	data := fetchSupann(t)
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	supann := write(t, dir, "supann.schema", string(data))
	dsn := sqliteWith(t, dir, `
create table staff (login text primary key, secret text, sn text, etab text, civ text, rouge text, empid text);
insert into staff values
  ('dora', 'hunter2', 'Dupont', '{UAI}0911568S', 'Mme', 'FALSE', '12345'),
  ('eli',  'swordfish', 'Martin', '{UAI}0911568S', 'M.', 'TRUE', null);
`)
	body := fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }

schema_files = [%q]

users "sql" {
  driver           = "sqlite"
  dsn_file         = %q
  users            = "select login, secret from staff"
  users_attributes = "select login, sn, etab as supannEtablissement, civ as supannCivilite, rouge as supannListeRouge, empid as supannEmpId from staff"
  object_classes   = ["supannPerson"]
}
`, hclPath(supann), hclPath(dsn))
	r := start(t, body)

	out := readerSearch(t, bin, r, "-LLL", "-b", "ou=people,dc=example,dc=org", "(uid=dora)")
	contains(t, out,
		"objectClass: inetOrgPerson",
		"objectClass: supannPerson",
		"supannEtablissement: {UAI}0911568S",
		"supannCivilite: Mme",
		"supannListeRouge: FALSE",
		"supannEmpId: 12345",
	)
	// A filter on a SUPANN attribute, evaluated with the matching rules the
	// file gives it (supannEtablissement: caseIgnoreMatch).
	out = readerSearch(t, bin, r, "-b", "ou=people,dc=example,dc=org", "(supannEtablissement={uai}0911568s)", "uid")
	contains(t, out, "uid: dora", "uid: eli", "numEntries: 2")
	out = readerSearch(t, bin, r, "-b", "cn=Subschema", "-s", "base", "(objectClass=subschema)", "objectClasses")
	contains(t, out, "objectClasses: ( 1.3.6.1.4.1.7135.1.2.2.1 NAME 'supannPerson'")
	contains(t, r.out.String(), "schema: "+hclPath(supann)+" adds 67 attribute types and 8 object classes",
		`users "sql" declares supannPerson for its people`)
	if strings.Contains(r.out.String(), "is published without supann") {
		t.Errorf("a SUPANN attribute was dropped:\n%s", r.out.String())
	}
}
