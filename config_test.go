package main

import (
	"fmt"
	"strings"
	"testing"
)

// What a configuration cannot mean is refused, with the reason.
func TestConfigurationsThatCannotWork(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{
			"no base_dn",
			`user "svc" { password = "x" }`,
			"no base_dn",
		},
		{
			"a base that is not a DN",
			`base_dn = "example.org"
			 user "svc" { password = "x" }`,
			"is not a DN",
		},
		{
			"an address that is not one",
			`base_dn = "dc=example,dc=org"
			 listen  = "not-an-address"
			 user "svc" { password = "x" }`,
			"is not an address",
		},
		{
			"nobody at all",
			`base_dn = "dc=example,dc=org"`,
			"there is nobody here",
		},
		{
			// A reader that proves nothing is anonymous search with extra
			// steps, and the whole reason readers exist is to refuse that.
			"a reader with no password",
			`base_dn = "dc=example,dc=org"
			 reader "cn=reader,dc=example,dc=org" {}
			 user "svc" { password = "x" }`,
			"a reader that proves nothing",
		},
		{
			"a reader that is not a DN",
			`base_dn = "dc=example,dc=org"
			 reader "reader" { password = "x" }
			 user "svc" { password = "x" }`,
			"is not a DN",
		},
		{
			"the same reader twice",
			`base_dn = "dc=example,dc=org"
			 reader "cn=reader,dc=example,dc=org" { password = "x" }
			 reader "CN=Reader,dc=example,dc=org" { password = "y" }
			 user "svc" { password = "x" }`,
			"defined twice",
		},
		{
			// Two ways to say the same secret can disagree, and then the
			// server answers one protocol as one person and another as
			// somebody who does not exist.
			"a password and an nt_hash at once",
			`base_dn = "dc=example,dc=org"
			 user "svc" {
			   password = "x"
			   nt_hash  = "8846f7eaee8fb117ad06bdd830b7586c"
			 }`,
			"the hash is derived from the password",
		},
		{
			"an nt_hash that is not one",
			`base_dn = "dc=example,dc=org"
			 user "svc" { nt_hash = "not a hash" }`,
			"an NT hash is hex",
		},
		{
			"a password and a password_file at once",
			`base_dn = "dc=example,dc=org"
			 user "svc" {
			   password      = "x"
			   password_file = "/etc/passwords/svc"
			 }`,
			"say which one",
		},
		{
			"a group with nobody in it",
			`base_dn = "dc=example,dc=org"
			 user "svc" { password = "x" }
			 group "empty" { members = [] }`,
			"has no members",
		},
		{
			"a key file and inline keys at once",
			`base_dn = "dc=example,dc=org"
			 user "svc" {
			   password             = "x"
			   authorized_keys      = ["ssh-ed25519 AAAA x@y"]
			   authorized_keys_file = "/etc/keys/svc"
			 }`,
			"say which one",
		},
		{
			"a users block that is neither kind",
			`base_dn = "dc=example,dc=org"
			 user "svc" { password = "x" }
			 users "kerberos" { driver = "sqlite" }`,
			`there is no "kerberos" directory here`,
		},
		{
			// ⛔ The one that matters most: a credential on a network in the
			// clear. sambaNTPassword is not a password hash in the sense a
			// login form means it.
			"an NT hash published on every interface, in the clear",
			`base_dn         = "dc=example,dc=org"
			 listen          = "0.0.0.0:3893"
			 publish_nt_hash = true
			 user "svc" { password = "x" }`,
			"publish_nt_hash needs cert_file and key_file",
		},
		{
			"half a TLS configuration",
			`base_dn   = "dc=example,dc=org"
			 cert_file = "/etc/authnd/cert.pem"
			 user "svc" { password = "x" }`,
			"go together",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, err := loadConfig([]string{write(t, dir, "c.hcl", tc.body)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// Publishing an NT hash over TLS is allowed on any interface: the wire is not
// in the clear, which was the whole objection.
func TestAnNTHashMayBePublishedOverTLS(t *testing.T) {
	dir := t.TempDir()
	body := fmt.Sprintf(`
base_dn         = "dc=example,dc=org"
listen          = "0.0.0.0:3893"
publish_nt_hash = true
cert_file       = %q
key_file        = %q
user "svc" { password = "x" }
`, hclPath(write(t, dir, "cert.pem", "")), hclPath(write(t, dir, "key.pem", "")))
	if _, err := loadConfig([]string{write(t, dir, "c.hcl", body)}); err != nil {
		t.Errorf("a TLS listener publishing hashes was refused: %v", err)
	}
}

// A group naming somebody no source has an entry for is served, and said.
func TestAGroupMayNameSomebodyThisServerCannotProve(t *testing.T) {
	dir := t.TempDir()
	body := `
base_dn = "dc=example,dc=org"
user "svc" { password = "x" }
group "ops" { members = ["svc", "trevor"] }
`
	// The refusal is at OPEN, not at load: a group member is checked against
	// the people who exist, and with a users block those are not all in the
	// file.
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if srv != nil {
		srv.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "trevor") {
		t.Errorf("a group block naming a stranger gave %v", err)
	}
}

// A directory of files is read as one: the people in one, the listener in
// another, and neither has to know about the other.
func TestADirectoryOfFilesIsReadAsOne(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "10-listen.hcl", "listen = \"127.0.0.1:0\"\nbase_dn = \"dc=example,dc=org\"\n")
	write(t, dir, "20-people.hcl", "user \"svc\" { password = \"x\" }\n")
	write(t, dir, "30-readers.hcl", "reader \"cn=reader,dc=example,dc=org\" { password = \"y\" }\n")
	cfg, err := loadConfig([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Users) != 1 || len(cfg.Readers) != 1 || cfg.BaseDN != "dc=example,dc=org" {
		t.Errorf("the files were not merged: %+v", cfg)
	}
	// A directory with nothing in it is a refusal naming the directory, not a
	// server that starts with no configuration at all.
	if _, err := loadConfig([]string{t.TempDir()}); err == nil || !strings.Contains(err.Error(), "no .hcl files") {
		t.Errorf("an empty directory gave %v", err)
	}
}
