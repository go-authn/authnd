// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"strings"
	"testing"
)

// ⛔ `check` is read by somebody deciding whether to restart something people
// log in through. It is the one output in this program whose AUDIENCE is a
// person under time pressure, and until now the half of it that talks about
// TLS and published credentials was never exercised at all -- `overWhat` sat
// at 0% coverage while being the sentence that says whether an NT hash
// crosses the network in the clear.
func TestCheckSaysWhatEachPersonCanProveAndWhatIsPublished(t *testing.T) {
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	path := write(t, dir, "c.hcl", fmt.Sprintf(`
listen    = "127.0.0.1:0"
base_dn   = "dc=example,dc=org"
cert_file = %q
key_file  = %q

publish_nt_hash = true

reader "cn=reader,dc=example,dc=org" { password = "let me read" }

# A password: everything can be derived from it, including the NT hash.
user "dora" { password = "hunter2" }

# ONLY an NT hash, as a site that stores what Samba stores does. She can be
# served over SMB and cannot be bound as with a password.
user "frank" { nt_hash = %q }

# Keys and a code, and no password at all.
user "gwen" {
  totp_secret     = %q
  authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7Zq5aJ9t3vZ6Z1JhKQ0T9xX2p0m1n2o3p4q5r6s7t8 gwen@example"]
}
`, hclPath(cert), hclPath(key), strings.ToLower(hunter2NTHash), tessSecretB32))

	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}

	// What each person can PROVE, which is the distinction this whole
	// program exists for: a password is not an NT hash is not a key.
	contains(t, out,
		"ldaps://", // the scheme, since cert_file is set
		"dora", "a password",
		"frank", "an NT hash", // and NOT "a password": she has none
		"gwen", "1 key", "a one-time-code secret",
	)

	// ⛔ And what is PUBLISHED, which is a different question. An NT hash is
	// a credential: whoever reads it authenticates as that person over
	// NTLMv2 without ever learning the password. The line that says so must
	// also say what protects the wire.
	contains(t, out, "sambaNTPassword", "over TLS", "NTLMv2")
	if !strings.Contains(out, "sshPublicKey") {
		t.Errorf("gwen's key is not listed as published:\n%s", out)
	}

	// ⛔ The secret itself is never printed. `check` is run in terminals
	// that scroll into other people's screenshots.
	if strings.Contains(out, tessSecretB32) {
		t.Error("check printed a one-time-code secret")
	}
	if strings.Contains(out, "hunter2") {
		t.Error("check printed a password")
	}
}

// Without a certificate the same line must say something DIFFERENT: the
// condition under which publishing a credential is defensible is not met by
// a promise, and "on a loopback listener" is the only other thing that meets
// it.
func TestCheckSaysWhatProtectsTheWireWhenThereIsNoTLS(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", fmt.Sprintf(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

publish_nt_hash = true

reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "dora" { password = "hunter2" }
`))
	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	contains(t, out, "ldap://", "sambaNTPassword", "on a loopback listener")
	if strings.Contains(out, "over TLS") {
		t.Errorf("a plaintext listener claimed TLS:\n%s", out)
	}
}

// ⛔ A group naming somebody no source publishes is refused AT STARTUP, and
// the refusal names both the group and the person.
//
// I wrote this test expecting `check` to list the name and carry on. It does
// not get the chance: the configuration will not load. That is the stronger
// behaviour and the right one -- a membership an administrator believes
// exists, pointing at nobody, is a permission that silently does nothing,
// and a server that starts anyway means finding out from an access review
// rather than from a restart.
func TestAGroupNamingNobodyIsRefusedAtStartup(t *testing.T) {
	dir := t.TempDir()
	// ⛔ Through `check`, not loadConfig: the file PARSES fine. The refusal
	// comes when the directory is opened and the sources are asked who they
	// have, which is the only moment the answer is knowable -- a `users`
	// block reading a database cannot be checked by reading the file.
	out, err := execute(t, "check", write(t, dir, "c.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "dora" { password = "hunter2" }
group "ghosts" { members = ["dora", "nobody"] }
`))
	if err == nil {
		t.Fatalf("a group naming somebody no source publishes was accepted:\n%s", out)
	}
	// It names BOTH, because an operator reading it has to find the line.
	for _, want := range []string{"ghosts", "nobody"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	// And the control: the same file without the ghost loads.
	if _, err := execute(t, "check", write(t, dir, "ok.hcl", `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "dora" { password = "hunter2" }
group "ghosts" { members = ["dora"] }
`)); err != nil {
		t.Errorf("the same file without the ghost was refused: %v", err)
	}
}
