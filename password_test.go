// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-authn/ldap"
	"github.com/go-authn/ldap/ldaptest"
)

// session is a bound connection, for calling a handler without a network.
type session struct{ dn string }

func (s session) BoundDN() string                  { return s.dn }
func (s session) TLS() (tls.ConnectionState, bool) { return tls.ConnectionState{}, false }
func (s session) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (s session) Conn() net.Conn                   { return nil }
func (s session) Controls() []ldap.Control         { return nil }

func replace(attr string, value string) []ldap.Change {
	return []ldap.Change{{
		Operation: ldap.ReplaceValues,
		Attribute: &ldap.Attribute{Name: attr, Values: [][]byte{[]byte(value)}},
	}}
}

// ⛔ The password has to land where THAT person's block keeps it. Writing an
// inline password into a block that named a password_file would quietly undo
// the reason the file exists -- the secret is not in a file somebody prints,
// pastes or commits -- and the configuration would still parse.
func TestAPasswordGoesWhereTheBlockKeepsIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pwPath := filepath.Join(dir, "bob.pw")
	if err := os.WriteFile(pwPath, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

# a comment that must survive a write
user "alice" { password = "hunter2" }

user "bob" {
  password_file = "` + pwPath + `"
}
`
	path := write(t, dir, "c.hcl", body)
	cfg, err := loadConfig([]string{path})
	if err != nil {
		t.Fatal(err)
	}

	if err := cfg.setPassword("alice", "correct horse"); err != nil {
		t.Fatalf("alice: %v", err)
	}
	if err := cfg.setPassword("bob", "stapler battery"); err != nil {
		t.Fatalf("bob: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(after)
	if !strings.Contains(got, `password = "correct horse"`) {
		t.Errorf("alice's new password is not in the file:\n%s", got)
	}
	if strings.Contains(got, "stapler battery") {
		t.Errorf("bob's password was written INTO the configuration:\n%s", got)
	}
	if !strings.Contains(got, "# a comment that must survive a write") {
		t.Errorf("the write lost a comment:\n%s", got)
	}
	file, err := os.ReadFile(pwPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(file)) != "stapler battery" {
		t.Errorf("the password file holds %q", file)
	}
	if fi, err := os.Stat(pwPath); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("the password file is mode %v, not 0600", fi.Mode().Perm())
	}
}

func TestWhatSetPasswordRefuses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"

user "alice" { password = "hunter2" }

# somebody a site holds only the SMB hash for.
user "hash" { nt_hash = "8846f7eaee8fb117ad06bdd830b7586c" }
`
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, who, password, want string
	}{
		{"an empty password", "alice", "", "would let anybody in"},
		{"somebody not written down here", "carol", "x", "not written down"},
		{"a person held only as an nt_hash", "hash", "x",
			"would change what can prove them"},
	} {
		err := cfg.setPassword(tc.who, tc.password)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// ⛔ hclwrite hands back TOKENS, not values. A password_file written as
// anything but a plain quoted string is refused rather than guessed at,
// because writing through a path we mis-read writes somebody's password to
// the wrong file.
func TestAPasswordFileThatIsNotALiteralIsRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password_file = "/does/not/matter${""}" }
`
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err != nil {
		t.Skipf("the configuration refused this before a write could: %v", err)
	}
	if err := cfg.setPassword("alice", "x"); err == nil ||
		!strings.Contains(err.Error(), "not a plain quoted path") {
		t.Errorf("an interpolated password_file was written through: %v", err)
	}
}

func TestOnlyAPasswordChangeIsAccepted(t *testing.T) {
	t.Parallel()
	two := append(replace("userPassword", "a"), replace("description", "b")...)
	for _, tc := range []struct {
		name    string
		changes []ldap.Change
		want    string
	}{
		{"two changes at once", two, "and nothing else"},
		{"another attribute", replace("description", "x"), "not description"},
		{"an add rather than a replace", []ldap.Change{{
			Operation: ldap.AddValues,
			Attribute: &ldap.Attribute{Name: "userPassword", Values: [][]byte{[]byte("x")}},
		}}, "is replaced, not"},
		{"two values", []ldap.Change{{
			Operation: ldap.ReplaceValues,
			Attribute: &ldap.Attribute{Name: "userPassword",
				Values: [][]byte{[]byte("a"), []byte("b")}},
		}}, "is one value"},
	} {
		if _, err := onlyAPasswordChange(tc.changes); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	got, err := onlyAPasswordChange(replace("userpassword", "fine"))
	if err != nil || got != "fine" {
		t.Errorf("a plain password change: %q %v", got, err)
	}
}

func TestOnlyThePersonItBelongsToMayChangeIt(t *testing.T) {
	t.Parallel()
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }
user "alice" { password = "hunter2" }
user "bob"   { password = "hunter2" }
`)
	alice := "uid=alice,ou=people,dc=example,dc=org"
	for _, tc := range []struct {
		name string
		who  string
		dn   string
		want ldap.ResultCode
	}{
		{"anonymous", "", alice, ldap.InsufficientAccessRights},
		{"somebody else", "uid=bob,ou=people,dc=example,dc=org", alice,
			ldap.InsufficientAccessRights},
		{"a DN this server does not publish", alice, "cn=nobody,dc=example,dc=org",
			ldap.NoSuchObject},
	} {
		res, err := r.srv.Modify(context.Background(), session{dn: tc.who},
			&ldap.ModifyRequest{DN: tc.dn, Changes: replace("userPassword", "x")})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.Code != tc.want {
			t.Errorf("%s: %s, wanted %s", tc.name, res.Code, tc.want)
		}
	}

	// And the person themselves succeeds, and the running server answers the
	// NEW password without a restart.
	res, err := r.srv.Modify(context.Background(), session{dn: alice},
		&ldap.ModifyRequest{DN: alice, Changes: replace("userPassword", "correct horse")})
	if err != nil || res.Code != ldap.Success {
		t.Fatalf("alice changing her own: %s %v", res.Code, err)
	}
	c := client(t, r)
	defer c.Close()
	if got, _ := c.Bind(alice, "hunter2"); got.Code != ldap.InvalidCredentials {
		t.Errorf("the old password still binds: %s", got.Code)
	}
	if got, _ := c.Bind(alice, "correct horse"); got.Code != ldap.Success {
		t.Errorf("the new password does not bind: %s", got.Code)
	}
}

func TestDecodingAPasswordModifyRequest(t *testing.T) {
	t.Parallel()
	build := func(fields map[int]string) []byte {
		seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		for _, tag := range []int{tagUserIdentity, tagOldPasswd, tagNewPasswd} {
			if v, ok := fields[tag]; ok {
				seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
					ber.Tag(tag), v, ""))
			}
		}
		return seq.Bytes()
	}

	got, err := decodePasswdModify(build(map[int]string{
		tagUserIdentity: "uid=alice,ou=people,dc=example,dc=org",
		tagNewPasswd:    "correct horse",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// ⛔ The fields are context-tagged primitives, whose octets asn1-ber
	// leaves in Data. Reading ByteValue gives "" for a password that is
	// there, which reads as "none given" and refuses a well-formed request.
	if got.new != "correct horse" || !got.haveIdentity {
		t.Errorf("decoded %+v", got)
	}

	if empty, err := decodePasswdModify(nil); err != nil || empty.haveIdentity {
		t.Errorf("every field is optional, so an empty value is legal: %+v %v", empty, err)
	}

	for _, tc := range []struct {
		name  string
		value []byte
		want  string
	}{
		{"not BER at all", []byte{0xff, 0xff}, "not BER"},
		{"not a SEQUENCE", ber.NewString(ber.ClassUniversal, ber.TypePrimitive,
			ber.TagOctetString, "x", "").Bytes(), "not a SEQUENCE"},
		{"a field this does not know", func() []byte {
			seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "x", ""))
			return seq.Bytes()
		}(), "does not know"},
	} {
		if _, err := decodePasswdModify(tc.value); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// The RFC 3062 path end to end, which is the one ldappasswd speaks.
func TestThePasswordModifyExtendedOperation(t *testing.T) {
	t.Parallel()
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }
`)
	alice := "uid=alice,ou=people,dc=example,dc=org"

	value := func(fields map[int]string) []byte {
		seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		for _, tag := range []int{tagUserIdentity, tagNewPasswd} {
			if v, ok := fields[tag]; ok {
				seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive,
					ber.Tag(tag), v, ""))
			}
		}
		return seq.Bytes()
	}

	c := client(t, r)
	defer c.Close()

	// Anonymous: refused before anything is written.
	if res, err := c.Extended(ldap.OIDPasswordModify,
		value(map[int]string{tagNewPasswd: "x"})); err != nil ||
		res.Code != ldap.InsufficientAccessRights {
		t.Errorf("anonymous: %s %v", res.Code, err)
	}

	if res, _ := c.Bind(alice, "hunter2"); res.Code != ldap.Success {
		t.Fatalf("binding: %s", res.Code)
	}

	// No new password: this server does not generate one.
	if res, err := c.Extended(ldap.OIDPasswordModify, value(nil)); err != nil ||
		res.Code != ldap.UnwillingToPerform {
		t.Errorf("an empty request: %s %v", res.Code, err)
	}

	// An OID this server does not answer.
	if res, err := c.Extended("1.2.3.4", nil); err != nil || res.Code != ldap.ProtocolError {
		t.Errorf("an unknown OID: %s %v", res.Code, err)
	}

	// Somebody else's.
	if res, err := c.Extended(ldap.OIDPasswordModify, value(map[int]string{
		tagUserIdentity: "uid=bob,ou=people,dc=example,dc=org",
		tagNewPasswd:    "x",
	})); err != nil || res.Code != ldap.InsufficientAccessRights {
		t.Errorf("somebody else's password: %s %v", res.Code, err)
	}

	// Her own, with the identity left out, which RFC 3062 says means "this
	// connection".
	if res, err := c.Extended(ldap.OIDPasswordModify,
		value(map[int]string{tagNewPasswd: "correct horse"})); err != nil ||
		res.Code != ldap.Success {
		t.Fatalf("alice changing her own: %s %v", res.Code, err)
	}

	fresh := client(t, r)
	defer fresh.Close()
	if res, _ := fresh.Bind(alice, "correct horse"); res.Code != ldap.Success {
		t.Errorf("the new password does not bind: %s", res.Code)
	}
}

func TestTheRootDSEAdvertisesPasswordModify(t *testing.T) {
	t.Parallel()
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }
`)
	c := client(t, r)
	defer c.Close()
	res, err := c.Search(ldaptest.Search{
		Base: "", Scope: ldap.ScopeBaseObject, Filter: "(objectClass=*)",
		Attrs: []string{"supportedExtension"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range res.Entries {
		for _, a := range e.Attributes {
			for _, v := range a.Values {
				if string(v) == ldap.OIDPasswordModify {
					found = true
				}
			}
		}
	}
	if !found {
		// ⛔ A write nobody can discover is a write nobody uses: ldappasswd
		// reads this attribute before it sends anything.
		t.Errorf("the root DSE does not advertise %s", ldap.OIDPasswordModify)
	}
}

// ⛔ The two ways a write fails after the request was perfectly legal. Both
// must reach the client as a refusal rather than as Success: a password change
// that reports success and did not happen is the failure this whole path
// exists to avoid.
func TestWhenTheWriteItselfFails(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }
`)
	alice := "uid=alice,ou=people,dc=example,dc=org"
	path := r.srv.cfg.files[0]

	// 1. Somebody this server serves but does not OWN. Rewriting the file
	// without alice is how a person reaches here from a sql or ldap source:
	// the bind proved them, and no sentence in our files describes them.
	if err := os.WriteFile(path, []byte(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "carol" { password = "hunter2" }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := r.srv.Modify(context.Background(), session{dn: alice},
		&ldap.ModifyRequest{DN: alice, Changes: replace("userPassword", "x")})
	if err != nil || res.Code != ldap.UnwillingToPerform {
		t.Errorf("somebody we only read: %s %v", res.Code, err)
	}
	if !strings.Contains(res.Diagnostic, "reads and does not write") {
		t.Errorf("the refusal does not say why: %q", res.Diagnostic)
	}

	// 2. A file that cannot be replaced. replaceFile writes a temporary file
	// beside the target and renames, so a directory nobody may write to is
	// what stops it.
	dir := filepath.Dir(path)
	if err := os.WriteFile(path, []byte(`
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "hunter2" }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	res, err = r.srv.Modify(context.Background(), session{dn: alice},
		&ldap.ModifyRequest{DN: alice, Changes: replace("userPassword", "x")})
	if err != nil || res.Code != ldap.Other {
		t.Errorf("an unwritable directory: %s %v", res.Code, err)
	}
	// ⛔ The client is told it failed and nothing else. The path is on the
	// server's own disk and belongs in its log, not in an answer to somebody
	// who may change one password.
	if strings.Contains(res.Diagnostic, dir) {
		t.Errorf("the refusal names a path on this machine: %q", res.Diagnostic)
	}
	if !strings.Contains(r.out.String(), "changing the password for alice") {
		t.Errorf("the reason did not reach the log:\n%s", r.out.String())
	}
}
