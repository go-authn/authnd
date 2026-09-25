package main

import (
	"fmt"
	"strings"
	"testing"
)

// A database, read through this server, by OpenLDAP's own client.
//
// This is the product's whole claim: people who are in SQL, answered as a
// directory to something that speaks LDAP and nothing else. The client is
// ldapsearch, which knows nothing about this program -- a Go client from the
// same ecosystem could share a misreading of the protocol with the server and
// the test would pass anyway.
func TestOpenLDAPReadsPeopleOutOfADatabase(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	r := start(t, peopleConfig(t, dir, ""))

	out, err := search(bin, r.url(), "cn=reader,dc=example,dc=org", "let me read",
		"ou=people,dc=example,dc=org", "(objectClass=posixAccount)", "uid")
	if err != nil {
		t.Fatalf("ldapsearch: %v\n%s", err, out)
	}
	contains(t, out,
		"dn: uid=dora,ou=people,dc=example,dc=org",
		"uid: dora",
		"uid: eli",
		"uid: svc", // the one written down here rather than in the database
		"result: 0 Success",
	)

	// A filter really filters, because the server does not evaluate filters:
	// it hands the entries over and the library applies RFC 4515. A test that
	// only ever asked for everything would never notice the difference.
	out, err = search(bin, r.url(), "cn=reader,dc=example,dc=org", "let me read",
		"ou=people,dc=example,dc=org", "(uid=dora)", "uid")
	if err != nil {
		t.Fatalf("ldapsearch: %v\n%s", err, out)
	}
	if !strings.Contains(out, "uid: dora") || strings.Contains(out, "uid: eli") {
		t.Errorf("(uid=dora) answered with more than dora:\n%s", out)
	}
	if !strings.Contains(out, "numEntries: 1") {
		t.Errorf("(uid=dora) did not answer with exactly one entry:\n%s", out)
	}

	// And the groups, in the search a directory reader makes for them.
	out, err = search(bin, r.url(), "cn=reader,dc=example,dc=org", "let me read",
		"ou=groups,dc=example,dc=org", "(&(objectClass=posixGroup)(cn=engineers))", "memberUid")
	if err != nil {
		t.Fatalf("ldapsearch: %v\n%s", err, out)
	}
	contains(t, out, "cn=engineers,ou=groups,dc=example,dc=org", "memberUid: dora", "memberUid: eli")
}

// Binding as a person in the database, judged by the same foreign client.
func TestOpenLDAPBindsAsSomebodyFromTheDatabase(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	r := start(t, peopleConfig(t, dir, ""))
	people := "ou=people,dc=example,dc=org"

	// The password is in the database; the bind is answered from it.
	if out, err := search(bin, r.url(), "uid=dora,"+people, "hunter2", people, "(uid=dora)"); err == nil {
		t.Errorf("dora bound and searched, and only a reader may search:\n%s", out)
	} else if !strings.Contains(out, "Insufficient access") {
		// The bind must have SUCCEEDED and the search must have been refused:
		// those are different failures and the difference is the point.
		t.Errorf("dora's bind should succeed and her search should not; got:\n%s", out)
	}
	// A wrong password is refused at the bind, which reads differently.
	if out, _ := search(bin, r.url(), "uid=dora,"+people, "wrong", people, "(uid=dora)"); !strings.Contains(out, "Invalid credentials (49)") {
		t.Errorf("a wrong password gave:\n%s", out)
	}
	// Somebody who is in no source at all is refused the same way, without
	// saying which of the name or the password was wrong.
	if out, _ := search(bin, r.url(), "uid=trevor,"+people, "hunter2", people, "(uid=dora)"); !strings.Contains(out, "Invalid credentials (49)") {
		t.Errorf("an unknown person gave:\n%s", out)
	}
}

// ⛔ The unauthenticated bind, refused -- and refused with the code RFC 4513
// asks for.
//
// §5.1.2 is a bind carrying a NAME and a zero-length password. It does not
// prove the name; it establishes an anonymous authorization state while
// naming somebody, and the specification says servers "SHOULD by default
// fail Unauthenticated Bind requests with a resultCode of
// unwillingToPerform".
//
// This comment used to say such a bind "is answered SUCCESS by a real
// directory". That is wrong, it was wrong in three places at once, and the
// mistake matters twice over: a server that passes it through as proof lets
// anybody in as anybody, and one that refuses it as invalidCredentials tells
// the client its password was wrong -- so a person retries and starts
// doubting a password that was never the problem.
//
// §5.1.1 is the ANONYMOUS bind, an empty name AND an empty password, which
// is legitimate and succeeds. One field apart.
//
// The judge is ldapsearch, which sends exactly this when given -w "".
func TestTheUnauthenticatedBindIsRefused(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	r := start(t, peopleConfig(t, dir, ""))
	people := "ou=people,dc=example,dc=org"

	for _, who := range []string{"uid=dora," + people, "cn=reader,dc=example,dc=org"} {
		out, err := search(bin, r.url(), who, "", people, "(objectClass=posixAccount)", "uid")
		if err == nil {
			t.Errorf("%s was let in with an empty password:\n%s", who, out)
		}
		if !strings.Contains(out, "unwilling to perform (53)") {
			t.Errorf("%s with an empty password gave:\n%s", who, out)
		}
	}
	// Anonymous, with no bind DN at all, reaches the search and is refused
	// there -- a different refusal, and the right one.
	out, _ := search(bin, r.url(), "", "", people, "(objectClass=posixAccount)", "uid")
	if strings.Contains(out, "uid: dora") {
		t.Errorf("an anonymous client read the people:\n%s", out)
	}
}

// A reader may search; a person who bound may not. A directory that answers
// everybody has published its people to everybody.
func TestOnlyAReaderMaySearch(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	r := start(t, peopleConfig(t, dir, ""))
	people := "ou=people,dc=example,dc=org"

	if out, err := search(bin, r.url(), "cn=reader,dc=example,dc=org", "let me read", people, "(objectClass=posixAccount)", "uid"); err != nil {
		t.Errorf("the reader could not search: %v\n%s", err, out)
	}
	if out, err := search(bin, r.url(), "uid=svc,"+people, "service", people, "(objectClass=posixAccount)", "uid"); err == nil {
		t.Errorf("svc bound and read everybody:\n%s", out)
	}
}

// ⛔ sambaNTPassword is a CREDENTIAL, and it is published only when asked for.
func TestTheNTHashIsPublishedOnlyOnPurpose(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	reader, people := "cn=reader,dc=example,dc=org", "ou=people,dc=example,dc=org"

	// Off by default: the attribute is not there at all.
	r := start(t, peopleConfig(t, dir, ""))
	out, err := search(bin, r.url(), reader, "let me read", people, "(uid=dora)", "uid", "sambaNTPassword")
	if err != nil {
		t.Fatalf("ldapsearch: %v\n%s", err, out)
	}
	// The attribute VALUE, not the name: ldapsearch echoes the attributes it
	// asked for in a comment at the top, so looking for the name alone finds
	// the question rather than the answer.
	if strings.Contains(out, "sambaNTPassword: ") {
		t.Errorf("an NT hash was published without being asked for:\n%s", out)
	}

	// On, on a loopback listener: the hash is there, and it is the MD4 of the
	// password the database holds -- which is the whole reason SMB can use it.
	dir2 := t.TempDir()
	r2 := start(t, peopleConfig(t, dir2, "\npublish_nt_hash = true\n"))
	out, err = search(bin, r2.url(), reader, "let me read", people, "(uid=dora)", "uid", "sambaNTPassword")
	if err != nil {
		t.Fatalf("ldapsearch: %v\n%s", err, out)
	}
	if !strings.Contains(out, "sambaNTPassword: "+hunter2NTHash) {
		t.Errorf("the published hash is not the MD4 of dora's password:\n%s", out)
	}
}

// A configuration that would put a credential on a network in the clear is
// refused, and the refusal says what to do about it.
func TestPublishingAnNTHashOffLoopbackIsRefused(t *testing.T) {
	dir := t.TempDir()
	body := strings.Replace(peopleConfig(t, dir, "\npublish_nt_hash = true\n"),
		`listen  = "127.0.0.1:0"`, `listen = "0.0.0.0:3893"`, 1)
	_, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err == nil {
		t.Fatal("a configuration publishing an NT hash on every interface in the clear was accepted")
	}
	if !strings.Contains(err.Error(), "cert_file") || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("the refusal reads %q", err)
	}
}

// check says what would be served, and never a secret.
func TestCheckSaysWhatWouldBeServed(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", peopleConfig(t, dir, ""))
	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	contains(t, out,
		"dc=example,dc=org",
		"dora", "eli", "svc",
		peopleFrom, "the configuration file",
		"engineers", // the group, with its members
		"cn=reader,dc=example,dc=org may search",
		"sambaNTPassword is not published",
		"this configuration can be served",
	)
	for _, secret := range []string{"hunter2", "swordfish", "let me read", "service"} {
		if strings.Contains(out, secret) {
			t.Errorf("check printed %q", secret)
		}
	}
}

// hunter2NTHash is MD4(UTF16LE("hunter2")), computed by something that is not
// this program:
//
//	printf 'hunter2' | iconv -f UTF-8 -t UTF-16LE | openssl md4
//
// with OpenSSL 1.1, which still has MD4 (3.x removed it from the default
// provider, and macOS ships 3.x). The same command gives
// 8846f7eaee8fb117ad06bdd830b7586c for "password" -- the value every article
// about NTLM quotes -- which is how that OpenSSL was checked before being
// believed here.
//
// Written down rather than computed: an expectation produced by the code under
// test agrees with it by construction, whatever either of them does.
const hunter2NTHash = "6608E4BC7B2B7A5F77CE3573570775AF"

// Binds are counted, and a bind really reaches this server: a test that
// asserts a password was checked can show it rather than assume it.
func TestBindsReachTheServer(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	r := start(t, peopleConfig(t, dir, ""))
	before := r.srv.Binds()
	search(bin, r.url(), "uid=dora,ou=people,dc=example,dc=org", "hunter2",
		"ou=people,dc=example,dc=org", "(uid=dora)")
	if r.srv.Binds() <= before {
		t.Error("a bind was answered without reaching the server")
	}
}

// A user with keys publishes them, and a key that is not one is refused at
// startup rather than dropped: silently ignoring a bad line is how a server
// ends up denying the person it was configured for, with nothing to say why.
func TestKeysArePublishedAndBadOnesRefused(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9Bl6dNhbHqUCLxLLjTe5MDLbLWyWZ9UBjFA+Vx4rJk dora@laptop"
	r := start(t, peopleConfig(t, dir, fmt.Sprintf(`
user "keyed" {
  password        = "x"
  authorized_keys = [%q]
}
`, key)))
	out, err := search(bin, r.url(), "cn=reader,dc=example,dc=org", "let me read",
		"ou=people,dc=example,dc=org", "(uid=keyed)", "uid", "sshPublicKey")
	if err != nil {
		t.Fatalf("ldapsearch: %v\n%s", err, out)
	}
	contains(t, unfold(out), "uid: keyed", "sshPublicKey: "+key)

	dir2 := t.TempDir()
	body := peopleConfig(t, dir2, `
user "keyed" {
  password        = "x"
  authorized_keys = ["ssh-ed25519 this-is-not-a-key dora@laptop"]
}
`)
	cfg, err := loadConfig([]string{write(t, dir2, "c.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if srv != nil {
		srv.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "authorized_keys line") {
		t.Errorf("a key that is not one gave %v", err)
	}
}

// A password read from a file, which is the shape to use: a file has
// permissions and a configuration under version control has none.
func TestPasswordsComeFromFiles(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	pw := write(t, dir, "svc.pw", "from-a-file\n")
	r := start(t, peopleConfig(t, dir, fmt.Sprintf(`
user "filed" { password_file = %q }
`, hclPath(pw))))
	// The trailing newline is not part of the password: a file written by
	// `echo` would otherwise authenticate nobody.
	if out, err := search(bin, r.url(), "uid=filed,ou=people,dc=example,dc=org", "from-a-file",
		"ou=people,dc=example,dc=org", "(uid=filed)"); !strings.Contains(out, "Insufficient access") {
		t.Errorf("the password from the file was refused: %v\n%s", err, out)
	}

	// A file that is not there is a refusal naming it.
	dir2 := t.TempDir()
	body := peopleConfig(t, dir2, `
user "filed" { password_file = "/no/such/password" }
`)
	cfg, err := loadConfig([]string{write(t, dir2, "c.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if srv != nil {
		srv.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "user filed") {
		t.Errorf("a password file that is not there gave %v", err)
	}
}

// The command refuses a configuration it cannot read, and says which one.
func TestTheCommandRefusesWhatItCannotRead(t *testing.T) {
	if out, err := execute(t); err == nil {
		t.Errorf("running with no configuration at all was accepted:\n%s", out)
	}
	if _, err := execute(t, "check", "/no/such/file.hcl"); err == nil {
		t.Error("check accepted a file that is not there")
	}
	if _, err := execute(t, "--config", "/no/such/file.hcl"); err == nil {
		t.Error("serve accepted a file that is not there")
	}
}
