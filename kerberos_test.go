package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// authnd as a KDC, judged by MIT's own kinit and kvno.
//
// No MIT KDC is involved: the keytab is built here in Go and only the CLIENT
// is borrowed. AUTHND_REQUIRE_JUDGE=1 turns "MIT is not installed" from a skip
// into a failure, because a differential test that can quietly not run is not
// a control.

const testRealm = "FLEET.TEST"

func mitAvailable(t *testing.T) {
	t.Helper()
	cmd := exec.Command("pkgx", "+kerberos.org", "--", "klist", "-V")
	if err := cmd.Run(); err != nil {
		if os.Getenv("AUTHND_REQUIRE_JUDGE") != "" {
			t.Fatalf("AUTHND_REQUIRE_JUDGE is set but MIT Kerberos is not usable: %v", err)
		}
		t.Skip("no MIT Kerberos; install pkgx")
	}
}

// writeKeytab builds the keys a realm needs: krbtgt to sign its own tickets,
// and one per service it issues to.
func writeKeytab(t *testing.T, dir string) string {
	t.Helper()
	kt := keytab.New()
	for _, p := range []string{"krbtgt/" + testRealm, "nfs/localhost"} {
		if err := kt.AddEntry(p, testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
			t.Fatal(err)
		}
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "realm.keytab")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// freePort picks one the kernel is not using, for a realm that must be named
// in a krb5.conf before it starts.
func freePort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// krb5Conf points a client at a realm. ⛔ The braces go on their own lines:
// MIT's profile parser silently ignores a realm written on one line, and kinit
// then says "Cannot find KDC for realm" — a message about the realm, from a
// failure about whitespace.
func krb5Conf(t *testing.T, dir string, port int) string {
	t.Helper()
	path := filepath.Join(dir, "krb5.conf")
	body := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
[realms]
    %s = {
        kdc = 127.0.0.1:%d
    }
`, testRealm, testRealm, port)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func kinit(t *testing.T, who, password string) (string, error) {
	t.Helper()
	cmd := exec.Command("pkgx", "+kerberos.org", "--", "kinit", who+"@"+testRealm)
	cmd.Env = os.Environ()
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestAuthndIssuesKerberosTickets(t *testing.T) {
	mitAvailable(t)
	dir := t.TempDir()
	port := freePort(t)
	kt := writeKeytab(t, dir)

	r := start(t, fmt.Sprintf(`
base_dn = "dc=example,dc=org"
user "alice" { password = "alicepw" }
kerberos {
  realm  = %q
  listen = "127.0.0.1:%d"
  keytab = %q
}
`, testRealm, port, kt))
	_ = r

	t.Setenv("KRB5_CONFIG", krb5Conf(t, dir, port))
	t.Setenv("KRB5CCNAME", "FILE:"+filepath.Join(dir, "ccache"))

	if out, err := kinit(t, "alice", "alicepw"); err != nil {
		t.Fatalf("kinit against authnd: %v\n%s\n--- server said:\n%s", err, out, r.out.String())
	}
	out, err := exec.Command("pkgx", "+kerberos.org", "--", "klist").CombinedOutput()
	if err != nil {
		t.Fatalf("klist: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "krbtgt/"+testRealm) {
		t.Fatalf("no TGT in the cache:\n%s", out)
	}

	// And a service ticket, which is the TGS half and never touches the
	// password again.
	out, err = exec.Command("pkgx", "+kerberos.org", "--", "kvno", "nfs/localhost@"+testRealm).CombinedOutput()
	if err != nil {
		t.Fatalf("kvno: %v\n%s\n--- server said:\n%s", err, out, r.out.String())
	}
	t.Logf("authnd served MIT's client: %s", strings.TrimSpace(string(out)))

	// ⛔ The directory did not stop being a directory. A server that traded
	// one for the other would be a different product.
	if !strings.Contains(r.out.String(), "ldap on ") {
		t.Errorf("the LDAP half is not announced:\n%s", r.out.String())
	}
}

func TestAWrongPasswordGetsNoTicket(t *testing.T) {
	mitAvailable(t)
	dir := t.TempDir()
	port := freePort(t)
	r := start(t, fmt.Sprintf(`
base_dn = "dc=example,dc=org"
user "alice" { password = "alicepw" }
kerberos {
  realm  = %q
  listen = "127.0.0.1:%d"
  keytab = %q
}
`, testRealm, port, writeKeytab(t, dir)))
	t.Setenv("KRB5_CONFIG", krb5Conf(t, dir, port))
	t.Setenv("KRB5CCNAME", "FILE:"+filepath.Join(dir, "ccache"))

	out, err := kinit(t, "alice", "not the password")
	if err == nil {
		t.Fatalf("a wrong password was given a ticket:\n%s", out)
	}
	if !strings.Contains(out, "Password incorrect") {
		t.Errorf("kinit said something else:\n%s\n--- server said:\n%s", out, r.out.String())
	}
}

func TestAMisconfiguredRealmIsRefusedAtStartup(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, body, want string
	}{
		{"no realm", "kerberos {\n  keytab = \"/dev/null\"\n}", "no realm"},
		{"a lower-case realm", "kerberos {\n  realm = \"fleet.test\"\n  keytab = \"/dev/null\"\n}", "not upper case"},
		{"no keytab", "kerberos {\n  realm = \"FLEET.TEST\"\n}", "krbtgt"},
		{"a lifetime that is not one", "kerberos {\n  realm = \"FLEET.TEST\"\n  keytab = \"/dev/null\"\n  lifetime = \"half a day\"\n}", "lifetime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "base_dn = \"dc=example,dc=org\"\nuser \"alice\" { password = \"x\" }\n" + tc.body + "\n"
			_, err := loadConfig([]string{write(t, dir, tc.name+".hcl", body)})
			if err == nil {
				t.Fatal("a realm that cannot work was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want something about %q", err, tc.want)
			}
		})
	}
}

func TestAKeytabThatCannotBeReadStopsTheServer(t *testing.T) {
	// ⛔ Not a warning. A server that started without its krbtgt key would
	// accept a kinit and then have nothing to hand back, and the failure
	// would reach a person who cannot fix it.
	dir := t.TempDir()
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", fmt.Sprintf(`
base_dn = "dc=example,dc=org"
user "alice" { password = "x" }
kerberos {
  realm  = %q
  listen = "127.0.0.1:%d"
  keytab = %q
}
`, testRealm, freePort(t), filepath.Join(dir, "absent.keytab")))})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	out := &safeBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer srv.Close()
	if err := srv.listen(); err == nil {
		t.Fatal("a server with an unreadable keytab started")
	} else if !strings.Contains(err.Error(), "keytab") {
		t.Errorf("err = %v, want something about the keytab", err)
	}
}

// ⛔ The report is the product here. Somebody whose source only verifies a
// password cannot be given a Kerberos ticket, EVER, and reading that from
// `authnd check` beats hearing it from a colleague whose correct password is
// reported wrong.
func TestCheckSaysWhoCanNeverGetATicket(t *testing.T) {
	dir := t.TempDir()
	body := fmt.Sprintf(`
base_dn = "dc=example,dc=org"
user "alice" { password = "alicepw" }
user "bob"   { nt_hash  = "8846f7eaee8fb117ad06bdd830b7586c" }
kerberos {
  realm  = %q
  listen = "127.0.0.1:%d"
  keytab = %q
}
`, testRealm, freePort(t), writeKeytab(t, dir))
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	out := &safeBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer srv.Close()

	var report safeBuffer
	kerberosReport(&report, cfg, srv.sorted())
	got := report.String()
	for _, want := range []string{
		"realm " + testRealm,
		"can be issued a ticket: alice",
		"CANNOT, whatever they type: bob",
		"a source that only verifies a password cannot produce one",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not say %q:\n%s", want, got)
		}
	}
	// And a realm everybody can use says nothing about who cannot, rather
	// than printing an empty list.
	if strings.Contains(reportFor(t, dir, true), "CANNOT") {
		t.Error("a realm with nobody excluded still printed the warning")
	}
	// Without a kerberos block there is no realm to report at all.
	var none safeBuffer
	kerberosReport(&none, &config{}, srv.sorted())
	if none.String() != "" {
		t.Errorf("a configuration with no realm reported one:\n%s", none.String())
	}
}

// reportFor builds a realm whose people can all be issued tickets.
func reportFor(t *testing.T, dir string, everybody bool) string {
	t.Helper()
	body := fmt.Sprintf(`
base_dn = "dc=example,dc=org"
user "alice" { password = "alicepw" }
kerberos {
  realm  = %q
  listen = "127.0.0.1:%d"
  keytab = %q
}
`, testRealm, freePort(t), writeKeytab(t, dir))
	cfg, err := loadConfig([]string{write(t, dir, "all.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	var b safeBuffer
	kerberosReport(&b, cfg, srv.sorted())
	return b.String()
}

// A realm whose address is already taken fails to LISTEN rather than starting
// half-up: the directory must not answer while the KDC silently does not.
func TestARealmThatCannotBindStopsTheServer(t *testing.T) {
	dir := t.TempDir()
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := taken.LocalAddr().(*net.UDPAddr).Port

	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", fmt.Sprintf(`
base_dn = "dc=example,dc=org"
user "alice" { password = "x" }
kerberos {
  realm  = %q
  listen = "127.0.0.1:%d"
  keytab = %q
}
`, testRealm, port, writeKeytab(t, dir)))})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer srv.Close()
	if err := srv.listen(); err == nil {
		t.Fatal("a realm whose port was taken started anyway")
	} else if !strings.Contains(err.Error(), "kerberos udp") {
		t.Errorf("err = %v, want something naming the kerberos socket", err)
	}
}
