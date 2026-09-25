package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TLS, judged twice: by an LDAP client and by a TLS one.
//
// It matters twice over: it is what a bind password crosses when this server
// is not on loopback, and it is the condition under which publishing an NT
// hash is defensible at all. A test that only ever spoke plaintext would be
// measuring the easy half.
//
// The two judges are split on purpose, because neither can do the other's job
// here:
//
//   - OpenLDAP's ldapsearch speaks ldaps:// to this server and comes back with
//     the entries, which is what proves the LDAP conversation happens over
//     TLS. macOS's ldapsearch trusts the SYSTEM store and ignores
//     LDAPTLS_CACERT, so it cannot be told to trust a certificate made for
//     one test -- measured, not assumed: with REQCERT=demand it refuses this
//     server while Go and OpenSSL both verify the very same certificate.
//   - openssl s_client -CAfile -verify_return_error verifies the chain, which
//     is the half ldapsearch had to be told to skip.
func TestOpenLDAPOverTLS(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	body := peopleConfig(t, dir, fmt.Sprintf(`
publish_nt_hash = true
cert_file = %q
key_file  = %q
`, hclPath(cert), hclPath(key)))
	r := start(t, body)

	cmd := exec.Command(bin, "-x", "-H", "ldaps://"+r.addr,
		"-D", "cn=reader,dc=example,dc=org", "-w", "let me read",
		"-b", "ou=people,dc=example,dc=org", "(uid=dora)", "uid", "sambaNTPassword")
	cmd.Env = append(os.Environ(), "LDAPTLS_CACERT="+cert, "LDAPTLS_REQCERT=allow")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch over ldaps: %v\n%s", err, out)
	}
	contains(t, string(out), "uid: dora", "sambaNTPassword: "+hunter2NTHash, "result: 0 Success")

	// The chain, by something whose whole job is checking chains.
	if openssl, err := exec.LookPath("openssl"); err == nil {
		out, err := exec.Command(openssl, "s_client", "-connect", r.addr,
			"-CAfile", cert, "-verify_return_error", "-brief").CombinedOutput()
		if err != nil {
			t.Errorf("openssl could not verify this server: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "Verification: OK") {
			t.Errorf("openssl did not verify the certificate:\n%s", out)
		}
	}
}

// A TLS listener still refuses the things a plaintext one refuses: the
// transport is not the authorisation.
func TestTLSDoesNotChangeWhoMaySearch(t *testing.T) {
	bin := needLDAPSearch(t)
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	r := start(t, peopleConfig(t, dir, fmt.Sprintf("\ncert_file = %q\nkey_file  = %q\n", hclPath(cert), hclPath(key))))

	run := func(dn, password string) (string, error) {
		cmd := exec.Command(bin, "-x", "-H", "ldaps://"+r.addr, "-D", dn, "-w", password,
			"-b", "ou=people,dc=example,dc=org", "(objectClass=posixAccount)", "uid")
		cmd.Env = append(os.Environ(), "LDAPTLS_REQCERT=allow")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// The unauthenticated bind is refused over TLS as it is in the clear,
	// and with unwillingToPerform (RFC 4513 5.1.2) rather than
	// invalidCredentials: the transport does not change which refusal is
	// true.
	if out, err := run("uid=svc,ou=people,dc=example,dc=org", ""); err == nil {
		t.Errorf("an empty password was accepted over TLS:\n%s", out)
	} else if !strings.Contains(out, "unwilling to perform (53)") {
		t.Errorf("the empty password gave:\n%s", out)
	}
	if out, err := run("uid=svc,ou=people,dc=example,dc=org", "service"); err == nil {
		t.Errorf("svc searched over TLS, and only a reader may search:\n%s", out)
	}
	if _, err := run("cn=reader,dc=example,dc=org", "let me read"); err != nil {
		t.Errorf("the reader could not search over TLS: %v", err)
	}
}

// A certificate that is not one is a refusal at startup, naming the file.
func TestACertificateThatIsNotOne(t *testing.T) {
	dir := t.TempDir()
	body := peopleConfig(t, dir, fmt.Sprintf(`
cert_file = %q
key_file  = %q
`, hclPath(write(t, dir, "cert.pem", "not a certificate\n")),
		hclPath(write(t, dir, "key.pem", "not a key\n"))))
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if err := srv.listen(); err == nil {
		t.Error("a server listened with a certificate that is not one")
	} else if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("the refusal reads %q", err)
	}
}

// selfSigned writes a certificate and its key, and returns the two paths.
func selfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = write(t, dir, "cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	raw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = write(t, dir, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw})))
	return certPath, keyPath
}
