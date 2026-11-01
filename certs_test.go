// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #68 (c): the certificate is read again when its files change.
//
// Bibliography: crypto/tls Config.GetCertificate (called per ClientHello when
// Certificates is empty); the shape of a renewal is certbot's and lego's:
// write the new files beside the old and rename them over, key and certificate
// one after the other.

// pairPEM is a certificate with this serial and its key, as PEM.
func pairPEM(t testing.TB, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw})
}

// renameOver puts content at path by renaming a new file over it, which is what a
// renewer does: a new inode.
func renameOver(t testing.TB, path string, content []byte) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// serialServed is the serial of the certificate a handshake receives.
func serialServed(t testing.TB, addr string) int64 {
	t.Helper()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func tlsServer(t *testing.T) (r *running, certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	c, k := pairPEM(t, 1)
	renameOver(t, certPath, c)
	renameOver(t, keyPath, k)
	r = start(t, networkConfig+fmt.Sprintf("\ncert_file = %q\nkey_file = %q\n", hclPath(certPath), hclPath(keyPath)))
	return r, certPath, keyPath
}

func recheckEvery(r *running, d time.Duration) {
	r.srv.certs.mu.Lock()
	r.srv.certs.recheck = d
	r.srv.certs.mu.Unlock()
}

func TestCertificateIsReloadedWhenItsFilesChange(t *testing.T) {
	r, certPath, keyPath := tlsServer(t)
	if got := serialServed(t, r.addr); got != 1 {
		t.Fatalf("first certificate: serial %d", got)
	}

	// Control: with a recheck far away, a replaced pair is NOT seen. The test
	// can tell "reloaded" from "never looked".
	recheckEvery(r, time.Hour)
	c2, k2 := pairPEM(t, 2)
	renameOver(t, certPath, c2)
	renameOver(t, keyPath, k2)
	if got := serialServed(t, r.addr); got != 1 {
		t.Fatalf("the files were read before the recheck was due: serial %d", got)
	}

	// Due: the next handshake serves the renewed certificate.
	recheckEvery(r, 0)
	if got := serialServed(t, r.addr); got != 2 {
		t.Fatalf("renewed certificate not served: serial %d", got)
	}
	if !strings.Contains(r.out.String(), "certificate reloaded from") {
		t.Errorf("the reload was not logged:\n%s", r.out.String())
	}

	// A renewer that has replaced the certificate and not yet the key: the
	// pair does not match, the old one stays, and the failure is said once.
	c3, k3 := pairPEM(t, 3)
	renameOver(t, certPath, c3)
	for range 3 {
		if got := serialServed(t, r.addr); got != 2 {
			t.Fatalf("half a renewal changed the served certificate: serial %d", got)
		}
	}
	if n := strings.Count(r.out.String(), "certificate not reloaded"); n != 1 {
		t.Errorf("a failure state was logged %d times, want once:\n%s", n, r.out.String())
	}
	// The key arrives: the pair is complete and served.
	renameOver(t, keyPath, k3)
	if got := serialServed(t, r.addr); got != 3 {
		t.Fatalf("completed renewal not served: serial %d", got)
	}
}

// Chaos: a certificate replaced with garbage keeps the old one serving, in
// both files, and a later good one is picked up.
func TestChaosCertificateReplacedWithGarbage(t *testing.T) {
	r, certPath, keyPath := tlsServer(t)
	recheckEvery(r, 0)
	for name, content := range map[string][]byte{
		"garbage": []byte("not a certificate\n"),
		"empty":   {},
		"binary":  {0, 1, 2, 0xff, 0xfe},
	} {
		renameOver(t, certPath, content)
		renameOver(t, keyPath, content)
		for range 3 {
			if got := serialServed(t, r.addr); got != 1 {
				t.Fatalf("%s: the server stopped serving the good certificate (serial %d)", name, got)
			}
		}
	}
	// Removed altogether (a renewer between rm and mv).
	os.Remove(certPath)
	os.Remove(keyPath)
	if got := serialServed(t, r.addr); got != 1 {
		t.Fatalf("files removed: serial %d", got)
	}
	// And the server still reloads once good files are back.
	c, k := pairPEM(t, 9)
	renameOver(t, certPath, c)
	renameOver(t, keyPath, k)
	if got := serialServed(t, r.addr); got != 9 {
		t.Fatalf("recovery: serial %d", got)
	}
	if strings.Contains(r.out.String(), "BEGIN") || strings.Contains(r.out.String(), "PRIVATE") {
		t.Errorf("key material in the log:\n%s", r.out.String())
	}
}

// A renewed pair of the same size, rewritten in place with the old modification
// time restored, is what a stat-based identity (size, mtime, inode) cannot see.
func TestCertificateReloadSeesAnUnchangedStat(t *testing.T) {
	r, certPath, keyPath := tlsServer(t)
	recheckEvery(r, 0)
	old, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	fk, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var c2, k2 []byte
	for range 500 { // ECDSA signatures vary by a byte or two: draw until the size matches
		c2, k2 = pairPEM(t, 2)
		if len(c2) == len(old) && len(k2) == len(oldKey) {
			break
		}
	}
	if len(c2) != len(old) || len(k2) != len(oldKey) {
		t.Skip("could not draw a pair of the same size")
	}
	if err := os.WriteFile(certPath, c2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, k2, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(certPath, fi.ModTime(), fi.ModTime())
	_ = os.Chtimes(keyPath, fk.ModTime(), fk.ModTime())
	if got := serialServed(t, r.addr); got != 2 {
		t.Fatalf("a rewritten pair with the same size and time was not served: serial %d", got)
	}
}

// A clock that reads earlier than the last look (stepped back; threads of an
// emulated CPU disagreeing) is not "checked recently": the files are looked at.
// Seen once on s390x under qemu, where recheck was 0 and elapsed was negative.
func TestCertificateRecheckSurvivesAClockStepBack(t *testing.T) {
	r, certPath, keyPath := tlsServer(t)
	r.srv.certs.mu.Lock()
	back := r.srv.certs.checked.Add(-time.Second)
	r.srv.certs.now = func() time.Time { return back }
	r.srv.certs.recheck = 0
	r.srv.certs.mu.Unlock()
	c2, k2 := pairPEM(t, 2)
	renameOver(t, certPath, c2)
	renameOver(t, keyPath, k2)
	if got := serialServed(t, r.addr); got != 2 {
		t.Fatalf("with the clock behind the last look, serial %d", got)
	}
}

// SIGHUP's hook reads the files now, whatever the recheck period.
func TestReloadCertOnDemand(t *testing.T) {
	r, certPath, keyPath := tlsServer(t)
	recheckEvery(r, time.Hour)
	c2, k2 := pairPEM(t, 2)
	renameOver(t, certPath, c2)
	renameOver(t, keyPath, k2)
	if got := serialServed(t, r.addr); got != 1 {
		t.Fatalf("serial %d before the signal", got)
	}
	r.srv.reloadCert()
	if got := serialServed(t, r.addr); got != 2 {
		t.Fatalf("serial %d after the signal", got)
	}
	// A bad pair on demand is logged every time it is asked for, and refused.
	renameOver(t, certPath, []byte("junk"))
	r.srv.reloadCert()
	if got := serialServed(t, r.addr); got != 2 {
		t.Fatalf("serial %d after a bad reload", got)
	}
	if !strings.Contains(r.out.String(), "certificate not reloaded, still serving the previous one") {
		t.Errorf("the refusal was not logged:\n%s", r.out.String())
	}
	(&server{}).reloadCert() // no TLS: nothing to do, no panic
}

// StartTLS serves the same store.
func TestStartTLSUsesTheReloadedCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	c, k := pairPEM(t, 1)
	renameOver(t, certPath, c)
	renameOver(t, keyPath, k)
	r := start(t, networkConfig+fmt.Sprintf("\ncert_file = %q\nkey_file = %q\nstarttls = true\n", hclPath(certPath), hclPath(keyPath)))
	recheckEvery(r, 0)
	c2, k2 := pairPEM(t, 2)
	renameOver(t, certPath, c2)
	renameOver(t, keyPath, k2)
	cl := upgradedWith(t, r)
	if cl != 2 {
		t.Errorf("StartTLS served serial %d, want 2", cl)
	}
}

func upgradedWith(t *testing.T, r *running) int64 {
	t.Helper()
	var serial int64
	cfg := &tls.Config{InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		serial = cs.PeerCertificates[0].SerialNumber.Int64()
		return nil
	}}
	c := client(t, r)
	if res, err := c.StartTLS(cfg); err != nil || !res.Code.OK() {
		t.Fatalf("StartTLS: %v %v", res.Code, err)
	}
	return serial
}
