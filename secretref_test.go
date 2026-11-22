package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-authn/secretsource"
)

const readerDN = "cn=reader,dc=example,dc=org"

// secretFile writes a secret readable by its owner alone, the shape file:
// demands.
func secretFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return hclPath(p)
}

// openReader loads a configuration with one reader block and opens it.
func openReader(t *testing.T, readerBody string) (*server, error) {
	t.Helper()
	dir := t.TempDir()
	body := fmt.Sprintf("base_dn = \"dc=example,dc=org\"\nlisten = \"127.0.0.1:0\"\nuser \"svc\" { password = \"x\" }\nreader %q {\n%s\n}\n", readerDN, readerBody)
	cfg, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err != nil {
		return nil, err
	}
	srv, err := open(cfg, &safeBuffer{})
	if srv != nil {
		t.Cleanup(func() { srv.Close() })
	}
	return srv, err
}

func TestReaderPasswordFromResolves(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file: access rules differ")
	}
	dir := t.TempDir()
	pw := secretFile(t, dir, "reader.pw", []byte("let me read\n"))
	srv, err := openReader(t, fmt.Sprintf("password_from = %q", "file:"+pw))
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.readers[strings.ToLower(readerDN)]; got != "let me read" {
		t.Errorf("the reader's password is %q", got)
	}
}

func TestReaderPasswordFileIsTheDeprecatedAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file: access rules differ")
	}
	dir := t.TempDir()
	pw := secretFile(t, dir, "reader.pw", []byte("let me read\n"))
	srv, err := openReader(t, fmt.Sprintf("password_file = %q", pw))
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.readers[strings.ToLower(readerDN)]; got != "let me read" {
		t.Errorf("the alias gave %q", got)
	}
	if out := srv.out.(*safeBuffer).String(); !strings.Contains(out, "password_file is deprecated") {
		t.Errorf("the alias was not flagged as deprecated: %q", out)
	}
}

func TestReaderTwoSpellingsOfOneSecretAreRefused(t *testing.T) {
	for name, body := range map[string]string{
		"from and file":      `password_from = "file:/x"` + "\n" + `password_file = "/x"`,
		"from and inline":    `password_from = "file:/x"` + "\n" + `password = "x"`,
		"file and inline":    `password_file = "/x"` + "\n" + `password = "x"`,
		"totp both":          `password = "x"` + "\n" + `totp_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"` + "\n" + `totp_secret_from = "file:/x"`,
		"no password at all": `totp_secret_from = "file:/x"`,
	} {
		if _, err := openReader(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReaderBadReferencesAreRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file: access rules differ")
	}
	dir := t.TempDir()
	// no scheme: a path is not guessed
	if _, err := openReader(t, fmt.Sprintf("password_from = %q", secretFile(t, dir, "a", []byte("x")))); err == nil {
		t.Error("a reference with no scheme was accepted")
	}
	// oversized
	big := secretFile(t, dir, "big", make([]byte, secretsource.MaxSize+1))
	if _, err := openReader(t, fmt.Sprintf("password_from = %q", "file:"+big)); err == nil || !strings.Contains(err.Error(), "4096") {
		t.Errorf("an oversized secret gave %v", err)
	}
	// two lines
	two := secretFile(t, dir, "two", []byte("a\nb\n"))
	if _, err := openReader(t, fmt.Sprintf("password_from = %q", "file:"+two)); err == nil {
		t.Error("a two-line secret was accepted")
	}
	// loose mode
	loose := filepath.Join(dir, "loose")
	os.WriteFile(loose, []byte("x"), 0o644)
	os.Chmod(loose, 0o644)
	if _, err := openReader(t, fmt.Sprintf("password_from = %q", "file:"+hclPath(loose))); err == nil {
		t.Error("a world-readable secret file was accepted")
	}
}

func TestReaderTOTPSecretFromResolves(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file: access rules differ")
	}
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", []byte("let me read"))
	ts := secretFile(t, dir, "totp", []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\n"))
	srv, err := openReader(t, fmt.Sprintf("password_from = %q\ntotp_secret_from = %q", "file:"+pw, "file:"+ts))
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.readerSecrets[strings.ToLower(readerDN)]) == 0 {
		t.Error("the reader's TOTP secret was not read from its reference")
	}
	short := secretFile(t, dir, "short", []byte("JBSWY3DPEHPK3PXP"))
	if _, err := openReader(t, fmt.Sprintf("password_from = %q\ntotp_secret_from = %q", "file:"+pw, "file:"+short)); err == nil || !strings.Contains(err.Error(), "bits") {
		t.Errorf("a short TOTP secret gave %v", err)
	}
}
