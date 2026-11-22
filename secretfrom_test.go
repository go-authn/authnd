// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A totp_secret_from is resolved by hcldir.File, so the 128-bit rule that
// loadConfig applies to an inline totp_secret has to be applied to it too: a
// short secret behind a reference stopped nothing.
func TestAShortTOTPSecretFromAReferenceIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file: wants an access list this test does not make")
	}
	dir := t.TempDir()
	for name, c := range map[string]struct{ secret, want string }{
		"80 bits":  {"JBSWY3DPEHPK3PXP", "128"},
		"128 bits": {"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", ""},
	} {
		t.Run(name, func(t *testing.T) {
			pw := filepath.Join(dir, "pw-"+name)
			ts := filepath.Join(dir, "ts-"+name)
			for p, body := range map[string]string{pw: "s3cret\n", ts: c.secret + "\n"} {
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &config{Users: []userBlock{{Name: "alice", PasswordFrom: "file:" + pw, TOTPSecretFrom: "file:" + ts}}}
			_, err := localSource(cfg)
			switch {
			case c.want == "" && err != nil:
				t.Errorf("a long enough secret was refused: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), `"alice"`)):
				t.Errorf("a short secret gave %v, want a refusal naming alice and %s", err, c.want)
			}
		})
	}
}
