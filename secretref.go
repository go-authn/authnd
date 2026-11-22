// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-authn/secretsource"
)

// secretTimeout bounds the resolution of one reference at startup: a manager
// that waits for somebody to unlock it must not hold the server forever.
const secretTimeout = 30 * time.Second

// secretRef is how a secret is named in the configuration: a go-authn/secretsource
// reference ("systemd-creds:NAME", "file:PATH", "keychain:SERVICE/ACCOUNT", ...).
// A reference never holds the secret, so the configuration file can be read,
// copied and put under version control without it.
//
// password_file = "PATH" is the deprecated spelling of password_from =
// "file:PATH", and `password = "..."` (the secret itself, in the file) is
// deprecated too and logged at startup.
//
// resolveSecret returns the secret as one line: a single trailing newline (what
// echo adds) is not part of it, and a NUL or any other newline is refused.
func resolveSecret(who, field string, inline, file, from string) (string, error) {
	switch {
	case file != "" && from != "":
		return "", fmt.Errorf("%s has both %s_file and %s_from: say which one (%s_file is the deprecated spelling of %s_from = \"file:PATH\")", who, field, field, field, field)
	}
	ref := from
	if file != "" {
		ref = "file:" + file
	}
	if ref == "" {
		return inline, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), secretTimeout)
	defer cancel()
	s, err := secretsource.Open(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("%s: %s_from: %w", who, field, err)
	}
	defer s.Close()
	v := strings.TrimSuffix(strings.TrimSuffix(string(s.Bytes()), "\n"), "\r")
	if v == "" || strings.ContainsAny(v, "\x00\r\n") {
		return "", fmt.Errorf("%s: %s_from: %w", who, field, errors.New("one non-empty line without NUL"))
	}
	return v, nil
}
