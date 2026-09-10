// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// A config is one HCL file, or a directory of them read as one.
//
// A directory of small files is a deployment shape, not a convenience: the
// people can come from one file managed by configuration management and the
// listener from another managed by hand, and neither has to know about the
// other.
type config struct {
	// Listen is where to answer. The default is loopback, because a
	// directory that appears on every interface the moment it starts is a
	// decision somebody should make on purpose.
	Listen string `hcl:"listen,optional"`
	// BaseDN is the root of what this server publishes. People are under
	// ou=people, groups under ou=groups.
	BaseDN string `hcl:"base_dn,optional"`

	// CertFile and KeyFile turn on TLS: ldaps:// on the listener, and
	// StartTLS on a plaintext connection.
	CertFile string `hcl:"cert_file,optional"`
	KeyFile  string `hcl:"key_file,optional"`

	// PublishNTHash publishes sambaNTPassword for the people whose source
	// holds one. It is what lets a Samba or an SMB server authenticate
	// through this directory -- and it is a CREDENTIAL, so it needs TLS or a
	// listener that is not on the network.
	PublishNTHash bool `hcl:"publish_nt_hash,optional"`

	// MFA, when present, is what a person's bind must carry beyond a password.
	MFA *mfaBlock `hcl:"mfa,block"`

	Readers     []readerBlock  `hcl:"reader,block"`
	Users       []userBlock    `hcl:"user,block"`
	Groups      []groupBlock   `hcl:"group,block"`
	Directories []hcldir.Block `hcl:"users,block"`
}

// An mfaBlock asks for more than a password at a bind.
//
// LDAP's simple bind carries one field, so the code goes on the END of the
// password -- "hunter2314159" -- which is what every appliance doing this
// does. There is nowhere else to put it: no round trip, no extra field, and a
// client that speaks LDAP will not learn one.
type mfaBlock struct {
	// Factors is how many must be satisfied. 2 is the point of the block;
	// 1 means a password alone and is refused as a configuration that says
	// something it does not mean.
	Factors int `hcl:"factors,optional"`
	// DistinctKinds requires them to be of different kinds -- what
	// "two-factor" is normally taken to mean, and what stops two things a
	// person KNOWS from counting as two.
	DistinctKinds bool `hcl:"distinct_kinds,optional"`
	// Digits is how many digits the codes have. 0 means 6.
	Digits int `hcl:"digits,optional"`
	// Period is how many seconds one code lasts. 0 means 30.
	Period int `hcl:"period,optional"`
	// Window is how many steps either side of now are accepted, for clocks
	// that differ. 0 means 1 -- and each step is a step of somebody else's
	// guessing time, so it is a number to set deliberately.
	Window int `hcl:"window,optional"`
	// Readers says whether the reader accounts must carry a code too. They
	// are service accounts with no phone, so they do not by default -- and a
	// site that gives one an authenticator can say so.
	Readers bool `hcl:"readers,optional"`
}

// A readerBlock is a service account that may SEARCH.
//
// Binding proves who you are; it does not entitle you to read everybody. A
// site's people are a list worth having, and a directory that hands it to
// anybody who can bind has published it.
type readerBlock struct {
	// DN is the bind DN, spelled as the client will write it.
	DN           string `hcl:"dn,label"`
	Password     string `hcl:"password,optional"`
	PasswordFile string `hcl:"password_file,optional"`
	// TOTPSecret is a one-time-code secret in base32, for a service account
	// that carries one. Only asked for when the mfa block says readers do.
	TOTPSecret string `hcl:"totp_secret,optional"`
}

// A userBlock is somebody written down here rather than in a directory: a
// service account, or a small site's whole list.
type userBlock struct {
	Name         string `hcl:"name,label"`
	Password     string `hcl:"password,optional"`
	PasswordFile string `hcl:"password_file,optional"`
	// NTHash is MD4(UTF16LE(password)), in the 32 hex characters a directory
	// publishes it as -- for a site that holds THAT and not the password.
	NTHash string `hcl:"nt_hash,optional"`
	// TOTPSecret is the base32 secret behind this person's one-time codes.
	// ⛔ It IS the second factor: whoever holds it produces every future code.
	TOTPSecret string `hcl:"totp_secret,optional"`
	// AuthorizedKeys are published as sshPublicKey, for whatever reads them.
	AuthorizedKeys     []string `hcl:"authorized_keys,optional"`
	AuthorizedKeysFile string   `hcl:"authorized_keys_file,optional"`
}

// A groupBlock names people, and is published as a posixGroup.
type groupBlock struct {
	Name    string   `hcl:"name,label"`
	Members []string `hcl:"members"`
}

// loadConfig reads the files and checks what can be checked without opening
// anything: a refusal at startup is worth ten at the first login.
func loadConfig(paths []string) (*config, error) {
	files, err := hclFiles(paths)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no configuration: give a .hcl file or a directory of them")
	}
	parser := hclparse.NewParser()
	var bodies []hcl.Body
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		file, diags := parser.ParseHCL(src, f)
		if diags.HasErrors() {
			return nil, diags
		}
		bodies = append(bodies, file.Body)
	}
	cfg := &config{}
	if diags := gohcl.DecodeBody(hcl.MergeBodies(bodies), nil, cfg); diags.HasErrors() {
		return nil, diags
	}
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// hclFiles is the files named, with a directory read as the .hcl files in it,
// sorted so that two runs read them in the same order.
func hclFiles(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		matches, err := filepath.Glob(filepath.Join(p, "*.hcl"))
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("%s has no .hcl files in it", p)
		}
		out = append(out, matches...)
	}
	return out, nil
}

// check refuses what cannot work, before anything is opened or listened on.
func (c *config) check() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:3893"
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %q is not an address to listen on: %w", c.Listen, err)
	}
	if c.BaseDN == "" {
		return fmt.Errorf("no base_dn: a directory has to say where it is (for example dc=example,dc=org)")
	}
	if !strings.Contains(c.BaseDN, "=") {
		return fmt.Errorf("base_dn %q is not a DN: it is written like dc=example,dc=org", c.BaseDN)
	}

	if (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf("cert_file and key_file go together: one without the other serves nothing")
	}
	// ⛔ sambaNTPassword is a CREDENTIAL, not a password hash in the sense a
	// login form means it: whoever holds it authenticates as that person over
	// NTLMv2 without ever learning the password. Publishing it over a
	// plaintext socket puts it on the wire for anybody watching, so it takes
	// TLS -- or a listener that is not on the network at all.
	if c.PublishNTHash && !c.tls() && !loopback(c.Listen) {
		return fmt.Errorf("publish_nt_hash needs cert_file and key_file: an NT hash IS the credential, "+
			"and %s is not loopback, so it would cross a network in the clear", c.Listen)
	}

	seen := map[string]bool{}
	for _, r := range c.Readers {
		if !strings.Contains(r.DN, "=") {
			return fmt.Errorf("reader %q is not a DN: it is written like cn=reader,%s", r.DN, c.BaseDN)
		}
		if seen[strings.ToLower(r.DN)] {
			return fmt.Errorf("reader %q is defined twice", r.DN)
		}
		seen[strings.ToLower(r.DN)] = true
		switch {
		case r.Password != "" && r.PasswordFile != "":
			return fmt.Errorf("reader %q has both a password and a password_file: say which one", r.DN)
		case r.Password == "" && r.PasswordFile == "":
			return fmt.Errorf("reader %q has no password: a reader that proves nothing is anonymous search "+
				"with extra steps", r.DN)
		}
	}

	people := map[string]bool{}
	for _, u := range c.Users {
		if people[u.Name] {
			return fmt.Errorf("user %q is defined twice", u.Name)
		}
		people[u.Name] = true
		switch {
		case u.Password != "" && u.PasswordFile != "":
			return fmt.Errorf("user %q has both a password and a password_file: say which one", u.Name)
		case u.Password != "" && u.NTHash != "":
			return fmt.Errorf("user %q has both a password and an nt_hash: the hash is derived from the password, "+
				"so two of them can disagree", u.Name)
		case len(u.AuthorizedKeys) > 0 && u.AuthorizedKeysFile != "":
			return fmt.Errorf("user %q has both authorized_keys and an authorized_keys_file: say which one", u.Name)
		}
		if u.NTHash != "" {
			if _, err := directory.ParseNTHash(u.NTHash); err != nil {
				return fmt.Errorf("user %q: %w", u.Name, err)
			}
		}
		if u.TOTPSecret != "" {
			if _, err := directory.ParseTOTPSecret(u.TOTPSecret); err != nil {
				return fmt.Errorf("user %q: %w", u.Name, err)
			}
		}
	}

	groups := map[string]bool{}
	for _, g := range c.Groups {
		if groups[g.Name] {
			return fmt.Errorf("group %q is defined twice", g.Name)
		}
		groups[g.Name] = true
		if len(g.Members) == 0 {
			// A group with nobody in it grants nothing, and a configuration
			// that grants nothing to nobody reads exactly like one that works.
			return fmt.Errorf("group %q has no members", g.Name)
		}
	}

	if m := c.MFA; m != nil {
		switch {
		case m.Factors == 1:
			return fmt.Errorf("mfa { factors = 1 } is a password and nothing else: remove the block, or ask for 2")
		case m.Factors < 0:
			return fmt.Errorf("mfa { factors = %d } accepts anyone", m.Factors)
		case m.Factors > 2:
			// There are two things an LDAP bind can carry, and no third.
			return fmt.Errorf("mfa { factors = %d }: a bind carries a password and a code, which is 2", m.Factors)
		case m.Digits != 0 && (m.Digits < 6 || m.Digits > 10):
			return fmt.Errorf("mfa { digits = %d }: RFC 4226 allows 6 to 10", m.Digits)
		case m.Period < 0 || m.Window < 0:
			return fmt.Errorf("mfa: a period of %d seconds and a window of %d steps", m.Period, m.Window)
		}
	}

	for _, b := range c.Directories {
		if err := b.Check(); err != nil {
			return err
		}
	}
	if len(c.Users) == 0 && len(c.Directories) == 0 {
		return fmt.Errorf("there is nobody here: name a user, or a users block reading a database or a directory")
	}
	return nil
}

// tls reports whether this server can be spoken to over TLS.
func (c *config) tls() bool { return c.CertFile != "" && c.KeyFile != "" }

// loopback reports whether an address is one nothing else on the network can
// reach -- the one case where a credential may cross a socket in the clear,
// because it never leaves the machine.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// secret reads a password from a file, or takes the one written inline.
//
// Inline is allowed and file is the shape to use: a file has permissions, and
// a configuration under version control has none.
func secret(inline, file, who string) (string, error) {
	if file == "" {
		return inline, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("%s: %w", who, err)
	}
	return strings.TrimSpace(string(raw)), nil
}
