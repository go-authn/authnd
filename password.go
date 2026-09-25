// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// errNotOurs is somebody this configuration does not declare.
//
// ⛔ It is NOT "no such person". A name that reaches here may exist perfectly
// well in a sql or ldap directory this server also serves; what it does not
// have is a sentence in a file we own. Saying "no such person" would be a
// different claim, and a wrong one.
var errNotOurs = errors.New("not written down in this configuration")

// setPassword writes a new password for somebody declared in a user block.
//
// ⛔ The parsed configuration cannot do this. It says alice has a password; it
// does not say which of five files holds the sentence, nor whether that
// sentence is `password` or `password_file`. So this re-parses the files with
// hclwrite -- which keeps comments, ordering and spacing that a re-render from
// the struct would quietly discard -- and edits the one block it finds.
func (c *config) setPassword(name, password string) error {
	if password == "" {
		return errors.New("an empty password would let anybody in as this person")
	}
	for _, path := range c.files {
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		f, diags := hclwrite.ParseConfig(src, path, hcl.InitialPos)
		if diags.HasErrors() {
			return fmt.Errorf("%s: %s", path, diags.Error())
		}
		blk := userBlockIn(f, name)
		if blk == nil {
			continue
		}
		return writePassword(path, f, blk, name, password)
	}
	return fmt.Errorf("user %q: %w", name, errNotOurs)
}

// attrString is the literal string an attribute is set to.
//
// hclwrite does not evaluate: it hands back tokens. A password_file written as
// a plain quoted string is the case that matters, and anything else -- an
// interpolation, a variable -- is refused rather than guessed at, because
// writing to a path we mis-read is writing to the wrong file.
func attrString(a *hclwrite.Attribute) (string, error) {
	toks := a.Expr().BuildTokens(nil)
	if len(toks) != 3 ||
		toks[0].Type != hclsyntax.TokenOQuote ||
		toks[1].Type != hclsyntax.TokenQuotedLit ||
		toks[2].Type != hclsyntax.TokenCQuote {
		return "", errors.New("is not a plain quoted path, so it is not safe to write through")
	}
	return string(toks[1].Bytes), nil
}

// userBlockIn is the `user "<name>"` block in this file, or nil.
func userBlockIn(f *hclwrite.File, name string) *hclwrite.Block {
	for _, blk := range f.Body().Blocks() {
		if blk.Type() != "user" {
			continue
		}
		labels := blk.Labels()
		if len(labels) == 1 && labels[0] == name {
			return blk
		}
	}
	return nil
}

// writePassword puts the password where THAT person's block keeps it.
func writePassword(path string, f *hclwrite.File, blk *hclwrite.Block, name, password string) error {
	body := blk.Body()
	hasFile := body.GetAttribute("password_file") != nil
	hasInline := body.GetAttribute("password") != nil
	hasHash := body.GetAttribute("nt_hash") != nil // only ever WITHOUT a password

	// ⛔ A person holding only an nt_hash cannot be given a password here
	// without changing WHAT PROVES THEM: the block would start answering S3
	// and WebDAV, which it could not before. That is a decision for whoever
	// wrote the configuration, not for a bind that only asked to change a
	// password.
	if !hasFile && !hasInline && hasHash {
		return fmt.Errorf("user %q holds an nt_hash and no password: "+
			"setting one here would change what can prove them, which is a "+
			"change to the configuration rather than to a password", name)
	}
	if !hasFile && !hasInline {
		return fmt.Errorf("user %q: %w", name, errNotOurs)
	}

	// ⛔ There is no nt_hash to keep in step here, and that is a rule rather
	// than an assumption: config.go:269 refuses a user block that carries
	// both a password and an nt_hash, because "the hash is derived from the
	// password, so two of them can disagree". A first draft of this function
	// recomputed the hash beside the password -- careful, plausible, and
	// UNREACHABLE, since such a block never starts the server. Code that
	// cannot run reads like a guarantee and is not one.

	if hasFile {
		// The password lives in a file on purpose -- so that it is not in a
		// configuration somebody prints, pastes or commits. Writing it inline
		// now would undo that silently, so the file is what changes.
		v, err := attrString(body.GetAttribute("password_file"))
		if err != nil {
			return fmt.Errorf("user %q: password_file: %w", name, err)
		}
		return replaceFile(v, []byte(password+"\n"), 0o600)
	}
	body.SetAttributeValue("password", cty.StringVal(password))
	return replaceFile(path, f.Bytes(), 0o644)
}

// replaceFile writes content where path is, atomically.
//
// ⛔ Through a temporary file in the SAME directory and a rename, because the
// alternative loses somebody's password on a full disk or a crash: a truncate
// that then fails to write leaves a file that exists, parses, and locks the
// person out. A rename either happened or did not.
func replaceFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".authnd-*")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("%s: %w", name, err)
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return os.Rename(name, path)
}

// The RFC 3062 password modify request, which is what ldappasswd sends.
//
//	PasswdModifyRequestValue ::= SEQUENCE {
//	  userIdentity [0] OCTET STRING OPTIONAL
//	  oldPasswd    [1] OCTET STRING OPTIONAL
//	  newPasswd    [2] OCTET STRING OPTIONAL }
const (
	tagUserIdentity = 0
	tagOldPasswd    = 1
	tagNewPasswd    = 2
)

// passwdModify is a decoded RFC 3062 request. Every field is optional in the
// specification, so "absent" and "empty" are different and both are answers.
type passwdModify struct {
	identity, old, new string
	haveIdentity       bool
}

// decodePasswdModify reads the request value.
//
// ⛔ The fields are context-tagged PRIMITIVES, and asn1-ber leaves their
// octets in Data rather than in ByteValue -- ByteValue is filled for the
// universal types it knows how to interpret, and [0] OCTET STRING is not one.
// Reading ByteValue here gives an empty string for a password that is
// present, which reads as "no new password given" and refuses a request that
// was perfectly well formed.
func decodePasswdModify(value []byte) (passwdModify, error) {
	var req passwdModify
	if len(value) == 0 {
		return req, nil // every field optional, so an empty value is legal
	}
	pkt, err := ber.DecodePacketErr(value)
	if err != nil {
		return req, fmt.Errorf("the request value is not BER: %w", err)
	}
	if pkt.ClassType != ber.ClassUniversal || pkt.TagType != ber.TypeConstructed ||
		pkt.Tag != ber.TagSequence {
		return req, errors.New("the request value is not a SEQUENCE")
	}
	for _, child := range pkt.Children {
		if child.ClassType != ber.ClassContext {
			return req, errors.New("a field is not context-tagged")
		}
		s := string(child.Data.Bytes())
		switch child.Tag {
		case tagUserIdentity:
			req.identity, req.haveIdentity = s, true
		case tagOldPasswd:
			req.old = s
		case tagNewPasswd:
			req.new = s
		default:
			return req, fmt.Errorf("the request has a field [%d] this does not know", child.Tag)
		}
	}
	return req, nil
}
