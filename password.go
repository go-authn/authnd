// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// ⛔ The writing half of this file moved to go-authn/directory/hcldir, which
// owns the `user` block it edits. It lived here first, which was the mistake
// that package exists to prevent: the block already lived twice, in this
// server and in go-fileshare/fileshare, and had already drifted once.
//
// The move is not a copy. hcldir RECOMPUTES an nt_hash beside a password, a
// branch this server can never reach because config.go refuses a block
// carrying both -- and fileshare, which hcldir also serves, allows it.

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
