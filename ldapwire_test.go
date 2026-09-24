// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-authn/ldap"
)

// upgraded dials plainly, asks for StartTLS by hand, and hands back an LDAP
// connection over the upgraded socket.
//
// ⛔ The exchange is written out here rather than done with the library's own
// StartTLS because that one races its own reader goroutine: it reads the
// socket directly while the pump is reading it too, and the pump panics on
// the packet it half-reads. Doing the upgrade BEFORE anything is pumping
// avoids the race entirely -- and it makes this an independent judge of the
// bytes, which a library's client testing that library's server is not.
func upgraded(t *testing.T, addr string) *ldap.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// An extendedRequest naming the StartTLS OID (RFC 4511 4.14.1).
	req := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(1), "MessageID"))
	ext := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "StartTLS")
	ext.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", "OID"))
	req.AppendChild(ext)
	if _, err := raw.Write(req.Bytes()); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	res, err := ber.ReadPacket(raw)
	if err != nil {
		raw.Close()
		t.Fatalf("reading the StartTLS response: %v", err)
	}
	// resultCode is the first field of the LDAPResult inside the response.
	code, ok := res.Children[1].Children[0].Value.(int64)
	if !ok || ldap.LDAPResultCode(code) != ldap.LDAPResultSuccess {
		raw.Close()
		t.Fatalf("StartTLS was refused: %v", res.Children[1].Children[0].Value)
	}

	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		raw.Close()
		t.Fatalf("the handshake after StartTLS failed: %v", err)
	}
	c := ldap.NewConn(tc)
	c.Start()
	t.Cleanup(c.Close)
	return c
}
