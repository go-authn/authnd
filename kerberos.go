// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io"
	"net"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// realm is the KDC half of this server, present only when the configuration
// asks for one.
type realm struct {
	srv *kdc.Server
	pc  net.PacketConn
	ln  net.Listener
	cfg *kerberosBlock
}

// openRealm builds the KDC, or reports why this configuration cannot have one.
//
// It is deliberately strict about the directory. A realm that starts and then
// cannot derive a key for anybody is worse than one that refuses: the failure
// surfaces as "password incorrect" to every user, at a moment nobody is
// watching the server.
func (s *server) openRealm() (*realm, error) {
	k := s.cfg.Kerberos
	if k == nil {
		return nil, nil
	}
	kt, err := keytab.Load(k.Keytab)
	if err != nil {
		return nil, fmt.Errorf("kerberos keytab %s: %w", k.Keytab, err)
	}
	srv, err := kdc.New(kdc.Config{
		Realm:    k.Realm,
		People:   s.dir,
		Services: kt,
		Lifetime: k.lifetime(),
		Logf:     func(format string, a ...any) { fmt.Fprintf(s.out, "kerberos: "+format+"\n", a...) },
	})
	if err != nil {
		return nil, err
	}
	return &realm{srv: srv, cfg: k}, nil
}

// listen binds the realm's two sockets. Kerberos answers on UDP and TCP both:
// a client tries UDP first and falls back when the reply does not fit.
func (r *realm) listen() error {
	pc, err := net.ListenPacket("udp", r.cfg.Listen)
	if err != nil {
		return fmt.Errorf("kerberos udp %s: %w", r.cfg.Listen, err)
	}
	ln, err := net.Listen("tcp", r.cfg.Listen)
	if err != nil {
		pc.Close()
		return fmt.Errorf("kerberos tcp %s: %w", r.cfg.Listen, err)
	}
	r.pc, r.ln = pc, ln
	return nil
}

// serve answers until Close. The two transports are equals: neither ending is
// a reason to stop the other, so the first error wins and Close takes the rest
// down.
func (r *realm) serve() <-chan error {
	done := make(chan error, 2)
	go func() { done <- r.srv.ServeUDP(r.pc) }()
	go func() { done <- r.srv.ServeTCP(r.ln) }()
	return done
}

func (r *realm) close() {
	if r == nil {
		return
	}
	r.srv.Close()
}

// kerberosReport says who this realm could issue a ticket to, and who it
// could not.
//
// ⛔ The second list is the point. A person whose source only VERIFIES a
// password cannot be given a Kerberos ticket, ever, and finding that out from
// `authnd check` beats finding it out from somebody whose kinit says their
// correct password is wrong.
func kerberosReport(out io.Writer, cfg *config, ids []*directory.Identity) {
	if cfg.Kerberos == nil {
		return
	}
	var can, cannot []string
	for _, id := range ids {
		if id.Can(directory.Password) {
			can = append(can, id.Name())
		} else {
			cannot = append(cannot, id.Name())
		}
	}
	fmt.Fprintf(out, "\nrealm %s on %s (udp and tcp), keytab %s\n",
		cfg.Kerberos.Realm, cfg.Kerberos.Listen, cfg.Kerberos.Keytab)
	fmt.Fprintf(out, "  can be issued a ticket: %s\n", list(can))
	if len(cannot) > 0 {
		fmt.Fprintf(out, "  CANNOT, whatever they type: %s\n", list(cannot))
		fmt.Fprintln(out, "  a KDC must decrypt the pre-authentication with the person's key, "+
			"and a source that only verifies a password cannot produce one")
	}
}
