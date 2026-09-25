// SPDX-License-Identifier: BSD-3-Clause

// Command authnd is an LDAP server for people who are somewhere else.
//
//	authnd --config /etc/authnd.d
//	authnd check /etc/authnd.d
//
// A site's people are in a database, or in a file, or in a directory that
// already exists. The things that want to authenticate them speak LDAP,
// because almost everything speaks LDAP. authnd is the front: it binds and
// searches over go-authn/directory's sources, so that what a database holds
// can be read by anything that knows how to ask a directory.
//
// # A realm, optionally
//
// A kerberos block makes this a KDC as well as a directory: the same people,
// issued tickets instead of only being looked up. It answers on UDP and TCP,
// requires encrypted-timestamp pre-authentication, and signs its own tickets
// with the krbtgt key in a keytab — the same file the services read.
//
// ⛔ Not every directory can back one. A KDC must DECRYPT the client's
// pre-authentication with that person's long-term key, so it needs the
// PASSWORD; a source that only VERIFIES one cannot produce a key. `authnd
// check` names the people this affects, because the alternative is somebody
// discovering it when their correct password is reported wrong.
//
// # What it refuses, and why
//
// An LDAP server is asked to prove people, so the refusals are the design:
//
//   - The UNAUTHENTICATED BIND. A bind carrying a NAME and an empty password
//     (RFC 4513 5.1.2) establishes an anonymous state while naming somebody:
//     the name "is not to be authenticated or otherwise validated", and a
//     server that passes it through as proof lets anybody in as anybody.
//     Refused with unwillingToPerform, which is what 5.1.2 asks for --
//     invalidCredentials would say the password was wrong, and a person
//     would retry one that was never the problem.
//
//     Its neighbour is NOT refused: 5.1.1, the ANONYMOUS bind, is an empty
//     name AND an empty password, it is legitimate, and refusing it locks
//     every client out of the root DSE that says how to authenticate.
//
//   - ANONYMOUS SEARCH. A directory that answers everybody publishes its
//     people to everybody. A reader binds first.
//
//   - A CREDENTIAL OVER A PLAINTEXT SOCKET. sambaNTPassword is not a password
//     hash in the sense a login form means: whoever holds it authenticates as
//     that person over NTLMv2. So publishing it needs TLS -- or a listener
//     that is not on the network at all.
//
// # A second factor, over a protocol with one field
//
// An LDAP simple bind carries a name and a password and nothing else. So a
// code goes on the END of the password -- "hunter2314159" -- which is what
// every appliance doing this does. The split is by length, both halves are
// always checked so the time taken says nothing about which was wrong, and a
// code is accepted once: it is valid for a whole step, and a server that takes
// it twice takes a replay.
//
// # The awkward half, said once
//
// NTLMv2 needs the password or its MD4, so a file server asking authnd about
// somebody can serve them over SMB only if the SOURCE holds enough for that.
// A directory that only checks passwords -- an LDAP directory behind this one,
// a bcrypt column -- answers WebDAV and cannot answer SMB, whatever authnd
// does in between. `authnd check` prints that per person, from the same model
// the file server uses: github.com/go-authn/directory.
package main
