# authnd

[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/authnd/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/authnd/actions/workflows/ci.yml)

**An LDAP server for people who are somewhere else** — a SQL database, a
configuration file, another directory. Pure Go, `CGO_ENABLED=0`, one binary.

```sh
authnd --config /etc/authnd.d
authnd check /etc/authnd.d
```

A site's people are already in a database. The things that want to
authenticate them speak LDAP, because almost everything speaks LDAP. authnd is
the front: it binds and searches over
[go-authn/directory](https://github.com/go-authn/directory)'s sources, so what
a database holds can be read by anything that knows how to ask a directory.

## The configuration

```hcl
listen  = "0.0.0.0:636"
base_dn = "dc=example,dc=org"

cert_file = "/etc/authnd/cert.pem"
key_file  = "/etc/authnd/key.pem"

# The service account that may READ. Binding proves who you are; reading
# everybody is a separate thing to be allowed.
reader "cn=reader,dc=example,dc=org" { password_file = "/etc/authnd/reader.pw" }

# People written down here: a service account, or a small site's whole list.
user "backup" { password_file = "/etc/authnd/backup.pw" }

group "operators" { members = ["backup"] }

# And people who are somewhere else.
users "sql" {
  driver   = "postgres"
  dsn_file = "/etc/authnd/dsn"
  users    = "select login, secret, nt_hash from staff"
  groups   = "select team, member from team_members"
}
```

The `users` block is `go-authn/directory/hcldir`'s, so this server and a file
server ([go-fileshare/fileshare](https://github.com/go-fileshare/fileshare))
describe the same directory the same way. The **queries are yours**: a site's
people are already in that site's shape.

Sources are asked in the order they are written and **the first that knows a
name owns it**, so a service account written down here is not overridden by
somebody with the same name in the database. Group membership is the union.

## What it refuses, and why

An LDAP server is asked to prove people, so the refusals are the design.

### The unauthenticated bind

A bind with a name and an **empty password** is answered `success` by a real
directory (RFC 4513 §5.1.2). It means *I am anonymous* — not *I proved this
name*. A server that passes it through as proof lets anybody in as anybody, and
the client that asked cannot tell it from a real success.

Refused here, always. It is the first thing the tests check, with OpenLDAP's
own client sending exactly that.

### Anonymous search

A directory that answers everybody has published its people to everybody. A
`reader` binds first, and a person who binds successfully still may not read
the list.

### A credential over a plaintext socket

`sambaNTPassword` is **not** a password hash in the sense a login form means:
whoever holds `MD4(UTF16LE(password))` authenticates as that person over
NTLMv2, without ever learning the password. So publishing it needs TLS — or a
listener that is not on the network at all:

```
$ authnd check /etc/authnd.d
publish_nt_hash needs cert_file and key_file: an NT hash IS the credential,
and 0.0.0.0:3893 is not loopback, so it would cross a network in the clear
```

## `check`, before you restart something people log in through

```
$ authnd check /etc/authnd.d
ldap://127.0.0.1:3893, base dc=example,dc=org

USER    FROM                    CAN PROVE   PUBLISHED AS
backup  the configuration file  a password  uid, cn and sambaNTPassword
dora    a sqlite database       a password  uid, cn and sambaNTPassword
eli     a sqlite database       a password  uid, cn and sambaNTPassword

GROUP      MEMBERS
engineers  dora and eli
operators  backup

cn=reader,dc=example,dc=org may search; every other bound client may not
sambaNTPassword is published on a loopback listener: it IS the credential, and
whoever reads it authenticates as that person over NTLMv2

this configuration can be served
```

It opens every source and prints what would be published, without listening —
and never a secret, only where each one comes from.

## The awkward half, said once

**NTLMv2 needs the password or its MD4, and nothing else will do.** A client
never sends a password to an SMB server; it sends a proof computed from one. So
a file server asking authnd about somebody can serve them over SMB only if the
*source* held enough for that — a password, or the hash. A directory that only
*checks* passwords (an LDAP directory behind this one, a bcrypt column) answers
WebDAV and can never answer SMB, whatever authnd does in between.

`check` prints that per person, and `publish_nt_hash` is the switch that
decides it. Nothing about this is a limitation of this program.

## Verified against real things

- **OpenLDAP's own `ldapsearch`** reads this server: the entries, a filter that
  really filters, the groups, a bind as a person, `Invalid credentials (49)`
  for a wrong password and for the empty one. A Go client from the same
  ecosystem could share a misreading of the protocol with the server and agree
  with it; OpenLDAP cannot.
- **TLS, judged twice**: `ldapsearch` over `ldaps://` proves the LDAP
  conversation crosses TLS, and `openssl s_client -verify_return_error` proves
  the chain. (macOS's `ldapsearch` trusts the system store and ignores
  `LDAPTLS_CACERT`, so it cannot be told to trust a test's certificate —
  measured, not assumed.)
- **The whole stack**: a SQLite database published by this server and read back
  by `go-authn/directory/ldapdir`, which is the library a file server uses. The
  identities that come out carry the NT hash SMB needs — and, with
  `publish_nt_hash` off, provably do not.
- **The NT hash the tests expect** was computed by an OpenSSL that is not this
  program (`printf 'hunter2' | iconv -t UTF-16LE | openssl md4`, with 1.1,
  since 3.x dropped MD4), and that OpenSSL was itself checked against the value
  every article about NTLM quotes for `password`.

## Building only what you want

| build | size | what it leaves out |
|---|---|---|
| everything | 23.8 MB | |
| `-tags noldap` | 23.2 MB | the LDAP **client**, and the `users "ldap"` block |
| `-tags nosql` | 11.7 MB | the three database drivers, and the `users "sql"` block |
| `-tags nosql,noldap` | 11.0 MB | both |

The server itself is always there; the tags are about where the *people* come
from. `nosql` is by a distance the biggest lever — the three drivers weigh
**12.1 MB**, more than the rest of the program put together — and it is also
attack surface: code that was never compiled cannot be reached.

Both lanes run the whole test suite, not a subset: the people arrive as `user`
blocks instead, and every question about binds, searches and refusals is asked
again. A tag lane that skipped its tests would prove only that the binary
links.

## Not yet

- **Multi-factor.** The seam is [go-authn/mfa](https://github.com/go-authn/mfa);
  what an LDAP bind can carry in-band is a password with a code appended, which
  is what every appliance does and is not written here yet.
- **OIDC.** A token verified into an identity, for the things that speak that
  instead.
- **Writes.** Nothing here modifies anything: `add`, `modify` and `delete` are
  answered by the library's default, which refuses them. A directory this
  server fronts is edited where it lives.

## Licence

BSD-3-Clause.
