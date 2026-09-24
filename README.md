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

## A second factor, over a protocol with one field

LDAP's simple bind carries a name and a password and nothing else — no place
for a code, no round trip to ask for one, and a client that speaks LDAP will
not learn one. So the code goes on the **end** of the password, which is what
every appliance that has ever done this does, and what people already know how
to type:

```
password:  hunter2314159
           ^^^^^^^ ^^^^^^
           password  the six digits on their phone
```

```hcl
mfa {
  factors        = 2
  distinct_kinds = true     # two things they KNOW are not two factors
}

user "tess" {
  password    = "…"
  totp_secret = "JBSWY3DPEHPK3PXP"   # ⛔ this IS the second factor
}
```

The secret can equally come from a database column or an LDAP attribute — see
[go-authn/directory](https://github.com/go-authn/directory), where it is a
credential like any other. The checking is
[go-authn/totp](https://github.com/go-authn/totp)'s.

What follows from the one field, since none of it is obvious:

- **The split is by length.** The last N characters are the code. A password
  ending in digits is fine; a field *shorter* than a code is refused rather
  than guessed at, because a short password cannot be told apart from a code.
- **Both halves are always checked.** Returning early on a wrong password would
  say, in the time taken, which half was wrong.
- **A code is used once.** It is valid for a whole step, so a server that
  accepts one twice accepts a replay — and every step up to the last accepted
  one is refused, not merely the same one.
- **Nobody enrolled is not a refusal.** A person with no secret has answered
  nothing rather than answered wrongly, and the server's own output says
  *nobody enrolled an authenticator for this person* while the client is told
  only that the bind failed.
- **Readers do not carry a code** unless `mfa { readers = true }`: a service
  account has no phone. One that does gets a `totp_secret` of its own.

`check` lists who cannot bind under the policy, which is the question to ask
before turning it on.

## A token at the bind, in a field that is not the password

[go-authn/oidc](https://github.com/go-authn/oidc) verifies a token into an
identity. The obvious way to carry one to an LDAP server is the password
field, and several appliances do exactly that. It works once and then stops:
the password field is where the `mfa` block above takes the code off the end,
and a token cannot be both.

So the token goes where the protocol has a place for it. A **SASL** bind's
credentials are an octet string of the mechanism's own shape, and
[RFC 7628](https://www.rfc-editor.org/rfc/rfc7628)'s `OAUTHBEARER` shape is a
GS2 header followed by key/value pairs, one of which is `auth=Bearer <token>`.
The password field is left alone — which is the whole point:

```hcl
oidc {
  issuer   = "https://login.example.org/realms/staff"
  audience = "ldap"

  # Which claim names the person in THIS directory. The default order is
  # preferred_username, then email, then sub.
  username_claim = "preferred_username"
}
```

On one listener, at the same time, tess still types her password with this
second's code on the end of it, and alice sends a token. Neither arrangement
costs the other anything.

### How many factors is a token?

**Whatever the issuer says it checked, and nothing more.** A token carries
[RFC 8176](https://www.rfc-editor.org/rfc/rfc8176)'s `amr`: the methods the
provider used. That is the only evidence there is, so it is what the `mfa`
policy counts — `["pwd","otp"]` is a password and a one-time code, of two
distinct kinds, and satisfies `distinct_kinds = true`. A token with no `amr`
is **one** factor and such a policy refuses it.

The alternative would be this server inventing a second factor nobody
performed. The trust involved is the same trust the bind already rests on: a
server that believes the issuer about *who* this is has no separate ground for
disbelieving it about *how* it checked.

### What it refuses

- **A token in the clear.** A bearer token needs no other half — whoever reads
  it off the wire is that person until it expires. `allow_plaintext = true`
  exists for a deployment that terminates TLS in front of this process, which
  is a statement only that deployment can make.
- **A request to be somebody else.** The GS2 header may name an `authzid`. A
  token for alice carrying a request to act as bob is refused, not quietly
  treated as either.
- **A token for somebody no source here publishes**, and the client is told
  only `invalid_token`. Which name exists is not something to hand out one
  guess at a time; the reason is in this server's own output, where an
  administrator is.
- **A mechanism this server does not speak**, with `authMethodNotSupported`
  rather than `invalidCredentials` — those send a client to different places.

A refusal is [RFC 7628 3.2.3](https://www.rfc-editor.org/rfc/rfc7628#section-3.2.3)'s:
a JSON error carrying `openid-configuration`, returned as `saslBindInProgress`
so the client can send the `^A` that ends the exchange.

### The library this needed

`glauth/ldap` refused every SASL bind outright, so there was no field to put a
token in. [tannevaled/ldap](https://github.com/tannevaled/ldap) is a fork that
adds an optional `SASLBinder`, offered back upstream — along with two defects
found on the way there: a failed bind left the connection with the *previous*
bind's authorisation (RFC 4511 4.2.1), and a response carrying any optional
field was read as a malformed packet.

⛔ It is a **bridge, not a destination**. Five defects turned up in the fifty
lines of the bind path alone, and its filter evaluator drops everything after
the first `*` — `(uid=svc-*-prod)` matches `svc-web-stage`, which in a
directory is disclosure. `go-authn/ldap`, an LDAP server written from
RFC 4511/4513/4515/7628, replaces it; this dependency is one line.

## ldaps:// or StartTLS, and not both at once

```hcl
starttls  = true            # a plaintext listener, upgraded on request
cert_file = "/etc/authnd/cert.pem"
key_file  = "/etc/authnd/key.pem"
```

Without `starttls`, the listener is `ldaps://`: the handshake happens before a
byte of LDAP is spoken. With it, the listener is plaintext and a client asks
to upgrade (RFC 4511 4.14) — which is what a client pointed at 389 with "use
TLS" ticked does.

It is one or the other and has to be: a listener cannot both require a
handshake and wait to see whether one is asked for. This used to be documented
as both at once, which no deployment ever got.

⛔ **StartTLS is asked for by the client**, so merely offering it promises
nothing. A listener configured for it therefore refuses every bind and every
search until it has been upgraded, and says `confidentialityRequired`. That is
what keeps `cert_file` a guarantee rather than an offer — which is what
`publish_nt_hash` is allowed to rely on.

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

- **Writes.** Nothing here modifies anything: `add`, `modify` and `delete` are
  answered by the library's default, which refuses them. A directory this
  server fronts is edited where it lives.

## Licence

BSD-3-Clause.
