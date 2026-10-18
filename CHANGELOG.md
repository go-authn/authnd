# Changelog

Changes that a deployment has to know about, newest first. Earlier releases
are described in their pull requests and release notes.

## v0.11.1 — 2026-10-18

- The startup line names only the sources somebody is served from. With no
  `user` block it read "serving 5 people from the configuration file, then a
  sqlite database": the configuration file is always in the set, because a
  password change is written there, but it served nobody.
- This file: v0.11.0 shipped with its section still headed "Unreleased".

## v0.11.0 — 2026-10-18

### ⛔ Breaking for v0.10.x configurations: `publish_nt_hash` needs a `samba` block

`publish_nt_hash = true` without a `samba` block is **refused at startup**
(and by `authnd check`). v0.10.x served that configuration. Add the domain the
people's `sambaSID` belongs to:

```hcl
publish_nt_hash = true
samba {
  domain_sid           = "S-1-5-21-..."   # the SMB server's: `net getlocalsid` prints it
  algorithmic_rid_base = 1000             # optional; Samba's default
}
```

`sambaNTPassword` belongs to Samba's `sambaSamAccount`, whose MUST is `uid` and
`sambaSID`, and no other class allows it. A person's `sambaSID` is their own
`sambaSID` attribute, or `domain_sid`-(2 × `uidNumber` + `algorithmic_rid_base`),
Samba's algorithmic mapping. A person with neither is published without
`sambaNTPassword`, and `check` and the startup log name them.

Refused rather than served differently: the v0.10.x entry cannot pass the
schema, and the two ways of carrying on -- dropping the attribute, dropping the
person -- would each take SMB away from somebody with nothing on the console.

### Standard-schema entries, held to the schema served at `cn=Subschema`

- People are an `account` (no `sn`) or an `inetOrgPerson` with every
  superclass, plus `posixAccount` when `uidNumber`, `gidNumber` and
  `homeDirectory` are all given, `ldapPublicKey` with SSH keys,
  `sambaSamAccount` with a published NT hash, and `uidObject` always. They were
  `top, person, posixAccount` whatever they had.
- Groups are a `posixGroup` with a `gidNumber`, a `groupOfNames` (`member`
  DNs) without one, and an `organizationalRole` when also empty. They were all
  `posixGroup`s, most without the `gidNumber` it requires.
- ⛔ A consumer filtering on `(objectClass=posixAccount)` no longer sees a
  person without the POSIX trio, and one filtering on
  `(objectClass=posixGroup)` no longer sees a group without a `gidNumber`
  (go-authn/directory's ldapdir up to v0.13.0, and so go-fileshare until it
  requires directory v0.14.0, whose defaults read `account`, `uidObject` and
  `groupOfNames`).
- go-authn/directory v0.14.0: authnd's own `users "ldap"` source has those
  wider defaults too.
- A descriptive attribute no class of the entry allows is dropped, and the
  entry published with the rest; the startup log and `check` name it. An entry
  that still fails `schema.Validate` is not published.
- The root DSE names `cn=Subschema`, which is answered; filters use the
  schema's matching rules, so `(uidNumber>=1000)` compares integers.
- `user` and `group` blocks take `attributes = { ... }`.
