# Changelog

Changes that a deployment has to know about, newest first. Earlier releases
are described in their pull requests and release notes.

## v0.13.0 — 2026-10-26

### DIT content rules, name forms and DIT structure rules, enforced

authnd builds with `ldap` v0.11.0, which reads, builds and enforces the three
kinds of definition RFC 4512 §4.1.6 and §4.1.7 define. `schema_files` (the
`.schema` keywords `ditcontentrule`, `nameform`, `ditstructurerule`, and the
LDIF attributes `olcDitContentRules`, `dITContentRules`, `nameForms`,
`dITStructureRules`) and `schema {}` blocks (`dit_content_rule`, `name_form`,
`dit_structure_rule`) accept them. A file that redefines one is refused, even
word for word, as for every other definition. `cn=Subschema` publishes them.

**Content rules shape each entry** (data), for the entry's structural class:

- an auxiliary class the rule's AUX does not list -- declared, or one authnd
  derives (posixAccount, ldapPublicKey, sambaSamAccount, uidObject) -- is left
  off that entry, with the attributes only it allowed (and the sshPublicKey,
  sambaSID and sambaNTPassword authnd would add for it); a declared class
  whose superclass is left off goes too;
- an attribute the rule's NOT names is dropped, whoever gave it;
- a type the rule's MUST names that the entry lacks leaves the entry out: the
  rule applies to the entry as a whole.

Each is said at startup and by `check`. Without a content rule, auxiliary
classes are allowed, as slapd allows them.

**Structure rules hold the tree** (configuration). With at least one active
DIT structure rule, authnd walks its tree at startup and in `check`: the
suffix (`base_dn`, given the class its RDN names: dc a domain, o an
organization, ou an organizationalUnit, c a country, l a locality),
`ou=people` and `ou=groups` (organizationalUnits), and the RDN attribute it
names people (`uid`) and groups (`cn`) by. A container no rule places, a
suffix of another kind, a name form that refuses `uid` or `cn`, or a container
under which nothing authnd publishes could be placed **refuses startup**,
naming the DN, the rule or name form, and the clause. A person or group whose
structural class -- which depends on its data, an `sn`, a `gidNumber` -- has
no rule under its container is left out and said. With no active structure
rule, nothing changes.

### Breaking

- None for a schema without rules: a configuration that started on v0.12.4
  could not hold a content rule, name form or structure rule (v0.12.4 refused
  all three), so its schema and its entries are the same here. The one
  exception: a `schema {}` block string that is not valid UTF-8 (an overlong
  encoding HCL lets through) started on v0.12.4 and is now refused, because it
  could not be published as it was written.

### Performance

Publishing 10,000 accounts makes 416 allocations per entry with the rules of
`testdata/rules.schema` against 265 without (`BenchmarkPublish10k`; this
includes dropping a precluded description and validating again). The times,
192 ms against 118 ms, were measured at a load of 8 to 14 and are not a ratio
to trust.

## v0.12.4 — 2026-10-26

### cn=Subschema: no page-layout whitespace inside RFC 2307 DESC values

The DESC values of 13 RFC 2307 definitions in `cn=Subschema` carried the
indentation of the RFC's page layout, e.g. `DESC 'An integer uniquely
identifying a user in an         administrative domain'` for `uidNumber`. They
are now one line with single spaces, as in the RFC text and OpenLDAP's
`nis.schema`. The 6 attribute types are `uidNumber`, `gidNumber`,
`ipHostNumber`, `ipNetworkNumber`, `ipNetmaskNumber` and `macAddress`; the 7
object classes are `ipService`, `ipProtocol`, `oncRpc`, `ipHost`, `ipNetwork`,
`ieee802Device` and `bootableDevice`. authnd now builds with `ldap` v0.10.2.
Only the text of DESC changes; no OID, name, syntax or rule does. A client that
caches the subschema picks the new text up the next time it reads it.

## v0.12.3 — 2026-10-26

### Schema loading no longer stalls on a huge schema file (denial of service)

`schema_files` are read at startup with `schema.Read` from
`github.com/go-authn/ldap`. Up to v0.10.0 that parser was quadratic on
continuation lines: a 4 MiB schema file of short continuation lines took about
three minutes (139.6 GB allocated for 1 MiB), so a hostile or oversized schema
file stalled startup. authnd now builds with `ldap` v0.10.1, where `Read` is
linear, no longer copies and splits the whole file to inspect its first line,
and the strict parser is about 2.6x faster (147 allocations instead of 498 on
`cosine.schema`, measured on a loaded machine). `schema.Format` also folds
lines over 2000 bytes, which slapd and `Read` refuse. Upgrade if you load
schema files you do not control.

## v0.12.2 — 2026-10-26

### Release binaries keep their symbol table

Release binaries are linked with `-ldflags="-w"` instead of `-s -w`. Per
`go doc cmd/link`, `-s` omits the symbol table and debug information, `-w`
only the DWARF symbol table. With the symbol table stripped,
`govulncheck -mode binary` cannot tell which functions are present and falls
back to module level, reporting vulnerabilities in code that is not linked
(a false positive: GO-2026-5932, x/crypto/openpgp). With it kept, the scan is
precise. Cost, measured on darwin/arm64 with go1.27.3: 18.8 MB to 20.5 MB
(+9%).

## v0.12.1 — 2026-10-25

### Schema refusals come from go-authn/ldap's typed BuildError

- A `schema_files` file or `schema` block that does not build is refused at
  the position go-authn/ldap v0.10.0's `*schema.BuildError` carries -- the
  line (and column) where the definition starts -- and the message now ends
  with the kind of refusal (`unknown reference`, `duplicate OID`, `kind
  violation` ...). A duplicate says where its first definition is, a
  redefinition which standard file or which line of an earlier file holds
  the original. Nothing reads ldap's message sentences or re-reads the file
  any more, so a change of wording there cannot misplace the line.
- Positions gain a column: `site.schema:6:` becomes `site.schema:6:1:`.
- `the name "x" is given to two object classs` reads `object classes`.

## v0.12.0 — 2026-10-25

### ⛔ Security: built with Go 1.27.3 (GO-2026-6809)

authnd verifies certificates (`x509.Certificate.Verify`, reached from
`main` per `govulncheck`), and Go 1.27.2's crypto/x509 did not distrust the
compromised intermediate certificates GO-2026-6809 names. v0.11.1's release
binaries were built with 1.27.2 and are affected. The release workflow now
builds with 1.27.3, and the `go` directive is 1.27.3, so `go install`
switches to the fixed toolchain by itself. `govulncheck` under 1.27.3: no
vulnerabilities.

### Site schemas, and auxiliary object classes a source declares

- `schema_files = [...]` loads OpenLDAP `.schema` and cn=config LDIF files as
  published (go-authn/ldap v0.9.0's slapd-compatible readers), on top of the
  standard schema, and serves them at `cn=Subschema`. A file that does not
  build refuses startup and `check` with the file and the line.
- ⛔ A file that **redefines** a definition already there -- the standard
  schema's, Samba's, an earlier file's -- is refused, even word for word, as
  slapd refuses it ("Duplicate attributeType", `servers/slapd/at.c`, `oc.c`).
- `schema { ... }` holds site-local definitions in go-authn/ldap's hclschema
  shape. Values must be literals (no `${...}`, `%{...}`, variables or
  functions); errors name the configuration's own line and column.
- go-authn/directory v0.15.0: `object_classes` / `group_object_classes` in
  `users` blocks and `object_classes` in `user` and `group` blocks declare
  auxiliary classes. Each is checked at startup and by `check`: defined,
  AUXILIARY, and not one authnd derives itself; otherwise startup is refused,
  naming the block, its position and the class.
- A declared class is published with its superclasses (RFC 4512 §3.3), and the
  attributes it allows are kept instead of dropped. A person or group missing
  one of its MUSTs is published without it, its attributes are dropped, and
  both are reported. Nothing is inferred: without a declaration, nothing
  changes.
- The startup log and `check` list the schema files and schema blocks loaded
  (what each adds), what each source declares, the classes left off per
  person, and **groups for which two sources declare different classes**
  (directory publishes the first list and ignores the rest silently).
- Schema files must be regular files of at most 4 MiB, read once at startup.

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
