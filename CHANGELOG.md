# Changelog

Changes that a deployment has to know about, newest first. Earlier releases
are described in their pull requests and release notes.

## Unreleased

Correction to the v0.13.3 entry below, text only. As first written it compared
v0.13.3 with a v0.13.2 of 1,100,039 / 720,036 allocations, 45.4 / 26.5 MiB and
70 / 38 ms (-12 % / -4 %). That baseline was not the v0.13.2 tag: it was run
with the v0.13.3 source and only `go.mod` pinned to ldap v0.11.2. The tags,
built from clean clones, give 1,280,040 / 850,036 allocations for v0.13.2 and
970,039 / 690,036 for v0.13.3: -24 % and -19 %. The tag v0.13.3 and its code are
unchanged; the table below is the corrected one.

## v0.13.3 — 2026-10-30

Performance only; nothing a deployment has to change, and the same entries are
published (a test holds a digest of every published entry, attribute, dropped
attribute and left-off class of 400 people and groups, with and without the
rules, that v0.13.2 produced).

authnd builds with `ldap` v0.11.3 (`GoverningStructureRule` reads only the types
of the RDN, the DN parser uses one buffer), and asks `schema.Validate` once for
an entry that `unmet` has just checked and `validated` is about to check again:
the entry has not changed, and Validate depends on the schema and the entry
alone. `BenchmarkPublish10k` (10,000 people, `-cpu 1`, Apple M4 Max), the
tags v0.13.2 and v0.13.3 built from clean clones (the table was corrected after
the release, see Unreleased):

| | v0.13.2 | v0.13.3 |
|---|---|---|
| with the rules: allocations | 1,280,040 | 970,039 (-24 %) |
| with the rules: memory | 54.8 MiB | 42.6 MiB |
| without rules: allocations | 850,036 | 690,036 (-19 %) |
| without rules: memory | 33.7 MiB | 25.7 MiB |

Times of v0.13.3, five interleaved runs of ten iterations at a load average of
4.8: about 65.8 ms with the rules and 36.0 ms without. v0.13.2 was not timed at
a load below 9 (indicative, at a load of 17 to 21: about 92 ms with the rules
and 57 ms without).

What the rules still cost per person: the entry of the benchmark carries a
description that the content rule precludes, so the rules path validates it
twice (once before, once after dropping the attribute) where the path without
rules validates it once, builds a `ValidationError` with its message, and holds
the entry to the structure rules (a second read of its DN). Dropping the
attribute and asking again is the behaviour the content rule is documented to
have, and it is not changed here.

## v0.13.2 — 2026-10-29

Performance only; nothing a deployment has to change, and the same entries are
published.

authnd builds with `ldap` v0.11.2: `Validate` makes 12 allocations for a ten
attribute entry instead of 76 (lookups without a lower-case copy, descriptions
not split and re-joined, in-place buffers instead of maps and appended slices).
`BenchmarkPublish10k` (10,000 people, `-cpu 1`, `-benchtime 3x`, Apple M4 Max):

| | v0.13.1 | v0.13.2 |
|---|---|---|
| with the rules of `testdata/rules.schema`: allocations | 3,640,042 | 1,280,038 (-65 %) |
| with the rules: memory | 102.5 MiB | 54.8 MiB (-47 %) |
| without rules: allocations | 2,390,036 | 850,036 (-64 %) |
| without rules: memory | 65.4 MiB | 33.7 MiB (-48 %) |

Against v0.13.0 (4,160,044 and 2,650,036 allocations) that is -69 % and -68 %.

Times, five interleaved runs of ten iterations each at a load average of 8 to
11 (a little above the 9 that is trusted): the run with the rules went from
about 158 ms to about 90 ms, the run without from about 100 ms to about 55 ms.
The allocation counts do not depend on the load.

## v0.13.1 — 2026-10-28

Performance only; nothing a deployment has to change, and the same entries are
published.

authnd builds with `ldap` v0.11.1: string matching rules prepare printable
ASCII values (RFC 4518, 2.1 to 2.4 are the identity on them) without the
`x/text` transform round trips, and the DN parser allocates less. Measured with
`BenchmarkPublish10k` (10,000 people, `-cpu 1`, `-benchtime 3x`, Apple M4 Max):

| | v0.13.0 | v0.13.1 |
|---|---|---|
| with the rules of `testdata/rules.schema`: allocations | 4,160,044 | 3,640,042 (-12.5 %) |
| with the rules: memory | 147.5 MiB | 102.5 MiB (-31 %) |
| without rules: allocations | 2,650,036 | 2,390,036 (-9.8 %) |
| without rules: memory | 88.0 MiB | 65.4 MiB (-26 %) |

Times were taken at a load average of 10 to 16 and are not reliable: the run
with the rules went from about 194 ms to about 157 ms, the run without from
about 123 ms to about 100 ms, one run of three iterations each. The allocation
counts do not depend on the load; a time on a quiet machine is not yet
published.

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
