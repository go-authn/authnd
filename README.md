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

user "carol" {
  nt_hash         = "…"   # MD4(UTF16LE(password)), 32 hex: a site that holds THAT, not the password
  authorized_keys = ["ssh-ed25519 AAAA… carol@laptop"]   # published as sshPublicKey; or authorized_keys_file
}

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

## The entries it publishes

Every entry is a standard-schema entry, and **every entry published passes
`schema.Validate`** ([go-authn/ldap](https://github.com/go-authn/ldap)'s
package `schema`) against the schema this server publishes at `cn=Subschema`.
An attribute a source gave that **no class of the entry allows is dropped**,
and the entry is published with the rest; the startup log and `authnd check`
name each dropped attribute, per person, with the classes that would carry it.
An entry that still fails is **not published**: it is absent from every
search, the startup log names it, and `authnd check` lists it with each problem
`Validate` found. Up to v0.10.2 every person was `top, person, posixAccount`
with none of the attributes those classes require.

| a person with… | `objectClass` (every superclass listed, RFC 4512 §3.3) | `cn` |
|---|---|---|
| no `sn` | `top`, `account` (RFC 4524 §3.1) | only when another class allows it |
| `sn` | `top`, `person`, `organizationalPerson`, `inetOrgPerson` (RFC 4519, RFC 2798) | yes |
| … and `uidNumber`, `gidNumber`, `homeDirectory`, all three | `+ posixAccount` (RFC 2307) | yes |
| … and SSH keys | `+ ldapPublicKey` (openssh-lpk), with `sshPublicKey` | |
| … and a published NT hash with a sambaSID | `+ sambaSamAccount` (Samba), with `sambaSID` and `sambaNTPassword` | allowed |
| … always | `+ uidObject` (RFC 4519 §3.14), so `(objectClass=uidObject)` finds everybody | |

| a group with… | `objectClass` | members |
|---|---|---|
| a `gidNumber` | `top`, `posixGroup` (RFC 2307) | `memberUid`, names |
| no `gidNumber`, somebody in it | `top`, `groupOfNames` (RFC 4519 §3.5) | `member`, the DNs this server publishes |
| no `gidNumber`, nobody in it | `top`, `organizationalRole` (RFC 4519 §3.10) | none |
| a `gidNumber`, nobody in it | `top`, `posixGroup` | none (no empty `memberUid`) |

`uid` is the person's name, and so is `cn` wherever a class allows it. An
`account` alone does not allow `cn` (its MAY is description, seeAlso, l, o,
ou and host), so a person without `sn` and without the POSIX trio has `uid`
and no `cn`. A person's and a group's descriptive attributes
([go-authn/directory](https://github.com/go-authn/directory)'s
`Identity.Attributes()` and `Set.GroupAttributes`) are published as given,
except one that no class of the entry allows, which is dropped:

| given | the entry | dropped, and the reason `check` gives |
|---|---|---|
| `uidNumber`, `gidNumber`, no `homeDirectory`, no `sn` | `account, uidObject` | `uidNumber`, `gidNumber`: *no class of the entry allows it; posixAccount would* |
| `mail`, no `sn` | `account, uidObject` | `mail`: *no class of the entry allows it; inetOrgPerson would* |
| a type the schema does not define | the rest | it: *the schema served here does not define it* |
| `mail` on a group without `gidNumber` | `groupOfNames` | `mail` |
| two `homeDirectory` values with the POSIX trio | **withheld**: SINGLE-VALUE, nothing to drop | — |
| a `gidNumber` that is not an integer | **withheld**: not of its syntax | — |

Only what a source gave is dropped. An attribute authnd derives itself (`uid`,
`cn`, `objectClass`, `sshPublicKey`, `sambaSID`, `sambaNTPassword`) that the
schema refused would be a defect here, and withholds the entry. Which
attributes are not allowed is `Validate`'s answer, and the entry is validated
again after dropping.

```
$ authnd check authnd.hcl
...
hal has no homeDirectory: not a posixAccount, published as account, uidObject
hal is published without uidNumber: no class of the entry allows it; posixAccount would
hal is published without gidNumber: no class of the entry allows it; posixAccount and posixGroup would
hal is published without mail: no class of the entry allows it; inetOrgPerson would
```

Why these choices:

- **posixGroup follows RFC 2307, not draft-howard-rfc2307bis-02.** The draft
  makes posixGroup AUXILIARY, and it expired without being published. The schema
  served here is RFC 2307's, and an AUXILIARY posixGroup would need a structural
  class beside it, `groupOfNames`, which needs a `member` that an empty group
  cannot give.
- **organizationalRole for an empty group without gidNumber.** `groupOfNames`
  and `groupOfUniqueNames` both MUST have a member, and inventing one would be
  false: `member: ""` names the root DSE, and the group's own DN makes it a
  member of itself. `organizationalRole` is the one standard structural class
  whose only MUST is `cn` and whose occupants (`roleOccupant`) are optional. It
  takes `description`, `ou` and `seeAlso` as `groupOfNames` does.
- **Auxiliary classes without DIT content rules.** RFC 4512 §2.4.3 forbids
  auxiliary classes on an entry whose structural class has no DIT content rule.
  slapd allows them anyway, and so does `Validate` (go-authn/ldap says so).
  When a site schema has a content rule, see
  [DIT content rules, name forms and structure rules](#dit-content-rules-name-forms-and-structure-rules).

The schema is served: the root DSE carries `subschemaSubentry: cn=Subschema`,
the library answers a base search of `cn=Subschema`, and filters are evaluated
with the schema's matching rules, so `(uidNumber>=1000)` compares integers.

```hcl
user "dora" {
  password_file   = "/etc/authnd/dora.pw"
  authorized_keys = ["ssh-ed25519 AAAA… dora@laptop"]
  attributes = {
    sn            = "Explorer"          # inetOrgPerson
    uidNumber     = "1000"              # the three: posixAccount
    gidNumber     = "1000"
    homeDirectory = "/home/dora"
    mail          = "dora@example.org"
  }
}

group "engineers" {
  members    = ["dora", "eli"]
  attributes = { gidNumber = "2000" }   # a posixGroup; without it, a groupOfNames
}

users "sql" {
  driver   = "sqlite"
  dsn_file = "/etc/authnd/dsn"
  users    = "select login, secret, nt_hash, ssh_keys from staff"
  groups   = "select team, member from teams"
  users_attributes  = "select login, sn, uid as uidNumber, gid as gidNumber, home as homeDirectory, mail from person_attrs"
  groups_attributes = "select team, gid as gidNumber, description from team_attrs"
}
```

What that SQL source publishes, read by OpenLDAP's `ldapsearch` (from the pull
request that introduced this):

```
dn: uid=dora,ou=people,dc=example,dc=org
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: ldapPublicKey
objectClass: uidObject
uid: dora
cn: dora
sn: Explorer
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/dora
mail: dora@example.org
sshPublicKey: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9Bl6dNhbHqUCLxLLjTe5MDLbLWyWZ9UBjFA+Vx4rJk dora@laptop

dn: uid=gus,ou=people,dc=example,dc=org
objectClass: top
objectClass: account
objectClass: uidObject
uid: gus

dn: cn=readers,ou=groups,dc=example,dc=org
objectClass: top
objectClass: groupOfNames
cn: readers
description: people who read
member: uid=fay,ou=people,dc=example,dc=org
member: uid=gus,ou=people,dc=example,dc=org
```

⛔ **A consumer that filters on `(objectClass=posixAccount)` no longer sees a
person without the POSIX trio**, and one that filters on
`(objectClass=posixGroup)` no longer sees a group without a `gidNumber`. This
includes go-authn/directory's `ldapdir` up to v0.13.0, and so go-fileshare.
Give people and groups those attributes, or point the consumer at
`(objectClass=uidObject)`. go-authn/directory **v0.14.0** widens ldapdir's
defaults to match (go-fileshare reads authnd correctly from the release that
requires it): the user filter to
`(|(objectClass=posixAccount)(objectClass=account)(objectClass=uidObject))`,
and the group filter to `(|(objectClass=posixGroup)(objectClass=groupOfNames))`,
with `member` DNs matched to the people ldapdir imported.

### `publish_nt_hash` needs a `samba` block

`sambaNTPassword` is an attribute of Samba's `sambaSamAccount`, whose MUST is
`uid` and `sambaSID`, and no other class allows it. So publishing it needs the
domain a person's SID belongs to:

```hcl
publish_nt_hash = true
samba {
  domain_sid           = "S-1-5-21-1004336348-1177238915-682003330"   # `net getlocalsid` on the SMB server
  algorithmic_rid_base = 1000                                         # optional; Samba's default
}
```

A person's `sambaSID` is their own `sambaSID` attribute when a source gives
one. Otherwise it is `domain_sid-RID`, with RID = 2 × `uidNumber` +
`algorithmic_rid_base`. That is Samba's algorithmic mapping: smb.conf(5),
*algorithmic rid base*, and `algorithmic_pdb_uid_to_user_rid` in
`source3/passdb/passdb.c`. A person with an NT key and neither is published
**without** `sambaNTPassword`, and `check` and the startup log say who. An odd
base, or one below 1000, is refused: Samba would silently use another one.

⛔ **Breaking change for v0.10.x configurations: `publish_nt_hash = true`
without a `samba` block is refused at startup**, with a message saying what to
add. v0.10.x served that configuration; an upgrade that does not add the block
stops, and `authnd check` refuses it the same way before the restart. Add:

```hcl
samba {
  domain_sid = "S-1-5-21-..."   # the SMB server's domain SID: `net getlocalsid` prints it
}
```

That is deliberate. The entry v0.10.x published cannot pass the schema. The
two quiet alternatives are dropping the attribute, which takes SMB away from
everybody, and dropping the entry, which takes the person away. Both would
happen with nothing on the console.

`samba.schema` carries the three Samba definitions. They are written from
Samba's published OIDs, names, syntaxes and matching rules, not copied from
Samba's GPL-3.0 `samba.schema`, and `sambaSamAccount`'s MAY lists only what
authnd publishes. See the file.

### Site schemas, and the auxiliary classes a source declares

A French research site serves SUPANN and eduPerson attributes. Since v0.12.0
authnd loads the schema files a site already has, and publishes the auxiliary
classes a source's configuration **declares**:

```hcl
schema_files = ["/etc/authnd/supann.schema", "/etc/authnd/eduperson.ldif"]

schema {                                   # site-local definitions, hclschema's shape
  attribute_type "siteBadge" {
    oid    = "1.3.6.1.4.1.99999.1.1"
    syntax = "1.3.6.1.4.1.1466.115.121.1.15"
  }
  object_class "siteMember" {
    oid  = "1.3.6.1.4.1.99999.2.1"
    kind = "auxiliary"
    may  = ["siteBadge"]
  }
}

users "sql" {
  driver           = "postgres"
  dsn_file         = "/etc/authnd/dsn"
  users            = "select login, secret from staff"
  users_attributes = "select login, sn, etab as \"supannEtablissement\", civ as \"supannCivilite\" from staff"
  object_classes       = ["supannPerson", "eduPerson"]   # declared, never inferred
  group_object_classes = ["supannGroupe"]
}
user  "alice" { object_classes = ["siteMember"] ... }
group "staff" { object_classes = ["supannGroupe"] ... }
```

- **`schema_files`** are OpenLDAP `.schema` or cn=config LDIF files, loaded
  **as published**, in order, on top of the standard schema (and `samba.schema`
  with the `samba` block), by go-authn/ldap's slapd-compatible readers: any term
  order, slapd and RFC 2849 continuations, base64, `{N}` prefixes,
  `objectidentifier` macros (one file's macros reach the next, as across slapd
  includes). A relative path is relative to the working directory, like every
  other path in the configuration. Each file must be a regular file of at most
  4 MiB (go-authn/ldap's `schema.MaxFileSize`, applied while reading); it is read
  once, at startup.
- **A file that does not build refuses startup and `check`**, with the file,
  the line and column where the definition starts, and the kind of refusal:
  an unknown superclass, attribute, rule or syntax, a structural class derived
  from an auxiliary one, a usage or supertype rule broken, an OID or a name
  defined twice (with where it was first defined). The place and the kind come
  from go-authn/ldap's typed `*schema.BuildError`, not from reading its
  message:

  ```
  schema_files: site.schema:6:1: the object class exampleB has MAY noSuchAttribute, which is not a defined attribute type (unknown reference)
  ```
- ⛔ **A file may not redefine a definition that is already there** -- the
  standard schema's, Samba's, or an earlier file's -- **even word for word**.
  That is slapd's rule: a schema file's definitions go through `parse_at` /
  `parse_oc` (`servers/slapd/schemaparse.c`), and `at_insert` / `oc_insert`
  (`at.c`, `oc.c`) answer an OID or name already there with
  *Duplicate attributeType* (same OID and names) or *Inconsistent duplicate
  attributeType*; only slapd's own hard-coded schema (`register_at(..., dupok)`)
  tolerates the first. A file slapd refuses is a file authnd refuses, and the
  refusal says whether the text was the same:

  ```
  schema_files: /etc/authnd/core-copy.schema:1:1: the attribute type cn (2.5.4.3) is already defined by the standard
  schema (rfc4519.schema:42:1), and this is the same definition, word for word: a schema file adds definitions and never replaces one --
  slapd refuses this too ("Duplicate attributeType", servers/slapd/at.c and oc.c). Remove it from this file
  ```
- **A `schema` block** holds site-local definitions in
  [hclschema](https://github.com/go-authn/ldap/tree/main/schema/hclschema)'s
  shape (`attribute_type`, `object_class`, `object_identifier`,
  `matching_rule`, `ldap_syntax`), after the files. hclschema decodes from
  bytes; each block is handed to it as its own text at its own place in the
  configuration file (the bytes before it blanked, line breaks kept), so the
  **literal-only rule** -- no variables, functions, `${...}` or `%{...}` -- and
  hclschema's bounds hold exactly as for an `.hcl` schema file, and every error
  names the configuration's own line and column. That was preferred to a new
  `hcl.Body` API in go-authn/ldap: one decoder instead of two entry points, the
  byte bounds still measured on bytes, and no release to wait for.
- **A declared class is checked at startup and by `check`** against the
  schema served: it must be defined, **AUXILIARY** (RFC 4512 §4.1.1; an entry
  has one structural chain, §2.4.2, which authnd chooses), and not one authnd
  derives itself (`account`, `inetOrgPerson` and its superclasses,
  `posixAccount`, `posixGroup`, `ldapPublicKey`, `uidObject`,
  `sambaSamAccount`, `groupOfNames`, `organizationalRole`, under any of their
  names). Otherwise startup is refused, naming every offending block, its
  position and the class:

  ```
  c.hcl:7:20: user "a" object_classes: exampleUnit is STRUCTURAL, and an entry has exactly one structural chain
  (RFC 4512 §2.4.2), which authnd chooses: only an AUXILIARY class (§4.1.1) can be declared
  c.hcl:29:26: users "sql" group_object_classes: groupOfNames is a class authnd derives itself, from what each
  person or group has (see `authnd check`), and a declaration cannot overrule that
  ```
- **Published with its superclasses** (RFC 4512 §3.3: "all superclasses of the
  named classes SHALL be implicitly added"), after the classes authnd derives.
  The attributes those classes allow are **kept** instead of dropped. A class
  is never inferred from an attribute: a person whose source declares nothing
  keeps losing the attributes no class of theirs allows.
- ⛔ **A person (or group) missing a MUST of a declared class is published
  without that class**, its attributes are dropped like any other attribute no
  class allows, and both are reported. That is the rule authnd already follows
  -- the person stays published, problems are said, nothing is changed
  silently. Withholding the person would take them out of every search for one
  missing attribute; publishing the class without its MUST would serve an entry
  that fails the schema served. Which MUST is missing is `schema.Validate`'s
  answer.
- **Two sources declaring different classes for one group**: go-authn/directory
  publishes the first source's list and ignores the later one, silently.
  `check` and the startup log **say so**:
  `group staff: the configuration file declares supannGroupe and a postgres database declares eduMember; the first is
  published and the second is ignored (the first source that declares classes for a group decides)`.

What `check` says, from the test that loads the committed example schema
(`testdata/example.schema`, `testdata/example.ldif`, OIDs under the private arc
1.3.6.1.4.1.99999) and a `schema` block (temporary paths shortened):

```
$ authnd check c.hcl
ldap://127.0.0.1:0, base dc=example,dc=org

schema: testdata/example.schema adds 3 object identifier macros, 3 attribute types and 5 object classes
schema: testdata/example.ldif adds 1 attribute type and 1 object class
schema: the schema block at c.hcl:8:1 adds 1 attribute type and 1 object class: exampleLocker and exampleLockerHolder
c.hcl:24:20: user "ann" declares exampleStaff, exampleLockerHolder and exampleOccupant for this person
c.hcl:35:20: user "ben" declares exampleStaff for this person
c.hcl:44:20: group "staff" declares exampleGroup for this group

USER  FROM                    CAN PROVE   PUBLISHED AS                                                                                                               WITH
ann   the configuration file  a password  person, organizationalPerson, inetOrgPerson, uidObject, examplePerson, exampleStaff, exampleLockerHolder, exampleOccupant  uid, cn, exampleBadge, exampleEmployeeId, exampleLocker, exampleOffice and sn
ben   the configuration file  a password  account, uidObject                                                                                                         uid
cat   the configuration file  a password  account, uidObject                                                                                                         uid

GROUP  MEMBERS      PUBLISHED AS
staff  ann and ben  posixGroup, exampleGroup

ann has no uidNumber, gidNumber or homeDirectory: not a posixAccount, published as person, organizationalPerson, inetOrgPerson, uidObject, examplePerson, exampleStaff, exampleLockerHolder, exampleOccupant
ben has no uidNumber, gidNumber or homeDirectory: not a posixAccount, published as account, uidObject
ben is published without exampleStaff, which its source declares: ben has no exampleEmployeeId, which exampleStaff requires
ben is published without exampleBadge: no class of the entry allows it; examplePerson and exampleStaff would
cat has no uidNumber, gidNumber or homeDirectory: not a posixAccount, published as account, uidObject
cat is published without exampleBadge: no class of the entry allows it; examplePerson and exampleStaff would
...
this configuration can be served
```

ann's `exampleStaff` brought `examplePerson`, its superclass. ben declares
`exampleStaff` without its MUST `exampleEmployeeId`, so he is published
without it, and his `exampleBadge` with it. cat declares nothing, and nothing
is inferred from her `exampleBadge`. The startup log carries the same lines,
with DNs.

Schema files are not secrets, but they decide what every entry may hold: keep
them with the rest of the configuration, `root:authnd`, mode `0640`, in a
directory only root writes ([docs/install.md](docs/install.md)).

### DIT content rules, name forms and structure rules

`schema_files` and `schema` blocks may hold the three kinds of definition
RFC 4512 §4.1.6 and §4.1.7 define (`ditcontentrule`, `nameform`,
`ditstructurerule`, or `dit_content_rule`, `name_form`, `dit_structure_rule`
in a block; slapd has a directive for the first only). They are published at
`cn=Subschema`, held to the redefinition rule above, and enforced:

- **A DIT content rule shapes each entry** of its structural class. An
  auxiliary class not in its AUX is left off that entry -- a declared one, or
  one authnd derives: posixAccount, ldapPublicKey (and its sshPublicKey),
  sambaSamAccount (and sambaSID, sambaNTPassword), uidObject -- like a
  declared class missing a MUST. An attribute in its NOT is dropped. A type in
  its MUST that the entry lacks leaves the entry out, since no class can be
  left off to fix it. All of it is said at startup and by `check`:

  ```
  uid=alice,ou=people,dc=example,dc=org is published without ldapPublicKey: the DIT content rule exampleAccountRule does not allow it (not in its AUX)
  uid=carol,ou=people,dc=example,dc=org is NOT published: it fails the schema: telephoneNumber is required by the DIT content rule examplePersonRule and is missing (RFC 4512 4.1.6)
  ```

- ⛔ **Structure rules hold the tree, which is configuration**: with one
  active DIT structure rule, the suffix (given the class its RDN names: dc a
  domain, o an organization, ou an organizationalUnit, c a country, l a
  locality), `ou=people` and `ou=groups` (organizationalUnits), and the RDN
  attributes authnd names people (`uid`) and groups (`cn`) by are checked
  from the root down, with go-authn/ldap's `GoverningStructureRule`. A tree
  the rules do not allow **refuses startup and `check`**:

  ```
  DIT structure rules: authnd names its people uid=<name>,ou=people,dc=example,dc=org, and an account named so is refused: the RDN (uid) is allowed by the name form of no DIT structure rule that places account under an entry governed by the rule 2: accountByCN needs cn
  ```

  A person or group whose structural class -- which comes from its data: an
  `sn` makes an inetOrgPerson, a `gidNumber` a posixGroup -- no rule places
  under its container is left out and said. An RDN the data makes different
  (a name holding `+`) never reaches the rules: Validate already refuses an
  entry whose RDN is not its own value. With no active structure rule,
  nothing changes. [`testdata/rules.schema`](testdata/rules.schema) is a
  complete example for this tree.

## What it refuses, and why

An LDAP server is asked to prove people, so the refusals are the design.

### The two empty-password binds

RFC 4513 has two, and they are **one field apart**:

| | | |
|---|---|---|
| **§5.1.1 anonymous** | empty name, empty password | *legitimate* — answered `success`, and the association is anonymous |
| **§5.1.2 unauthenticated** | a **name**, empty password | refused with `unwillingToPerform` |

The unauthenticated one establishes an anonymous state *while naming
somebody*. The name "is not to be authenticated or otherwise validated", and
the specification says servers "SHOULD by default fail Unauthenticated Bind
requests with a resultCode of `unwillingToPerform`".

Getting this wrong goes wrong in **both** directions, and this server has
managed both:

- Passing it through as proof lets anybody in as anybody, and the client
  cannot tell it from a real success.
- Refusing *every* empty password — which this did until the root DSE
  arrived — locks out every anonymous client, including from the discovery
  that tells it how to authenticate at all.
- Refusing it as `invalidCredentials` says *that password was wrong*, so a
  person retries and starts doubting a password that was never the problem.
  `unwillingToPerform` says *this server does not do that*, which is true and
  stops the retry.

Both are checked, with OpenLDAP's own client sending exactly them.

### Two people whose names differ only by case

A uid is compared ignoring case ([RFC 4519](https://www.rfc-editor.org/rfc/rfc4519)
§2.39), and so is every DN. `user "backup"` in the file and a row `Backup` in a
database are therefore one name to LDAP and two people to anything that
compares bytes — which is a password change by one landing on the other. So a
configuration whose sources between them hold two such names is **refused at
startup**, naming both and where each came from. A password change is also
authorized on the exact identity the connection bound as, not on a DN
comparison, so the two controls do not depend on each other.

### Changing a password proves the old one

A person may change their own password, and nobody else's, through the RFC 3062
password modify operation (what `ldappasswd` sends) or an RFC 4511 modify. In
both, **the current password must be sent with the new one**, whatever the
connection bound with. A session bound with an OAUTHBEARER token, which is
short-lived and may be single-factor, could otherwise turn it into a permanent
password that also works for `kinit`.

```
$ ldappasswd -H ldap://localhost:3893 -D uid=alice,ou=people,dc=example,dc=org \
    -W -A -S
```

`-A` asks for the old password and `-S` for the new one. With `ldapmodify`, the
change is a delete of the old value followed by an add of the new one, in one
request:

```
dn: uid=alice,ou=people,dc=example,dc=org
changetype: modify
delete: userPassword
userPassword: the old one
-
add: userPassword
userPassword: the new one
-
```

| Request | Answer |
|---|---|
| no old password, or a bare `replace: userPassword` | `insufficientAccessRights` |
| an old password that is not the current one | `unwillingToPerform` |
| anybody with no password at all (signs in with a token only) | `unwillingToPerform`: a bearer token is not a password, so it cannot set the first one either. An administrator sets it in the configuration. |
| somebody served from a `users` block (a database, another directory) | `unwillingToPerform`: this server reads those sources and does not write them. Only the people written down in the configuration files can change a password here, and the change is written back into the file that declares them. |

This is OpenLDAP's ppolicy behaviour with `pwdSafeModify` set
(slapo-ppolicy(5)), with the result codes its `ppolicy.c` returns. RFC 3062 §3
allows it: "If oldPasswd is not present, the server MAY use other policy to
determine whether or not to change the password." Before v0.7.0 a
bound session could change its password without the old one.

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
authnd: publish_nt_hash needs cert_file and key_file: an NT hash IS the credential,
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
  # digits = 6, period = 30 (seconds) and window = 1 are the defaults. Each
  # step of window is a step of somebody else's guessing time: set it on purpose.
}

user "tess" {
  password    = "…"
  totp_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"   # ⛔ this IS the second factor
}
```

The secret can equally come from a database column or an LDAP attribute — see
[go-authn/directory](https://github.com/go-authn/directory), where it is a
credential like any other. The checking is
[go-authn/totp](https://github.com/go-authn/totp)'s.

What follows from the one field, since none of it is obvious:

- **The split is by length.** The last N characters are the code. A password
  ending in digits is fine; a field *no longer* than a code is refused rather
  than guessed at, because a short password cannot be told apart from a code.
- **Both halves are always checked.** Returning early on a wrong password would
  say, in the time taken, which half was wrong.
- **A code is used once.** It is valid for a whole step, so a server that
  accepts one twice accepts a replay — and every step up to the last accepted
  one is refused, not merely the same one.
- **Guessing is limited per name**, with go-authn/totp's defaults: after five
  wrong codes in a row a person is refused for fifteen minutes, the right code
  included, and after a hundred they are locked out until authnd restarts. The
  count is kept in memory, per process. **Only a code behind the right password
  is counted**: otherwise anybody who knew a name could freeze its owner with
  five binds. Behind a wrong password the code is still computed, so the time
  taken says nothing either way. A reader is counted under its DN as the
  configuration spells it, so `CN=Reader` gets no fresh budget of its own.
- **A secret too short to be one is refused at startup.** A `totp_secret` in a
  `user` or `reader` block under 128 bits (RFC 4226 R6) stops the server,
  naming the person, rather than failing every one of their logins later.
- **Nobody enrolled is not a refusal.** A person with no secret has answered
  nothing rather than answered wrongly, and the server's own output says
  *nobody enrolled an authenticator for this person* while the client is told
  only that the bind failed.
- **Readers do not carry a code** unless `mfa { readers = true }`: a service
  account has no phone. One that does gets a `totp_secret` of its own.
- **No Kerberos realm beside it.** A `kerberos` block and an `mfa` block in
  one configuration are refused at startup. A kinit proves the password and
  nothing else — [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120)'s
  encrypted-timestamp pre-authentication is keyed by the password alone, and a
  second factor needs OTP pre-authentication
  ([RFC 6560](https://www.rfc-editor.org/rfc/rfc6560)) inside FAST, which this
  KDC does not implement. A realm here would hand out tickets on one factor to
  the people this block says need two, so the choice is made closed: one or
  the other.

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
  # preferred_username, then email when email_verified is true, then sub.
  username_claim = "preferred_username"

  # jwks_url skips discovery, for a provider that does not publish it.
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
token in — which is why this page said, for months, that OIDC at the bind
needed "the shape deciding rather than guessing". It did not. RFC 7628 has had
a field for a token since 2015; the library would not carry one.

That is now [`go-authn/ldap`](https://github.com/go-authn/ldap), written here
rather than borrowed, after **six defects** turned up in the parts of the
borrowed one this server actually used — five of them in the fifty lines of
the bind path. Among them:

- a **failed bind left the connection with the previous bind's
  authorisation** (RFC 4511 §4.2.1), so on a pooled connection — how every
  LDAP client library is used — the person whose password was refused was
  served as the last one who succeeded;
- a **substring filter was evaluated as a broader one**, so
  `(uid=svc-*-prod)` returned `svc-web-stage`. In a directory that is
  disclosure, and it is silent, because every entry returned is a real entry.

Those fixes are offered back as glauth/ldap
[#11](https://github.com/glauth/ldap/pull/11),
[#12](https://github.com/glauth/ldap/pull/12) and
[#13](https://github.com/glauth/ldap/pull/13).

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

## A Kerberos realm for the same people

```hcl
kerberos {
  realm    = "EXAMPLE.ORG"
  keytab   = "/etc/authnd/krb5.keytab"   # krbtgt/EXAMPLE.ORG, and a key per service
  listen   = "127.0.0.1:88"              # the default; UDP and TCP both
  lifetime = "10h"                       # the default, MIT's
}
```

A `kerberos` block makes this a KDC as well as a directory, through
[go-authn/kdc](https://github.com/go-authn/kdc): the same people are issued
tickets instead of only being looked up. Startup refuses a realm with no name,
one not in capitals, no keytab, or a keytab without `krbtgt/REALM`, and, as
said above, a `kerberos` block beside an `mfa` block.

A KDC needs the person's **password**, not only a way to check one, so a
person whose source only verifies (an LDAP directory behind this one) can never
be issued a ticket, and neither can one known only by an NT hash, which is the
RC4 key and not the AES key this realm issues. `check` lists who can and who
cannot, and why.

A password changed over LDAP reaches the realm at once: the KDC reads the same
people the directory serves, so the old password stops working for `kinit` the
moment it stops working for a bind.

## `check`, before you restart something people log in through

```
$ authnd check authnd.hcl
ldap://127.0.0.1:3893, base dc=example,dc=org

USER  FROM               CAN PROVE             PUBLISHED AS                                                                         WITH
dora  a sqlite database  a password and 1 key  person, organizationalPerson, inetOrgPerson, posixAccount, ldapPublicKey, uidObject  uid, cn, sn, uidNumber, gidNumber, homeDirectory, mail and sshPublicKey
eli   a sqlite database  a password            account, posixAccount, uidObject                                                     uid, cn, uidNumber, gidNumber and homeDirectory
fay   a sqlite database  a password            person, organizationalPerson, inetOrgPerson, uidObject                               uid, cn, sn and mail
gus   a sqlite database  a password            account, uidObject                                                                   uid
hal   a sqlite database  a password            account, uidObject                                                                   uid
ida   a sqlite database  a password            account, posixAccount, uidObject                                                     uid, cn, uidNumber, gidNumber and homeDirectory

GROUP       MEMBERS       PUBLISHED AS
alumni      nobody        organizationalRole
engineers   dora and eli  posixGroup
nobody-yet  nobody        posixGroup
readers     fay and gus   groupOfNames

fay has no uidNumber, gidNumber or homeDirectory: not a posixAccount, published as person, organizationalPerson, inetOrgPerson, uidObject
gus has no uidNumber, gidNumber or homeDirectory: not a posixAccount, published as account, uidObject
hal has no homeDirectory: not a posixAccount, published as account, uidObject
hal is published without uidNumber: no class of the entry allows it; posixAccount would
hal is published without gidNumber: no class of the entry allows it; posixAccount and posixGroup would
hal is published without mail: no class of the entry allows it; inetOrgPerson would
group alumni has no gidNumber and nobody in it: not a posixGroup, published as an organizationalRole (a groupOfNames needs a member)
group readers has no gidNumber: not a posixGroup, published as a groupOfNames (member DNs, no memberUid)

a bind carries a password
cn=reader,dc=example,dc=org may search; every other bound client may not
sambaNTPassword is not published, so nothing here can authenticate an SMB session (NTLMv2 needs the password or its MD4, and a bind cannot answer it)

this configuration can be served
```

It opens every source, the certificate and the keytab -- everything the server
opens before it listens -- and prints what would be published, without
listening, and never a secret, only where each one comes from. A port somebody
else holds is the one failure it cannot see.

`PUBLISHED AS` is each entry's object classes and `WITH` its attributes, read
off the entries a search would return, built and validated the same way. After
the tables come the people who lack posixAccount's attributes and which ones,
the groups without a `gidNumber` and what they are published as instead, the
people whose NT hash has no `sambaSID` to go with it, every attribute dropped
because no class of its entry allows it (and which classes would), and every entry that is
not published, with each problem `schema.Validate` named.

## The awkward half, said once

**NTLMv2 needs the password or its MD4, and nothing else will do.** A client
never sends a password to an SMB server; it sends a proof computed from one. So
a file server asking authnd about somebody can serve them over SMB only if the
*source* held enough for that — a password, or the hash. A directory that only
*checks* passwords (an LDAP directory behind this one) answers
WebDAV and can never answer SMB, whatever authnd does in between.

`check` prints that per person, and `publish_nt_hash` is the switch that
decides it. Nothing about this is a limitation of this program.

## Verified against real things

- **OpenLDAP's own `ldapsearch`** reads this server: the entries, a filter that
  really filters, the groups, a bind as a person, `Invalid credentials (49)`
  for a wrong password and `Server is unwilling to perform (53)` for the
  unauthenticated bind. A Go client from the same
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
- **RENATER's SUPANN schema**, as published, loaded by `schema_files` and
  served from a SQLite source declaring `supannPerson`, read back by
  `ldapsearch` (`supannEtablissement`, `supannCivilite`, `supannListeRouge`,
  `supannEmpId`, and a filter evaluated with the file's matching rules). The
  file is downloaded only when `LDAP_SCHEMA_NETWORK=1`, checked against its
  recorded SHA-256, and never committed: RENATER publishes it without a licence.
- **The NT hash the tests expect** was computed by an OpenSSL that is not this
  program (`printf 'hunter2' | iconv -t UTF-16LE | openssl md4`, with 1.1,
  since 3.x dropped MD4), and that OpenSSL was itself checked against the value
  every article about NTLM quotes for `password`.

## Building only what you want

| build | size | what it leaves out |
|---|---|---|
| everything | 26.6 MiB | |
| `-tags noldap` | 26.3 MiB | the LDAP **client**, and the `users "ldap"` block |
| `-tags nosql` | 15.1 MiB | the three database drivers, and the `users "sql"` block |
| `-tags nosql,noldap` | 14.8 MiB | both |

As the CI's build-tags lanes print them (linux/amd64, Go 1.27.1,
`CGO_ENABLED=0`).

The server itself is always there; the tags are about where the *people* come
from. `nosql` is by a distance the biggest lever — the three drivers weigh
**11.5 MiB**, close to half the binary — and it is also
attack surface: code that was never compiled cannot be reached.

Each tag lane runs the whole test suite, not a subset: the people arrive as
`user` blocks instead, and every question about binds, searches and refusals
is asked again. A tag lane that skipped its tests would prove only that the
binary links.

## Not yet

- **Writes**, beyond a person changing their own password (above). `add`,
  `delete` and `modifyDN` are answered `unwillingToPerform`, because this server
  implements no handler for them, and so is a `modify` of one's own entry
  that touches anything but `userPassword`. That is *"I do not do that"* — a
  different statement from `insufficientAccessRights`, *"you may not do
  that"*, and it sends an administrator somewhere else.

  What changed is that a correct write is now **expressible**. The library
  this used to stand on held a modify as three buckets — add, delete,
  replace — so

  ```
  delete member=alice; add member=alice     (alice stays)
  add member=alice; delete member=alice     (alice goes)
  ```

  arrived as the *same request*, and no server built on it could tell which
  was asked. `go-authn/ldap` carries them as an **ordered list**, which is
  what RFC 4511 §4.6 requires. A directory this server fronts is still edited
  where it lives; the obstacle to changing that is now policy, not shape.

## Release binaries

Each release carries `authnd` for linux, darwin and windows on amd64 and arm64
(pure Go, `CGO_ENABLED=0`), a `SHA256SUMS` manifest, and a build provenance
attestation per binary, made by this repository's release workflow at the
tag. Check a download before running it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify authnd-linux-amd64 --repo go-authn/authnd
```

`authnd --version` prints the tag it was built from.

To run it as a systemd service -- the account, a hardened unit, a
configuration for each source, TLS, the Kerberos realm, upgrades and roll
back -- see [docs/install.md](docs/install.md).

## Licence

BSD-3-Clause.
