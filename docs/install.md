# Installing authnd on Linux with systemd

This page installs a release binary as a systemd service: the account it runs
as, the unit, a configuration for each place people can come from, TLS, the
Kerberos realm, and then upgrading, rolling back and removing it.

Everything below was run on Ubuntu 24.04 (systemd 255, arm64) against the
v0.9.3 release. Where something was not run, the section says so.

> **Coming, not available:** go-pkgx will later offer versioned services
> (`pkgm service`), which will install and upgrade authnd in place of the
> manual steps here. It does not exist yet. Until it does, this page is the way.

## 1. Download and verify

Each release carries `authnd-<os>-<arch>`, a `SHA256SUMS` manifest, and a build
provenance attestation per binary.

```sh
version=v0.9.3
arch=amd64          # or arm64
base=https://github.com/go-authn/authnd/releases/download/$version

curl -fsSLO "$base/authnd-linux-$arch"
curl -fsSLO "$base/SHA256SUMS"

# The bytes are the ones the release published:
sha256sum -c SHA256SUMS --ignore-missing

# And the release was built by this repository's workflow, at that tag:
gh attestation verify "authnd-linux-$arch" --repo go-authn/authnd
```

`gh attestation verify` needs the GitHub CLI, which can run on any machine: the
check is about the file, not about where it is run. Stop if either check fails.

## 2. Install the binary, the account and the unit

The two packaging files are in this repository:
[`packaging/sysusers.d/authnd.conf`](../packaging/sysusers.d/authnd.conf) and
[`packaging/systemd/authnd.service`](../packaging/systemd/authnd.service).

```sh
sudo install -m 0755 "authnd-linux-$arch" /usr/local/bin/authnd
authnd --version                       # authnd version v0.9.3

sudo install -m 0644 authnd.conf    /usr/lib/sysusers.d/authnd.conf
sudo systemd-sysusers /usr/lib/sysusers.d/authnd.conf    # creates the authnd user and group

sudo install -m 0644 authnd.service /etc/systemd/system/authnd.service
sudo systemd-analyze verify /etc/systemd/system/authnd.service
sudo systemctl daemon-reload
```

### What the unit grants, and why

| | |
|---|---|
| **Account** | a static `authnd` user from sysusers.d, not `DynamicUser=`. The files authnd reads -- password files, a DSN, a keytab, a TLS key -- are secrets given to the `authnd` group ahead of time, and a password change writes back into them. A dynamic uid does not exist until the service starts, and what it writes would belong to a number that later means somebody else. |
| **Capabilities** | `CAP_NET_BIND_SERVICE`, in both `AmbientCapabilities=` and `CapabilityBoundingSet=`, and nothing else: LDAP is 389, LDAPS 636, Kerberos 88 over UDP and TCP. |
| **Configuration** | `ExecStart=/usr/local/bin/authnd --config /etc/authnd`: every `.hcl` file in that directory, read as one, in name order. |
| **State** | none of its own. TOTP lockout counts are kept in memory and reset at restart; the KDC's keys are the keytab the configuration names. `StateDirectory=authnd` provides `/var/lib/authnd` (0700, owned by `authnd`) for a SQLite database. |
| **File system** | `ProtectSystem=strict`: read-only everywhere except `/var/lib/authnd`. A password change therefore needs the drop-in in [section 6](#6-letting-people-change-their-own-password). |
| **Reload** | there is none: authnd reads its configuration, TLS certificate and keytab once. After changing any of them: `systemctl restart authnd`. Since v0.9.4 a `SIGHUP` (from logrotate, or a habit) is caught and logged, and authnd stays up. Before v0.9.4 it **killed** authnd, and systemd counted that as a clean exit, so `Restart=on-failure` did not start it again. |

`systemd-analyze security authnd` rates it **1.4 OK**. What remains is what a
network directory is:

| finding | exposure | why it stays |
|---|---|---|
| `PrivateNetwork=` | 0.5 | it answers on the network |
| `RestrictAddressFamilies=~AF_INET/AF_INET6` | 0.3 | same |
| `PrivateUsers=` | 0.2 | inside a user namespace `CAP_NET_BIND_SERVICE` no longer applies to the host's network: the bind to 389 is refused |
| `IPAddressDeny=` | 0.2 | which networks may ask is the site's decision; add it in a drop-in |
| `AmbientCapabilities=`, `CAP_NET_BIND_SERVICE` | 0.1 + 0.1 | ports 88, 389, 636 |
| `RestrictAddressFamilies=~AF_UNIX` | 0.1 | a local PostgreSQL or MariaDB is reached through its socket |
| `ProcSubset=` | 0.1 | `ProcSubset=pid` hides `/proc/sys/net/core/somaxconn`, and every listener's backlog fell from 4096 to Go's fallback of 128 |
| `DeviceAllow=` (char-rtc:r) | 0.1 | comes with `ProtectClock=` |
| `RootDirectory=` | 0.1 | |

To restrict who may connect, for example:

```sh
sudo systemctl edit authnd
```

```ini
[Service]
IPAddressDeny=any
IPAddressAllow=localhost 10.0.0.0/8
```

## 3. Configure

The configuration directory belongs to root and is readable by the `authnd`
group only, because it holds secrets:

```sh
sudo install -d -o root -g authnd -m 0750 /etc/authnd
```

Every file inside it: `root:authnd`, mode `0640`. Secrets go in files named by
`*_file` keys rather than inline, because a file has permissions and a
configuration someone pastes does not.

These keys apply to every configuration:

| key | required | default | |
|---|---|---|---|
| `base_dn` | **yes** | | the root of the tree, e.g. `dc=example,dc=org`. People are under `ou=people`, groups under `ou=groups`. |
| `listen` | no | `127.0.0.1:3893` | one address. `0.0.0.0:389` for LDAP, `0.0.0.0:636` for LDAPS. A site that needs both runs two instances, each with its own `--config`. |
| `reader "<dn>"` | no | | a service account that may **search**, with `password` or `password_file`. Without one, nothing may search: a bind is not permission to read everybody. |
| at least one person | **yes** | | a `user` block or a `users` block: authnd refuses to start with nobody to serve. |

Before every restart:

```sh
sudo -u authnd authnd check /etc/authnd
```

`check` opens every source -- the database, the directory, the files -- and the
certificate and keytab, and prints who would be published and what each can
prove, without listening and without printing a secret.

### People written in the file

```hcl
# /etc/authnd/authnd.hcl
listen  = "0.0.0.0:389"
base_dn = "dc=example,dc=org"

reader "cn=reader,dc=example,dc=org" { password_file = "/etc/authnd/reader.pw" }

user "alice" { password_file = "/etc/authnd/passwords/alice.pw" }
user "bob"   { password_file = "/etc/authnd/passwords/bob.pw" }

group "staff" { members = ["alice", "bob"] }
```

A `user` block takes `password` or `password_file` (not both), or `nt_hash`
(MD4 of the UTF-16LE password, 32 hex digits) instead of a password, and
optionally `totp_secret`, `authorized_keys` or `authorized_keys_file`. A
`group` needs at least one member. A password file holds the password on one
line.

### People in a SQL database

`driver` is `postgres`, `mysql` (or `mariadb`) or `sqlite`. `dsn_file` and
`users` are required; `groups` is optional. The queries are yours: `users`
returns, in this order, a name and then any of a password, an NT hash, SSH keys
and a TOTP secret (a NULL is a credential that person does not have), and
`groups` returns a group name and a member, one row per membership.

The password column is compared **as it is stored**. authnd has no setting for
a hashed column: a bcrypt or `crypt(3)` value there is taken for the password
itself, and nobody binds. A directory that keeps only hashes belongs behind a
`users "ldap"` source instead, which checks a password by binding.

PostgreSQL on the same machine, through its socket and peer authentication, so
the DSN holds no password:

```hcl
# /etc/authnd/people.hcl
users "sql" {
  driver   = "postgres"
  dsn_file = "/etc/authnd/pg.dsn"
  users    = "select login, secret from staff"
  groups   = "select team, member from team_members"
}
```

```sh
echo 'host=/run/postgresql dbname=authnd user=authnd' | sudo tee /etc/authnd/pg.dsn
sudo -u postgres psql -c 'create role authnd login'     # and GRANT SELECT on the two tables
```

The socket needs nothing added to the unit: connecting to a socket is allowed
on a read-only file system. A database on another host is a DSN like
`postgres://authnd:…@db.example.org/people?sslmode=verify-full`, and that file
then holds a password.

SQLite, in the state directory:

```hcl
users "sql" {
  driver   = "sqlite"
  dsn_file = "/etc/authnd/sqlite.dsn"
  users    = "select name, password from people"
}
```

```sh
echo 'file:/var/lib/authnd/people.db' | sudo tee /etc/authnd/sqlite.dsn
```

The database is reached at startup, before authnd listens: one that is not
answering stops the service with that reason in `journalctl -u authnd`.

### People in another LDAP directory

`url` and `base_dn` are required. `ldap://` to anything but loopback is refused
without `start_tls = true`, because the bind password would cross the network
in the clear; and credentials in the `url` are refused, because a URL gets
printed.

```hcl
users "ldap" {
  url                = "ldaps://ldap.example.org"
  base_dn            = "ou=people,dc=example,dc=org"
  bind_dn            = "cn=reader,dc=example,dc=org"
  bind_password_file = "/etc/authnd/upstream.pw"
  # user_filter = "(objectClass=posixAccount)", user_attribute = "uid",
  # group_filter = "(objectClass=posixGroup)", group_attribute = "cn" and
  # group_member_attribute = "memberUid" are the defaults. totp_attribute has
  # none: name it if the directory holds one-time-code secrets.
}
```

A directory behind this one only *checks* passwords, so its people can bind
but can never be issued a Kerberos ticket. `check` says so per person.

Sources are asked in the order they are written, and the first that knows a
name owns it.

## 4. TLS (optional)

authnd reads a certificate and key from files; it has no ACME client of its
own. Use whatever writes the two files -- go-authn/servercert, certbot, a
site's own CA -- and restart authnd after each renewal, because the
certificate is read once, at start.

```hcl
listen    = "0.0.0.0:636"            # ldaps://: the handshake comes first
cert_file = "/etc/authnd/cert.pem"   # the chain, leaf first
key_file  = "/etc/authnd/key.pem"
```

Or StartTLS on 389, where the listener refuses every bind and search until the
client has upgraded:

```hcl
listen    = "0.0.0.0:389"
starttls  = true
cert_file = "/etc/authnd/cert.pem"
key_file  = "/etc/authnd/key.pem"
```

Both files `root:authnd 0640`. With certbot, a deploy hook does the copy and
the restart:

```sh
# /etc/letsencrypt/renewal-hooks/deploy/authnd
install -o root -g authnd -m 0640 "$RENEWED_LINEAGE/fullchain.pem" /etc/authnd/cert.pem
install -o root -g authnd -m 0640 "$RENEWED_LINEAGE/privkey.pem"   /etc/authnd/key.pem
systemctl restart authnd
```

`publish_nt_hash = true` requires TLS unless `listen` is loopback: an NT hash
is the credential itself.

## 5. A Kerberos realm (optional)

```hcl
kerberos {
  realm    = "EXAMPLE.ORG"               # required, upper case
  keytab   = "/etc/authnd/krb5.keytab"   # required; must hold krbtgt/EXAMPLE.ORG
  listen   = "0.0.0.0:88"                # default 127.0.0.1:88, udp and tcp
  lifetime = "10h"                       # the default
}
```

The keytab holds the key authnd signs its own tickets with, and one key per
service it issues tickets to. MIT's `ktutil` (package `krb5-user` on Debian and
Ubuntu) writes one; the krbtgt password is never typed again, so make it random:

```sh
printf 'addent -password -p krbtgt/EXAMPLE.ORG@EXAMPLE.ORG -k 1 -e aes256-cts-hmac-sha1-96\n%s\nwkt /tmp/krb5.keytab\nquit\n' \
  "$(head -c 32 /dev/urandom | base64)" | ktutil
sudo install -o root -g authnd -m 0640 /tmp/krb5.keytab /etc/authnd/krb5.keytab
rm /tmp/krb5.keytab
```

Add a service's key the same way (`-p nfs/files.example.org@EXAMPLE.ORG`), and
give that service the same key in its own keytab.

A `kerberos` block and an `mfa` block cannot both be present: a kinit carries
the password and nothing else, so a realm here would issue tickets on one
factor to people the `mfa` block says need two. Only people whose source holds
the password itself (a `user` block, a SQL password column) can be issued a
ticket.

## 6. Letting people change their own password

A person may change their own password over LDAP (`ldappasswd`), and only if
they are declared in a `user` block. The change is written back to the file
that holds it, through a temporary file and a rename in the **same
directory**, so the account needs write access to that directory -- which
`ProtectSystem=strict` takes away. Without the drop-in below, a change is
refused with `the password could not be written`, and the journal says
`read-only file system`.

Keep the passwords in a directory of their own, so that the configuration
itself stays read-only to the service:

```sh
sudo install -d -o authnd -g authnd -m 0700 /etc/authnd/passwords
sudo systemctl edit authnd
```

```ini
[Service]
ReadWritePaths=/etc/authnd/passwords
```

Every `user` block then uses `password_file = "/etc/authnd/passwords/<name>.pw"`.
A person whose password is written inline (`password = "…"`) would need
`/etc/authnd` itself writable, which would also let the service rewrite its own
configuration: prefer the separate directory.

## 7. Enable and check

```sh
sudo systemctl enable --now authnd
systemctl status authnd
journalctl -u authnd
```

```text
ldap on [::]:389, serving 4 people from the configuration file, then a postgres database, then a sqlite database
realm EXAMPLE.ORG on 127.0.0.1:88 (udp and tcp)
```

A bind as a person, and a search as the reader (`ldap-utils`):

```sh
ldapwhoami -x -H ldap://127.0.0.1 -D uid=alice,ou=people,dc=example,dc=org -W
ldapsearch -x -LLL -H ldap://127.0.0.1 -D cn=reader,dc=example,dc=org -W \
  -b dc=example,dc=org '(uid=alice)'
```

A search by anybody but a reader is answered `Insufficient access (50)`.

A ticket (`krb5-user`), with a krb5.conf that names this KDC. ⛔ The braces go
on their own lines: MIT's parser silently ignores a realm written on one line.

```ini
[libdefaults]
    default_realm = EXAMPLE.ORG
    dns_lookup_kdc = false
[realms]
    EXAMPLE.ORG = {
        kdc = authnd.example.org:88
    }
```

```sh
kinit alice && klist
```

The process runs as `authnd` with one capability:

```sh
pid=$(systemctl show -p MainPID --value authnd)
grep -E '^(Uid|CapEff|CapBnd|CapAmb)' /proc/$pid/status    # CapEff: 0000000000000400
capsh --decode=0000000000000400                             # cap_net_bind_service
```

## 8. Upgrade

Download and verify the new release as in [section 1](#1-download-and-verify),
then check the configuration with the **new** binary before it replaces the old
one:

```sh
sudo -u authnd ./authnd-linux-$arch check /etc/authnd
sudo cp /usr/local/bin/authnd /usr/local/bin/authnd.previous
sudo install -m 0755 "authnd-linux-$arch" /usr/local/bin/authnd
sudo systemctl restart authnd
authnd --version
```

Compare `packaging/` at the new tag with what is installed; a changed unit is
installed the same way as in section 2, followed by `systemctl daemon-reload`.

## 9. Roll back

```sh
sudo install -m 0755 /usr/local/bin/authnd.previous /usr/local/bin/authnd
sudo systemctl restart authnd
authnd --version
```

## 10. Uninstall

```sh
sudo systemctl disable --now authnd
sudo rm /etc/systemd/system/authnd.service
sudo rm -r /etc/systemd/system/authnd.service.d     # if a drop-in was added
sudo systemctl daemon-reload
sudo rm /usr/local/bin/authnd /usr/local/bin/authnd.previous
sudo rm /usr/lib/sysusers.d/authnd.conf
```

The configuration (`/etc/authnd`), the state directory (`/var/lib/authnd`) and
the `authnd` account are left in place, because the first two hold people's
credentials and a uid that is reused can be given someone else's files. Remove
them deliberately:

```sh
sudo rm -r /etc/authnd /var/lib/authnd
sudo userdel authnd                  # the group goes with it
```

## What was verified, and what was not

On Ubuntu 24.04, systemd 255, arm64, with the v0.9.3 release binary:

- the SHA256SUMS check and `gh attestation verify`;
- `systemd-analyze verify` (clean) and `systemd-analyze security` (1.4);
- a bind and a search with OpenLDAP's `ldapsearch`/`ldapwhoami` on 389, and an
  anonymous search refused;
- people from a `user` block, from PostgreSQL 16 through `/run/postgresql` with
  peer authentication, and from SQLite in `/var/lib/authnd`;
- LDAPS on 636 with a certificate from files;
- `kinit` and `klist` against the realm on 88, and a wrong password refused;
- the process as `authnd`, `CapEff`, `CapBnd` and `CapAmb` all
  `cap_net_bind_service` only, `NoNewPrivs: 1`, seccomp on;
- `ldappasswd` refused without the drop-in and accepted with
  `ReadWritePaths=/etc/authnd/passwords`, the new password then working for
  both the bind and `kinit`;
- `SIGHUP` stopping the service for good, on v0.9.3; v0.9.4 catches it and stays up;
- the upgrade (v0.9.2 to v0.9.3), the roll back and the uninstall, as written.

Not run: a `users "ldap"` block against another directory, MySQL/MariaDB,
StartTLS, the certbot hook, and amd64 (the unit does not depend on the
architecture).
