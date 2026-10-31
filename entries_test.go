// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	ldap "github.com/go-authn/ldap"
	"github.com/go-authn/ldap/schema"
)

const shapeKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9Bl6dNhbHqUCLxLLjTe5MDLbLWyWZ9UBjFA+Vx4rJk keys@laptop"

// entriesOf is every entry the server would publish or hold back, by DN.
func entriesOf(t *testing.T, s *server) map[string]*entry {
	t.Helper()
	out := map[string]*entry{}
	for _, e := range s.publish().all {
		out[e.DN] = e
	}
	return out
}

// values is an attribute's values, found whatever its case.
func values(e *ldap.Entry, name string) []string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			out := make([]string, len(a.Values))
			for i, v := range a.Values {
				out[i] = string(v)
			}
			return out
		}
	}
	return nil
}

// The person shapes, one per row of the README's table, each held to the
// schema the server publishes -- and the one that breaks it, held back.
func TestEveryPersonShape(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
reader "cn=reader,dc=example,dc=org" { password = "let me read" }

# Nothing but a name: an account, with uidObject, and no cn -- account does
# not allow one (RFC 4524 3.1).
user "acc" { password = "x" }

# sn: an inetOrgPerson, every superclass listed (RFC 4512 3.3).
user "inet" {
  password   = "x"
  attributes = { sn = "Inet", mail = "inet@example.org", givenName = "In" }
}


# The posix trio and no sn: account + posixAccount.
user "posix" {
  password   = "x"
  attributes = { uidNumber = "1000", gidNumber = "1000", homeDirectory = "/home/posix", loginShell = "/bin/sh" }
}

# Everything: inetOrgPerson + posixAccount + ldapPublicKey.
user "full" {
  password        = "x"
  authorized_keys = ["`+shapeKey+`"]
  attributes      = { sn = "Full", uidNumber = "1001", gidNumber = "1000", homeDirectory = "/home/full" }
}

# Keys and nothing else: account + ldapPublicKey.
user "keys" {
  password        = "x"
  authorized_keys = ["`+shapeKey+`"]
}

# Two of the trio: not a posixAccount -- so uidNumber and gidNumber belong
# to no class it has, and are DROPPED; the rest is published.
user "partial" {
  password   = "x"
  attributes = { uidNumber = "1002", gidNumber = "1000" }
}

# mail on an account (no sn): dropped, the account published.
user "mailacc" {
  password   = "x"
  attributes = { mail = "mailacc@example.org", description = "kept: account allows it" }
}

# A type the schema does not define: dropped too.
user "colour" {
  password   = "x"
  attributes = { favouriteColour = "blue" }
}

# Two home directories: posixAccount allows homeDirectory, SINGLE-VALUE
# forbids two. Nothing to drop -- the entry still fails, and is withheld.
user "twohomes" {
  password   = "x"
  attributes = { uidNumber = "1003", gidNumber = "1000", homeDirectory = ["/home/a", "/home/b"] }
}
`)
	got := entriesOf(t, r.srv)
	dn := func(n string) string { return "uid=" + n + ",ou=people,dc=example,dc=org" }
	for _, tc := range []struct {
		name    string
		classes []string
		cn      bool
	}{
		{"acc", []string{"top", "account", "uidObject"}, false},
		{"inet", []string{"top", "person", "organizationalPerson", "inetOrgPerson", "uidObject"}, true},
		{"posix", []string{"top", "account", "posixAccount", "uidObject"}, true},
		{"full", []string{"top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount", "ldapPublicKey", "uidObject"}, true},
		{"keys", []string{"top", "account", "ldapPublicKey", "uidObject"}, false},
	} {
		e := got[dn(tc.name)]
		if e == nil {
			t.Errorf("%s: no entry", tc.name)
			continue
		}
		if e.invalid != nil {
			t.Errorf("%s fails the schema: %v", tc.name, e.invalid)
		}
		// Asked of the schema directly as well: the invariant is about
		// what Validate says, not about a field this package keeps.
		if err := e.Validate(r.srv.schema); err != nil {
			t.Errorf("%s: Validate: %v", tc.name, err)
		}
		if c := values(e.Entry, "objectClass"); !slices.Equal(c, tc.classes) {
			t.Errorf("%s: objectClass %v, want %v", tc.name, c, tc.classes)
		}
		if u := values(e.Entry, "uid"); !slices.Equal(u, []string{tc.name}) {
			t.Errorf("%s: uid %v", tc.name, u)
		}
		if c := values(e.Entry, "cn"); tc.cn != (len(c) > 0) || (tc.cn && c[0] != tc.name) {
			t.Errorf("%s: cn %v, want it %v and the person's name", tc.name, c, tc.cn)
		}
	}
	// Descriptive attributes are published as given.
	if m := values(got[dn("inet")].Entry, "mail"); !slices.Equal(m, []string{"inet@example.org"}) {
		t.Errorf("inet's mail: %v", m)
	}
	if s := values(got[dn("posix")].Entry, "loginShell"); !slices.Equal(s, []string{"/bin/sh"}) {
		t.Errorf("posix's loginShell: %v", s)
	}
	if k := values(got[dn("keys")].Entry, "sshPublicKey"); !slices.Equal(k, []string{shapeKey}) {
		t.Errorf("keys' sshPublicKey: %v", k)
	}
	if m := got[dn("acc")].missingPosix; !slices.Equal(m, []string{"uidNumber", "gidNumber", "homeDirectory"}) {
		t.Errorf("acc lacks %v", m)
	}

	// The ones published without what no class of theirs allows.
	for _, tc := range []struct {
		name    string
		classes []string
		dropped []string
		would   string
		kept    string
	}{
		{"partial", []string{"top", "account", "uidObject"}, []string{"gidNumber", "uidNumber"}, "posixAccount", ""},
		{"mailacc", []string{"top", "account", "uidObject"}, []string{"mail"}, "inetOrgPerson", "description"},
		{"colour", []string{"top", "account", "uidObject"}, []string{"favouriteColour"}, "does not define it", ""},
	} {
		e := got[dn(tc.name)]
		if e == nil {
			t.Fatalf("%s: no entry built", tc.name)
		}
		if e.invalid != nil {
			t.Errorf("%s is withheld, and dropping %v should have been enough: %v", tc.name, tc.dropped, e.invalid)
		}
		if err := e.Validate(r.srv.schema); err != nil {
			t.Errorf("%s, published, fails Validate: %v", tc.name, err)
		}
		if c := values(e.Entry, "objectClass"); !slices.Equal(c, tc.classes) {
			t.Errorf("%s: objectClass %v, want %v", tc.name, c, tc.classes)
		}
		var names []string
		for _, d := range e.dropped {
			names = append(names, d.name)
			if !strings.Contains(d.why, tc.would) {
				t.Errorf("%s: %s dropped because %q, want it to name %q", tc.name, d.name, d.why, tc.would)
			}
			if values(e.Entry, d.name) != nil {
				t.Errorf("%s: %s was dropped and is still in the entry", tc.name, d.name)
			}
		}
		slices.Sort(names)
		if !slices.Equal(names, tc.dropped) {
			t.Errorf("%s dropped %v, want %v", tc.name, names, tc.dropped)
		}
		if tc.kept != "" && values(e.Entry, tc.kept) == nil {
			t.Errorf("%s: %s, which the entry allows, was dropped with the rest", tc.name, tc.kept)
		}
		if !slices.ContainsFunc(r.srv.publish().valid(), func(v *ldap.Entry) bool { return v.DN == e.DN }) {
			t.Errorf("%s is not among the entries a search may return", tc.name)
		}
	}
	if !slices.Equal(got[dn("partial")].missingPosix, []string{"homeDirectory"}) {
		t.Errorf("partial lacks %v, want [homeDirectory]", got[dn("partial")].missingPosix)
	}
	// Nothing is dropped from an entry whose attributes all fit.
	if d := got[dn("full")].dropped; d != nil {
		t.Errorf("full dropped %v", d)
	}

	// The one that still cannot be published: dropping does not make an
	// entry pass that fails for another reason.
	two := got[dn("twohomes")]
	var v *schema.ValidationError
	if !errors.As(two.invalid, &v) || !v.Has(schema.SingleValued) {
		t.Fatalf("twohomes, with two values of a SINGLE-VALUE type, passed or failed for another reason: %v", two.invalid)
	}
	if two.dropped != nil {
		t.Errorf("twohomes dropped %v: an allowed attribute is never dropped", two.dropped)
	}
	for _, e := range r.srv.publish().valid() {
		if e.DN == dn("twohomes") {
			t.Error("an entry that fails the schema is among those a search may return")
		}
	}
}

// The group shapes: posixGroup with a gidNumber, groupOfNames without one,
// organizationalRole for an empty one without one -- and an empty posixGroup.
func TestEveryGroupShape(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "x" }
user "bob"   { password = "x" }
`)
	gid := func(g string, more ...directory.Attribute) directory.Attributes {
		a, err := directory.NewAttributes(append([]directory.Attribute{{Name: "gidNumber", Values: []string{g}}}, more...)...)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	desc := directory.Attribute{Name: "description", Values: []string{"a group"}}
	descOnly, err := directory.NewAttributes(desc)
	if err != nil {
		t.Fatal(err)
	}
	r.srv.dir = directory.NewSet(&directory.Static{
		Groups: map[string][]string{
			"posix":      {"alice", "bob"},
			"emptyposix": {},
			"names":      {"alice", "bob"},
			"empty":      {},
		},
		GroupAttrs: map[string]directory.Attributes{
			"posix":      gid("100", desc),
			"emptyposix": gid("101"),
			"names":      descOnly,
			"empty":      descOnly,
		},
	})
	reread(t, r.srv)
	got := entriesOf(t, r.srv)
	dn := func(n string) string { return "cn=" + n + ",ou=groups,dc=example,dc=org" }
	people := func(n ...string) []string {
		var out []string
		for _, p := range n {
			out = append(out, "uid="+p+",ou=people,dc=example,dc=org")
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		class     string
		memberUid []string
		member    []string
	}{
		{"posix", "posixGroup", []string{"alice", "bob"}, nil},
		{"emptyposix", "posixGroup", nil, nil},
		{"names", "groupOfNames", nil, people("alice", "bob")},
		{"empty", "organizationalRole", nil, nil},
	} {
		e := got[dn(tc.name)]
		if e == nil {
			t.Errorf("%s: not built", tc.name)
			continue
		}
		if err := e.Validate(r.srv.schema); err != nil || e.invalid != nil {
			t.Errorf("%s fails the schema: %v", tc.name, err)
		}
		if c := values(e.Entry, "objectClass"); !slices.Equal(c, []string{"top", tc.class}) {
			t.Errorf("%s: objectClass %v, want top, %s", tc.name, c, tc.class)
		}
		if c := values(e.Entry, "cn"); !slices.Equal(c, []string{tc.name}) {
			t.Errorf("%s: cn %v", tc.name, c)
		}
		// ⛔ An empty group carries no memberUid and no member at all,
		// rather than an empty one: an attribute has at least one value
		// (RFC 4511 4.1.7).
		if m := values(e.Entry, "memberUid"); !slices.Equal(m, tc.memberUid) {
			t.Errorf("%s: memberUid %v, want %v", tc.name, m, tc.memberUid)
		}
		if m := values(e.Entry, "member"); !slices.Equal(m, tc.member) {
			t.Errorf("%s: member %v, want %v", tc.name, m, tc.member)
		}
	}
	if d := values(got[dn("posix")].Entry, "description"); !slices.Equal(d, []string{"a group"}) {
		t.Errorf("Set.GroupAttributes did not reach the entry: %v", d)
	}
	if d := values(got[dn("empty")].Entry, "description"); !slices.Equal(d, []string{"a group"}) {
		t.Errorf("the empty group's description: %v", d)
	}
	if g := values(got[dn("posix")].Entry, "gidNumber"); !slices.Equal(g, []string{"100"}) {
		t.Errorf("posix's gidNumber: %v", g)
	}
}

// A group attribute no class of its shape allows is dropped, and the group
// published; one that still fails -- a gidNumber that is not an integer -- is
// withheld.
func TestAGroupAttributeNoClassAllowsIsDropped(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "alice" { password = "x" }
`)
	mail, err := directory.NewAttributes(directory.Attribute{Name: "mail", Values: []string{"team@example.org"}},
		directory.Attribute{Name: "description", Values: []string{"a team"}})
	if err != nil {
		t.Fatal(err)
	}
	badGID, err := directory.NewAttributes(directory.Attribute{Name: "gidNumber", Values: []string{"staff"}})
	if err != nil {
		t.Fatal(err)
	}
	r.srv.dir = directory.NewSet(&directory.Static{
		Groups:     map[string][]string{"team": {"alice"}, "bad": {"alice"}},
		GroupAttrs: map[string]directory.Attributes{"team": mail, "bad": badGID},
	})
	reread(t, r.srv)
	got := entriesOf(t, r.srv)
	team := got["cn=team,ou=groups,dc=example,dc=org"]
	if team == nil || team.invalid != nil {
		t.Fatalf("team, a groupOfNames once mail is dropped, is withheld: %+v", team)
	}
	if len(team.dropped) != 1 || team.dropped[0].name != "mail" || !strings.Contains(team.dropped[0].why, "inetOrgPerson") {
		t.Errorf("team dropped %+v, want mail, naming a class that would carry it", team.dropped)
	}
	if values(team.Entry, "mail") != nil || values(team.Entry, "description") == nil {
		t.Errorf("team: mail %v, description %v", values(team.Entry, "mail"), values(team.Entry, "description"))
	}
	bad := got["cn=bad,ou=groups,dc=example,dc=org"]
	var v *schema.ValidationError
	if bad == nil || !errors.As(bad.invalid, &v) || !v.Has(schema.InvalidValue) {
		t.Fatalf("a posixGroup with gidNumber \"staff\" was not withheld for its value: %+v", bad)
	}
	for _, e := range r.srv.publish().valid() {
		if e.DN == bad.DN {
			t.Error("it is among the entries a search may return")
		}
	}
}

// sambaSamAccount: a derived SID, a given one, and a person with an NT key and
// no way to a SID, who is published without sambaNTPassword.
func TestSambaShapes(t *testing.T) {
	r := start(t, `
listen          = "127.0.0.1:0"
base_dn         = "dc=example,dc=org"
publish_nt_hash = true
samba {
  domain_sid           = "S-1-5-21-1-2-3"
  algorithmic_rid_base = 2000
}
reader "cn=reader,dc=example,dc=org" { password = "let me read" }

user "derived" {
  password   = "hunter2"
  attributes = { uidNumber = "1000", gidNumber = "1000", homeDirectory = "/home/derived" }
}
user "given" {
  password   = "hunter2"
  attributes = { sambaSID = "S-1-5-21-1-2-3-555", sn = "Given" }
}
user "nosid" { password = "hunter2" }
user "nokey" {
  authorized_keys = ["`+shapeKey+`"]
  attributes      = { uidNumber = "1003", gidNumber = "1000", homeDirectory = "/home/nokey" }
}
`)
	got := entriesOf(t, r.srv)
	dn := func(n string) string { return "uid=" + n + ",ou=people,dc=example,dc=org" }
	for name, want := range map[string]string{
		// Samba's algorithmic mapping: 2 x 1000 + 2000.
		"derived": "S-1-5-21-1-2-3-4000",
		"given":   "S-1-5-21-1-2-3-555",
	} {
		e := got[dn(name)]
		if e.invalid != nil {
			t.Errorf("%s fails the schema: %v", name, e.invalid)
		}
		if c := values(e.Entry, "objectClass"); !slices.Contains(c, "sambaSamAccount") {
			t.Errorf("%s: objectClass %v has no sambaSamAccount", name, c)
		}
		if s := values(e.Entry, "sambaSID"); !slices.Equal(s, []string{want}) {
			t.Errorf("%s: sambaSID %v, want %s", name, s, want)
		}
		if h := values(e.Entry, "sambaNTPassword"); !slices.Equal(h, []string{hunter2NTHash}) {
			t.Errorf("%s: sambaNTPassword %v", name, h)
		}
	}
	nosid := got[dn("nosid")]
	if nosid.invalid != nil {
		t.Errorf("nosid fails the schema: %v", nosid.invalid)
	}
	if h := values(nosid.Entry, "sambaNTPassword"); h != nil {
		t.Errorf("nosid has no sambaSID and was published with sambaNTPassword %v", h)
	}
	if !strings.Contains(nosid.noSID, "no uidNumber") {
		t.Errorf("nosid: the reason is %q", nosid.noSID)
	}
	// No NT key: no sambaSamAccount, and nothing to say about a SID.
	nokey := got[dn("nokey")]
	if c := values(nokey.Entry, "objectClass"); slices.Contains(c, "sambaSamAccount") {
		t.Errorf("nokey, who has no NT key, is a sambaSamAccount: %v", c)
	}
	if nokey.noSID != "" {
		t.Errorf("nokey: %q", nokey.noSID)
	}
	// And startup said what it held back.
	if !strings.Contains(r.out.String(), "uid=nosid,ou=people,dc=example,dc=org is published without sambaNTPassword") {
		t.Errorf("startup did not say nosid has no sambaNTPassword:\n%s", r.out)
	}
}

// What a samba block must be, and what publish_nt_hash now needs.
func TestTheSambaConfiguration(t *testing.T) {
	base := `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "svc" { password = "x" }
`
	for _, tc := range []struct{ name, body, want string }{
		{"publish_nt_hash without samba", "publish_nt_hash = true", "publish_nt_hash needs a samba block"},
		{"samba without publish_nt_hash", `samba { domain_sid = "S-1-5-21-1-2-3" }`, "without publish_nt_hash publishes nothing"},
		{"not a SID", "publish_nt_hash = true\n" + `samba { domain_sid = "S-1-5-21-x" }`, "is not a number a SID can hold"},
		{"not even close", "publish_nt_hash = true\n" + `samba { domain_sid = "domain" }`, "not a SID"},
		{"a sub-authority too large", "publish_nt_hash = true\n" + `samba { domain_sid = "S-1-5-21-4294967296" }`, "is not a number"},
		{"too many sub-authorities", "publish_nt_hash = true\n" + `samba { domain_sid = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15" }`, "no room for a RID"},
		{"an odd rid base", "publish_nt_hash = true\n" + `samba {
  domain_sid           = "S-1-5-21-1-2-3"
  algorithmic_rid_base = 1001
}`, "algorithmic_rid_base = 1001"},
		{"a rid base below Samba's floor", "publish_nt_hash = true\n" + `samba {
  domain_sid           = "S-1-5-21-1-2-3"
  algorithmic_rid_base = 998
}`, "at least 1000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", base+tc.body)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one saying %q", err, tc.want)
			}
		})
	}
	// The refusal says what to add.
	_, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", base+"publish_nt_hash = true")})
	if err == nil || !strings.Contains(err.Error(), `domain_sid = "S-1-5-21-...`) || !strings.Contains(err.Error(), "sambaSamAccount") {
		t.Errorf("the refusal does not say what to add: %v", err)
	}
	// And a good one loads.
	if _, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", base+"publish_nt_hash = true\n"+
		`samba { domain_sid = "S-1-5-21-1004336348-1177238915-682003330" }`)}); err != nil {
		t.Errorf("a valid samba block was refused: %v", err)
	}
}

// The RID limits of Samba's algorithmic mapping.
func TestASambaSIDOutOfRange(t *testing.T) {
	r := start(t, `
listen          = "127.0.0.1:0"
base_dn         = "dc=example,dc=org"
publish_nt_hash = true
samba { domain_sid = "S-1-5-21-1-2-3" }
user "big" {
  password   = "x"
  attributes = { uidNumber = "2147483648" }
}
user "nan" {
  password   = "x"
  attributes = { uidNumber = "lots" }
}
`)
	got := entriesOf(t, r.srv)
	if why := got["uid=big,ou=people,dc=example,dc=org"].noSID; !strings.Contains(why, "too large") {
		t.Errorf("big: %q", why)
	}
	if why := got["uid=nan,ou=people,dc=example,dc=org"].noSID; !strings.Contains(why, "not a number") {
		t.Errorf("nan: %q", why)
	}
}

// The second failure: "both" has an attribute to drop and another problem
// dropping does not touch.
func TestDroppingDoesNotMakeAnEntryPass(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "both" {
  password   = "x"
  attributes = { mail = "both@example.org", seeAlso = "not a DN at all" }
}
`)
	e := entriesOf(t, r.srv)["uid=both,ou=people,dc=example,dc=org"]
	var v *schema.ValidationError
	if !errors.As(e.invalid, &v) || !v.Has(schema.InvalidValue) {
		t.Fatalf("both, whose seeAlso is not a DN, passed once mail was dropped: %v", e.invalid)
	}
	if v.Has(schema.NotAllowed) {
		t.Errorf("the problem left is not the one dropping fixes: %v", e.invalid)
	}
	for _, p := range r.srv.publish().valid() {
		if p.DN == e.DN {
			t.Error("both is among the entries a search may return")
		}
	}
}

// Only what a source gave is dropped. An attribute this server put there
// itself -- here a cn on a bare account -- that the schema refuses is a
// mistake in this server, and the entry is withheld rather than published
// without it.
func TestADerivedAttributeIsNeverDropped(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "x" { password = "x" }
`)
	e := r.srv.validated(&entry{
		Entry: &ldap.Entry{DN: "uid=x,ou=people,dc=example,dc=org", Attributes: []*ldap.Attribute{
			ldap.StringAttribute("objectClass", "top", "account", "uidObject"),
			ldap.StringAttribute("uid", "x"),
			ldap.StringAttribute("cn", "x"),
		}},
		given: map[string]bool{},
	})
	if e.invalid == nil {
		t.Error("an entry whose derived cn no class allows was published without it")
	}
	if e.dropped != nil || values(e.Entry, "cn") == nil {
		t.Errorf("the derived cn was dropped: %v", e.dropped)
	}
}
