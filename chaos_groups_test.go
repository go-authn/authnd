// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/ldap"
)

// reread is what a test that replaces the sources after start must call: the
// groups are read once (groups.go), and so is the publication built from them.
func reread(t *testing.T, srv *server) {
	t.Helper()
	g, err := readGroups(srv.dir, srv.sorted())
	if err != nil {
		t.Fatal(err)
	}
	srv.groups = g
	srv.published.Store(nil)
}

// brokenSource fails at the stage it is told to, and otherwise has one group.
type brokenSource struct{ stage string }

var errBroken = errors.New("the database went away")

func (b brokenSource) Describe() string                           { return "a broken source" }
func (b brokenSource) Identities() ([]*directory.Identity, error) { return nil, nil }
func (b brokenSource) fail(stage string) error {
	if b.stage == stage {
		return errBroken
	}
	return nil
}
func (b brokenSource) GroupNames() ([]string, error) { return []string{"g"}, b.fail("names") }
func (b brokenSource) Members(string) ([]string, error) {
	return []string{"a"}, b.fail("members")
}
func (b brokenSource) GroupAttributes(string) (directory.Attributes, error) {
	return directory.Attributes{}, b.fail("attributes")
}
func (b brokenSource) GroupObjectClasses(string) (directory.ObjectClasses, error) {
	return directory.ObjectClasses{}, b.fail("classes")
}

// Every way reading a group can fail refuses startup, naming the stage and the
// source, and keeps the cause.
func TestChaosReadGroupsRefusesWhateverStageFails(t *testing.T) {
	for stage, want := range map[string]string{
		"names":      "listing the groups of a broken source",
		"members":    `reading the members of group "g"`,
		"attributes": `reading the attributes of group "g"`,
		"classes":    `reading the object classes of group "g"`,
	} {
		t.Run(stage, func(t *testing.T) {
			_, err := readGroups(directory.NewSet(brokenSource{stage}), nil)
			if err == nil || !strings.Contains(err.Error(), want) || !errors.Is(err, errBroken) {
				t.Fatalf("got %v, want %q wrapping the cause", err, want)
			}
		})
	}
	if _, err := readGroups(directory.NewSet(brokenSource{"none"}), nil); err != nil {
		t.Fatalf("a source that works was refused: %v", err)
	}
}

// ⛔ One source down among two is a refusal, not a smaller directory:
// directory.Set.GroupNames keeps what the other source named and drops the
// error, and this is the case it was blind to.
func TestChaosOneSourceDownAmongTwoRefuses(t *testing.T) {
	ok := &directory.Static{Name: "fine", Groups: map[string][]string{"staff": {"ann"}}}
	_, err := readGroups(directory.NewSet(ok, brokenSource{"names"}), nil)
	if err == nil || !errors.Is(err, errBroken) {
		t.Fatalf("a set with one source down was read as complete: %v", err)
	}
}

// A group a person names and no source has is listed and not published.
func TestChaosGroupNamedByAPersonOnly(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "ann" { password = "x" }
`)
	ann := directory.NewIdentity("ann", directory.WithGroups("ghosts"))
	snap, err := readGroups(directory.NewSet(&directory.Static{People: []*directory.Identity{ann}}), []*directory.Identity{ann})
	if err != nil {
		t.Fatal(err)
	}
	r.srv.groups = snap
	r.srv.published.Store(nil)
	f := r.srv.groups.by["ghosts"]
	if f == nil || f.missing == nil {
		t.Fatalf("a group only a person names must be listed as missing: %+v", f)
	}
	for _, e := range r.srv.publish().valid() {
		if strings.Contains(e.DN, "cn=ghosts") {
			t.Fatalf("a group no source has was published: %s", e.DN)
		}
	}
	if _, err := r.srv.groupEntry("ghosts", nil); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Fatalf("groupEntry of a missing group: %v", err)
	}
	if _, err := r.srv.groupEntry("never heard of it", nil); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Fatalf("groupEntry of an unknown group: %v", err)
	}
}

// A source that cannot list groups is skipped, not refused.
type unlisting struct{}

func (unlisting) Describe() string                           { return "a source that cannot list" }
func (unlisting) Identities() ([]*directory.Identity, error) { return nil, nil }
func (unlisting) Members(string) ([]string, error)           { return nil, directory.ErrNoSuchGroup }

func TestChaosSourceThatCannotListIsSkipped(t *testing.T) {
	snap, err := readGroups(directory.NewSet(unlisting{}), nil)
	if err != nil || len(snap.names) != 0 {
		t.Fatalf("got %v %v", snap, err)
	}
}

// A group that declares a class whose MUST it cannot meet is published without
// the class, like a person is.
func TestChaosGroupLeftOffADeclaredClassItCannotMeet(t *testing.T) {
	srv, err := openBody(t, exampleConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	staff, _ := directory.NewObjectClasses("exampleStaff")
	srv.dir.Add(&directory.Static{Name: "crew list", Groups: map[string][]string{"crew": {"ann"}},
		GroupClasses: map[string]directory.ObjectClasses{"crew": staff}})
	reread(t, srv)
	e := entryOf(t, srv.publish(), "crew", true)
	if e.invalid != nil || len(e.leftOff) == 0 {
		t.Fatalf("crew: invalid=%v leftOff=%v", e.invalid, e.leftOff)
	}
}

// A value too large for one message withholds the entry, and the rest of the
// search is answered.
func TestChaosEntryTooLargeIsWithheld(t *testing.T) {
	e := &entry{Entry: &ldap.Entry{DN: "uid=big,ou=people,dc=example,dc=org",
		Attributes: []*ldap.Attribute{ldap.StringAttribute("sn", strings.Repeat("x", maxEntryBytes))}}}
	sized(e)
	if e.invalid == nil || !strings.Contains(e.invalid.Error(), "more than the") {
		t.Fatalf("an entry of %d bytes was not withheld: %v", maxEntryBytes, e.invalid)
	}
	small := &entry{Entry: &ldap.Entry{DN: "uid=a,dc=x", Attributes: []*ldap.Attribute{ldap.StringAttribute("sn", "A")}}}
	sized(small)
	if small.invalid != nil {
		t.Fatalf("a small entry was withheld: %v", small.invalid)
	}
	// An entry already withheld keeps its own reason.
	why := fmt.Errorf("fails the schema")
	failing := &entry{Entry: e.Entry, invalid: why}
	sized(failing)
	if failing.invalid != why {
		t.Fatalf("the reason was overwritten: %v", failing.invalid)
	}
}

// The publication is built once for as long as the people are the same people,
// and again when a password change swaps them.
func TestChaosPublicationIsKeptUntilThePeopleChange(t *testing.T) {
	r := start(t, `
listen  = "127.0.0.1:0"
base_dn = "dc=example,dc=org"
user "ann" { password = "x" }
`)
	a, b := r.srv.publish(), r.srv.publish()
	if len(a.all) == 0 || &a.all[0] != &b.all[0] {
		t.Fatal("the second publish rebuilt the entries")
	}
	roster, err := newRoster(r.srv.sorted())
	if err != nil {
		t.Fatal(err)
	}
	r.srv.people.Store(roster)
	if c := r.srv.publish(); &c.all[0] == &a.all[0] {
		t.Fatal("new people, old publication")
	}
}
