// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-authn/directory"
	ldap "github.com/go-authn/ldap"
	"github.com/go-authn/ldap/schema"
)

// The entries this server publishes, and the schema they are held to.
//
// ⛔ EVERY ENTRY PUBLISHED PASSES schema.Validate AGAINST THE SCHEMA THIS
// SERVER PUBLISHES at cn=Subschema. An attribute a source gave that no class
// of the entry allows -- a uidNumber without gidNumber and homeDirectory, a
// mail on an account -- is DROPPED, the entry is published with the rest,
// and the startup log and `authnd check` name it with the reason. An entry
// that still fails is not published at all -- not served with a problem in
// it -- and `authnd check` names it with every problem Validate found. Up to
// v0.10.2 every person was "top, person,
// posixAccount" with no uidNumber, gidNumber, homeDirectory or sn, which
// broke four MUSTs at once, and sambaNTPassword sat on an entry with no class
// that allows it. A client that reads the schema and believes it -- an
// LDAP browser, a sync tool, a directory replicating this one -- was being
// told one thing and shown another.
//
// The shapes (RFC 4512 §3.3: every superclass is listed):
//
//	person   top, account                                        no sn
//	         top, person, organizationalPerson, inetOrgPerson    sn given
//	       + posixAccount     uidNumber, gidNumber, homeDirectory all given
//	       + ldapPublicKey    SSH keys
//	       + sambaSamAccount  publish_nt_hash, an NT key and a sambaSID
//	       + uidObject        always
//	group    top, posixGroup        gidNumber given
//	         top, groupOfNames      no gidNumber, somebody in it
//	         top, organizationalRole  no gidNumber, nobody in it

// An entry is one entry this server would publish, with what it is and, when
// it fails the schema, why it is not published.
type entry struct {
	*ldap.Entry
	// name is the person's or the group's name, for a sentence about it.
	name string
	// group says which of the two it is.
	group bool
	// shape is the object classes, minus top: what `check` says it is
	// published as.
	shape []string
	// missingPosix is which of posixAccount's MUSTs a person lacks, when
	// they lack some: they are published without posixAccount.
	missingPosix []string
	// noSID is why a person whose NT hash would be published has no
	// sambaSID, and so no sambaNTPassword.
	noSID string
	// given are the descriptions a source gave (Identity.Attributes,
	// Set.GroupAttributes): the only attributes that may be dropped.
	given map[string]bool
	// dropped are the given attributes no class of the entry allows, left
	// out so that the rest of the entry can be published.
	dropped []dropped
	// invalid is what schema.Validate said, nil for an entry that passes.
	invalid error
	// declared are the declared object classes the entry carries (by their
	// schema names), and leftOff the declared ones it does not, with why.
	declared []string
	leftOff  []leftOff
}

// A dropped attribute is one a source gave that the entry could not carry,
// and why.
type dropped struct {
	name, why string
}

// publication is what a search can return: the entries that pass the schema.
type publication struct {
	all []*entry
}

// valid is the entries that pass, in the order they were built.
func (p publication) valid() []*ldap.Entry {
	var out []*ldap.Entry
	for _, e := range p.all {
		if e.invalid == nil {
			out = append(out, e.Entry)
		}
	}
	return out
}

// rejected is the entries that do not pass, and are not published.
func (p publication) rejected() []*entry {
	var out []*entry
	for _, e := range p.all {
		if e.invalid != nil {
			out = append(out, e)
		}
	}
	return out
}

// publish builds every entry and holds each one to the schema.
func (s *server) publish() publication {
	var p publication
	for _, id := range s.sorted() {
		e := s.personEntry(id, nil)
		if off, skip := s.unmet(e); len(off) > 0 {
			e = s.personEntry(id, skip)
			e.leftOff = append(e.leftOff, off...)
		}
		p.all = append(p.all, s.placedAndValidated(e))
	}
	for _, name := range s.groupNames() {
		e, err := s.groupEntry(name, nil)
		if err != nil {
			// A source that cannot answer for a group: it is left out, as it
			// was before, and `check` says so from its own question.
			continue
		}
		if off, skip := s.unmet(e); len(off) > 0 {
			if e, err = s.groupEntry(name, skip); err != nil {
				continue
			}
			e.leftOff = append(e.leftOff, off...)
		}
		p.all = append(p.all, s.placedAndValidated(e))
	}
	return p
}

// placedAndValidated is validated, then the structure rules (structure.go).
func (s *server) placedAndValidated(e *entry) *entry {
	e = s.validated(e)
	s.placed(e)
	return e
}

// ⛔ A person or group missing a MUST of a declared class is published
// WITHOUT that class, and its attributes are then dropped like any other
// attribute no class of the entry allows; both are reported. That is the
// rule this file already follows: the person stays published, problems are
// said at startup and by `check`, and nothing is changed silently. The other
// two choices break it -- withholding the person takes them out of every
// search for one missing optional-looking attribute (supannPerson has no
// MUST, but a site class may), and publishing the class without its MUST is
// an entry that fails the schema this server serves. Which MUSTs are missing
// is schema.Validate's answer (unmet), and the entry is built again without
// the class rather than edited, so the rebuilt entry is the one Validate is
// asked about.

// validated is e with what Validate says about it, after dropping the given
// attributes no class of the entry allows.
//
// ⛔ Only what a SOURCE gave is dropped. An attribute this server derives --
// uid, cn, objectClass, sshPublicKey, sambaSID, sambaNTPassword -- that
// Validate refuses is a mistake here, and the entry is withheld rather than
// quietly published without it. And dropping never makes an entry pass that
// fails for another reason: Validate is asked again, and a second failure
// withholds the entry as before.
//
// Which attributes are not allowed is Validate's answer, not a second
// reading of MUST and MAY here: two readings of the schema can disagree, and
// the one that decides is Validate's.
func (s *server) validated(e *entry) *entry {
	err := e.Validate(s.schema)
	var v *schema.ValidationError
	if errors.As(err, &v) {
		drop := map[string]string{}
		for _, p := range v.Problems {
			switch {
			case (p.Kind == schema.NotAllowed || p.Kind == schema.UnknownAttribute) && e.given[p.Attribute]:
				drop[p.Attribute] = s.whyNotAllowed(p.Attribute)
			case p.Kind == schema.Precluded:
				// The site's DIT content rule says this entry may not carry
				// it (RFC 4512 §4.1.6, NOT): dropped whoever gave it, a
				// source or authnd. Build has made sure NOT names no type a
				// class of the rule requires, so dropping it cannot break a
				// MUST; Validate is asked again all the same.
				drop[p.Attribute] = "the DIT content rule " + p.Class + " precludes it (NOT)"
			}
		}
		if len(drop) > 0 {
			kept := e.Attributes[:0:0]
			for _, a := range e.Attributes {
				if why, ok := drop[a.Name]; ok {
					e.dropped = append(e.dropped, dropped{name: a.Name, why: why})
					continue
				}
				kept = append(kept, a)
			}
			e.Attributes = kept
			err = e.Validate(s.schema)
		}
	}
	e.invalid = err
	return e
}

// whyNotAllowed says why an attribute was dropped, and which classes would
// have carried it.
func (s *server) whyNotAllowed(desc string) string {
	t, _, ok := s.schema.Describe(desc)
	if !ok {
		return "the schema served here does not define it, or not with that option"
	}
	var would []string
	for _, oc := range s.schema.ObjectClasses() {
		for _, a := range append(oc.MustTypes(), oc.MayTypes()...) {
			if t.IsA(a) {
				would = append(would, oc.Name())
				break
			}
		}
	}
	switch {
	case len(would) == 0:
		return "no class of the entry allows it, and no class of the schema does"
	case len(would) > 4:
		would = append(would[:4], "others")
	}
	return "no class of the entry allows it; " + list(would) + " would"
}

// posixMust is what posixAccount requires beyond cn and uid, which every
// person here has: RFC 2307 §4, MUST ( cn $ uid $ uidNumber $ gidNumber $
// homeDirectory ).
var posixMust = []string{"uidNumber", "gidNumber", "homeDirectory"}

// personEntry is the entry for one person, with the classes their source
// declares that are not in skip.
func (s *server) personEntry(id *directory.Identity, skip map[string]bool) *entry {
	attrs := id.Attributes()
	e := &entry{name: id.Name()}

	var classes []string
	if s.has(attrs, "sn") {
		// inetOrgPerson (RFC 2798) is a person (RFC 4519 §3.12, MUST sn
		// and cn) by way of organizationalPerson, and RFC 4512 §3.3 wants
		// every one of them listed.
		classes = []string{"person", "organizationalPerson", "inetOrgPerson"}
	} else {
		// account (RFC 4524 §3.1, MUST uid): the structural class RFC 2307
		// §5.3 itself recommends for a posixAccount.
		classes = []string{"account"}
	}
	for _, m := range posixMust {
		if !s.has(attrs, m) {
			e.missingPosix = append(e.missingPosix, m)
		}
	}
	// skip also holds the derived auxiliary classes a DIT content rule does
	// not allow (unmet): left off, with what authnd derives for them.
	off := func(class string) bool { return skip[strings.ToLower(class)] }
	if len(e.missingPosix) == 0 && !off("posixAccount") {
		classes = append(classes, "posixAccount")
	}
	keys := id.Keys()
	if off("ldapPublicKey") {
		keys = nil
	}
	if len(keys) > 0 {
		// openssh-lpk upstream (as go-authn/ldap embeds it): AUXILIARY,
		// MAY ( sshPublicKey $ uid ), and the only class that allows
		// sshPublicKey at all.
		classes = append(classes, "ldapPublicKey")
	}
	var ntValue, sid string
	if s.cfg.PublishNTHash && !off("sambaSamAccount") {
		if key, err := id.NTKey(); err == nil {
			// ⛔ Published only when asked for, because it IS the
			// credential: whoever holds MD4(UTF16LE(password))
			// authenticates as that person over NTLMv2 without ever
			// learning the password. The configuration refuses to turn
			// this on where it would cross a network in the clear.
			if sid, e.noSID = s.sambaSID(id); sid != "" {
				ntValue = strings.ToUpper(hex.EncodeToString(key))
				classes = append(classes, "sambaSamAccount")
			}
		}
	}
	// uidObject (RFC 4519 §3.14, AUXILIARY, MUST uid) on every person, so
	// one class finds all of them whatever their structural class.
	if !off("uidObject") {
		classes = append(classes, "uidObject")
	}
	// The auxiliary classes the person's source declares, last: checked at
	// startup (declared.go), each with its superclasses.
	classes, e.declared = s.withDeclared(classes, id.ObjectClasses(), skip)
	e.leftOff = s.undeclared(id.ObjectClasses())
	e.shape = classes

	list := []*ldap.Attribute{
		ldap.StringAttribute("objectClass", append([]string{"top"}, classes...)...),
		ldap.StringAttribute("uid", id.Name()),
	}
	// cn is the person's name wherever a class allows it: person and
	// posixAccount require it, sambaSamAccount allows it. account alone does
	// not (RFC 4524 §3.1: MAY description, seeAlso, l, o, ou, host), so a
	// bare account carries uid and no cn.
	if s.allows(classes, "cn") {
		list = append(list, ldap.StringAttribute("cn", id.Name()))
	}
	e.given = map[string]bool{}
	for name, values := range attrs.All() {
		e.given[name] = true
		list = append(list, ldap.StringAttribute(name, values...))
	}
	if ntValue != "" {
		if len(attrs.Get("sambaSID")) == 0 {
			list = append(list, ldap.StringAttribute("sambaSID", sid))
		}
		list = append(list, ldap.StringAttribute("sambaNTPassword", ntValue))
	}
	if len(keys) > 0 {
		list = append(list, ldap.StringAttribute("sshPublicKey", keys...))
	}
	e.Entry = &ldap.Entry{DN: s.dnOf(id.Name()), Attributes: list}
	return e
}

// groupEntry is the entry for one group.
//
// A posixGroup needs a gidNumber (RFC 2307 §4: STRUCTURAL, MUST ( cn $
// gidNumber )), and RFC 2307's posixGroup is followed rather than
// draft-howard-rfc2307bis-02's, which makes it AUXILIARY: the draft expired
// unpublished, the schema served here is RFC 2307's, and an AUXILIARY
// posixGroup would need a structural class beside it -- groupOfNames, whose
// MUST member an empty group cannot give.
//
// A group without a gidNumber cannot be a posixGroup, and memberUid belongs
// to posixGroup alone, so:
//
//   - with somebody in it, it is a groupOfNames (RFC 4519 §3.5, MUST
//     member and cn), its members as the DNs this server publishes them
//     under;
//   - with nobody in it, it is an organizationalRole (RFC 4519 §3.10,
//     STRUCTURAL, MUST cn). groupOfNames would need a member, and the ways
//     of inventing one are false: member: "" names the root DSE as a member,
//     and the group's own DN makes it a member of itself. groupOfUniqueNames
//     has the same MUST. organizationalRole is the one standard structural
//     class whose only MUST is cn and whose occupants (roleOccupant, DNs)
//     are optional -- a set that may be empty, which is what this group is.
//     It takes description, ou and seeAlso, as groupOfNames does.
func (s *server) groupEntry(name string, skip map[string]bool) (*entry, error) {
	members, err := s.dir.Members(name)
	if err != nil {
		return nil, err
	}
	attrs, err := s.dir.GroupAttributes(name)
	if err != nil && !errors.Is(err, directory.ErrNoSuchGroup) {
		return nil, err
	}
	declared, err := s.dir.GroupObjectClasses(name)
	if err != nil && !errors.Is(err, directory.ErrNoSuchGroup) {
		return nil, err
	}
	e := &entry{name: name, group: true}
	var class string
	switch {
	case s.has(attrs, "gidNumber"):
		class = "posixGroup"
	case len(members) > 0:
		class = "groupOfNames"
	default:
		class = "organizationalRole"
	}
	classes, added := s.withDeclared([]string{class}, declared.Names(), skip)
	e.shape, e.declared = classes, added
	e.leftOff = s.undeclared(declared.Names())
	list := []*ldap.Attribute{
		ldap.StringAttribute("objectClass", append([]string{"top"}, classes...)...),
		ldap.StringAttribute("cn", name),
	}
	e.given = map[string]bool{}
	for n, values := range attrs.All() {
		e.given[n] = true
		list = append(list, ldap.StringAttribute(n, values...))
	}
	// ⛔ An empty group is published WITHOUT memberUid or member, not with an
	// empty one: an attribute of an entry has at least one value (RFC 4511
	// 4.1.7).
	if len(members) > 0 {
		switch class {
		case "posixGroup":
			list = append(list, ldap.StringAttribute("memberUid", members...))
		case "groupOfNames":
			dns := make([]string, len(members))
			for i, m := range members {
				dns[i] = s.dnOf(m)
			}
			list = append(list, ldap.StringAttribute("member", dns...))
		}
	}
	e.Entry = &ldap.Entry{DN: "cn=" + name + "," + s.groupsDN, Attributes: list}
	return e, nil
}

// has reports whether attrs hold the attribute type name, under any of its
// names (sn is also surname) and with any options: what a MUST asks for.
func (s *server) has(attrs directory.Attributes, name string) bool {
	want := s.schema.AttributeType(name)
	for desc := range attrs.All() {
		if t, _, ok := s.schema.Describe(desc); ok && t == want {
			return true
		}
	}
	return false
}

// allows reports whether one of these classes, or a superclass, has the
// attribute type in its MUST or MAY.
func (s *server) allows(classes []string, name string) bool {
	want := s.schema.AttributeType(name)
	for _, c := range classes {
		oc := s.schema.ObjectClass(c)
		if oc == nil {
			continue
		}
		if slices.Contains(oc.MustTypes(), want) || slices.Contains(oc.MayTypes(), want) {
			return true
		}
	}
	return false
}

// problems is what Validate said, one line per problem.
func problems(err error) []string {
	var v *schema.ValidationError
	if errors.As(err, &v) {
		out := make([]string, len(v.Problems))
		for i, p := range v.Problems {
			out[i] = p.String()
		}
		return out
	}
	return []string{err.Error()}
}

// shapeOf is how `check` says what an entry is published as.
func shapeOf(e *entry) string {
	if e.invalid != nil {
		return "NOT PUBLISHED (see below)"
	}
	return strings.Join(e.shape, ", ")
}

// describeMissing is "no uidNumber, gidNumber or homeDirectory".
func describeMissing(names []string) string {
	switch len(names) {
	case 1:
		return "no " + names[0]
	case 2:
		return fmt.Sprintf("no %s or %s", names[0], names[1])
	}
	return fmt.Sprintf("no %s or %s", strings.Join(names[:len(names)-1], ", "), names[len(names)-1])
}
