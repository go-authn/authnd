// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	ldap "github.com/go-authn/ldap"
	"github.com/go-authn/ldap/schema"
)

// DIT structure rules and name forms (RFC 4512 §4.1.7, X.501 13.7): where an
// entry may be in the tree, and what its RDN is made of.
//
// With no active DIT structure rule in the schema served -- the standard
// schema has none -- nothing here does anything, and the tree is what it has
// always been.
//
// With some, the tree authnd publishes is checked from its root down at
// startup, and by `check`, with go-authn/ldap's GoverningStructureRule:
//
//	base_dn                 the suffix, a subschema administrative point
//	ou=people,<base_dn>     where every person is, named uid=<name>
//	ou=groups,<base_dn>     where every group is, named cn=<name>
//
// ⛔ THE TREE IS CONFIGURATION, SO A RULE IT BREAKS REFUSES STARTUP, naming
// the DN, the rule or name form, and the clause. Three things are
// configuration rather than data:
//
//   - the suffix and the two containers. authnd does not publish them as
//     entries, but every entry it publishes is under them, and X.501 13.7.5
//     places an entry by its superior's governing rule. They are given the
//     class their RDN names -- dc a domain, o an organization, ou an
//     organizationalUnit, c a country, l a locality (containerClasses) --
//     and a suffix named by anything else is refused: there is no class to
//     hold to the rules;
//   - the RDN attribute of people (uid) and of groups (cn), which authnd
//     chooses. For each structural class authnd can give a person or a group
//     (personShapes, groupShapes), a probe entry named that way is placed
//     under its container: a name form that refuses the RDN attribute is a
//     refusal of the configuration, whoever the person is;
//   - a container under which no class authnd can give its entries has a
//     rule: nothing could ever be published there.
//
// What is DATA is checked per entry, when it is published: a person whose
// structural class -- account or inetOrgPerson, which depends on whether
// they have an sn -- has no rule under ou=people is left out, and the startup
// log and `check` say why, as for an entry that fails the schema. An RDN made
// different by the data cannot get past the schema to the rules: the RDN is
// uid=<name>, and a name holding a "+" (uid=a+mail=b) has an RDN whose first
// value, "a", is not the entry's uid, "a+mail=b", which Validate refuses
// (RDNNotPresent) before any rule is asked.

// containerClasses are the structural classes authnd gives a container by
// the attribute of its RDN (RFC 4519 §3: domain RFC 4524 §3.4).
var containerClasses = []struct{ attr, class string }{
	{"dc", "domain"},
	{"o", "organization"},
	{"ou", "organizationalUnit"},
	{"c", "country"},
	{"l", "locality"},
}

// personShapes and groupShapes are the structural chains authnd gives a
// person or a group (entries.go), superclasses first.
var (
	personShapes = [][]string{{"account"}, {"person", "organizationalPerson", "inetOrgPerson"}}
	groupShapes  = [][]string{{"posixGroup"}, {"groupOfNames"}, {"organizationalRole"}}
)

// tree is the rules that govern the two containers, when the schema has
// active DIT structure rules.
type tree struct {
	people, groups *schema.DITStructureRule
}

// activeStructureRules reports whether the schema has a DIT structure rule
// that is not OBSOLETE.
func activeStructureRules(s *schema.Schema) bool {
	return slices.ContainsFunc(s.DITStructureRules(), func(r *schema.DITStructureRule) bool { return !r.Obsolete })
}

// checkStructure walks the tree from the suffix down and keeps the rules of
// the two containers for publish. Every refusal is returned at once.
func (s *server) checkStructure() error {
	if !activeStructureRules(s.schema) {
		return nil
	}
	base := s.cfg.BaseDN
	class, err := s.containerClass(base)
	if err != nil {
		return err
	}
	root, err := s.schema.GoverningStructureRule(container(base, class), nil)
	if err != nil {
		return fmt.Errorf("DIT structure rules: %s, the suffix (base_dn), as %s %s: %s",
			base, article(class), class, whyNot(err))
	}
	t := &tree{}
	var errs []error
	for _, c := range []struct {
		dn, what, rdn string
		shapes        [][]string
		rule          **schema.DITStructureRule
	}{
		{s.peopleDN, "people", "uid", personShapes, &t.people},
		{s.groupsDN, "groups", "cn", groupShapes, &t.groups},
	} {
		r, err := s.schema.GoverningStructureRule(container(c.dn, "organizationalUnit"), root)
		if err != nil {
			errs = append(errs, fmt.Errorf("DIT structure rules: %s, where authnd publishes its %s, as an organizationalUnit: %s",
				c.dn, c.what, whyNot(err)))
			continue
		}
		*c.rule = r
		placed := 0
		var unplaced []string
		for _, shape := range c.shapes {
			class := shape[len(shape)-1]
			probe := schema.Entry{DN: c.rdn + "=probe," + c.dn, Attributes: []schema.Attribute{objectClasses(shape)}}
			_, err := s.schema.GoverningStructureRule(probe, r)
			var v *schema.ValidationError
			switch {
			case err == nil:
				placed++
			case errors.As(err, &v) && v.Has(schema.NameFormViolation):
				errs = append(errs, fmt.Errorf("DIT structure rules: authnd names its %s %s=<name>,%s, and %s %s named so is refused: %s",
					c.what, c.rdn, c.dn, article(class), class, whyNot(err)))
				placed++ // refused already: not also "nothing could be published"
			default:
				unplaced = append(unplaced, class+" ("+whyNot(err)+")")
			}
		}
		if placed == 0 {
			errs = append(errs, fmt.Errorf("DIT structure rules: no entry authnd publishes under %s could be placed there: %s",
				c.dn, strings.Join(unplaced, "; ")))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	s.tree = t
	return nil
}

// containerClass is the structural class authnd gives the container dn, by
// the attribute of its RDN.
func (s *server) containerClass(dn string) (string, error) {
	avas := schema.DNValues(dn)
	if len(avas) == 0 {
		return "", fmt.Errorf("DIT structure rules: base_dn %q is not a DN", dn)
	}
	t := s.schema.AttributeType(avas[0].Type)
	for _, c := range containerClasses {
		if t != nil && t == s.schema.AttributeType(c.attr) {
			return c.class, nil
		}
	}
	names := make([]string, len(containerClasses))
	for i, c := range containerClasses {
		names[i] = c.attr
	}
	return "", fmt.Errorf("DIT structure rules: the suffix %s is named by %s, and authnd gives a class to a suffix named by %s only: "+
		"without one, the schema's structure rules cannot place it", dn, avas[0].Type, list(names))
}

// container is the entry a container is held to the rules as.
func container(dn, class string) schema.Entry {
	return schema.Entry{DN: dn, Attributes: []schema.Attribute{objectClasses([]string{class})}}
}

func objectClasses(chain []string) schema.Attribute {
	a := schema.Attribute{Description: "objectClass", Values: [][]byte{[]byte("top")}}
	for _, c := range chain {
		a.Values = append(a.Values, []byte(c))
	}
	return a
}

// whyNot is what GoverningStructureRule said, its problems joined.
func whyNot(err error) string { return strings.Join(problems(err), "; ") }

func article(class string) string {
	if strings.ContainsAny(class[:1], "aeiouAEIOU") {
		return "an"
	}
	return "a"
}

// placed holds a published entry to the structure rules: one that no rule
// places under its container is not published, and why is said as for an
// entry that fails the schema.
func (s *server) placed(e *entry) {
	if e.invalid != nil || s.tree == nil {
		return
	}
	sup := s.tree.people
	if e.group {
		sup = s.tree.groups
	}
	if _, err := s.schema.GoverningStructureRule(schemaEntry(e.Entry), sup); err != nil {
		e.invalid = err
	}
}

// schemaEntry is an entry as package schema reads it.
func schemaEntry(e *ldap.Entry) schema.Entry {
	out := schema.Entry{DN: e.DN, Attributes: make([]schema.Attribute, len(e.Attributes))}
	for i, a := range e.Attributes {
		out.Attributes[i] = schema.Attribute{Description: a.Name, Values: a.Values}
	}
	return out
}
