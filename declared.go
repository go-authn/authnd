// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-authn/directory"
	"github.com/go-authn/ldap/schema"
	"github.com/hashicorp/hcl/v2"
)

// Declared object classes: the auxiliary classes a source's configuration
// says its people, or its groups, carry.
//
//	users "sql" {
//	  ...
//	  object_classes       = ["supannPerson", "eduPerson"]
//	  group_object_classes = ["supannGroupe"]
//	}
//	user "alice"  { object_classes = ["eduPerson"] ... }
//	group "staff" { object_classes = ["supannGroupe"] ... }
//
// ⛔ DECLARED ONLY. A class is never inferred from the attributes a person
// has, and never read from the data (go-authn/directory carries no column and
// no upstream objectClass value that sets one): a class is a promise about
// the shape of every entry, and the promise belongs to whoever writes the
// configuration.
//
// go-authn/directory checks the spelling. The rest is checked here, at
// startup and by `check`, against the schema this server serves, and a class
// that fails refuses startup naming the block, its position and the class --
// a configuration error, said where the operator is watching (the samba
// block's refusal is the precedent). A declared class must be:
//
//   - defined by the schema served here;
//   - AUXILIARY (RFC 4512 §4.1.1 kinds; §2.4.2: an entry has exactly one
//     structural chain, which authnd chooses, and §2.4.1: an abstract class
//     is only ever a superclass);
//   - not one authnd derives itself (derivedClasses): those say what authnd
//     has decided about a person from what they have -- posixAccount when
//     the three posix attributes are there, sambaSamAccount when an NT hash
//     and a SID are -- and a declaration cannot overrule that decision.

// derivedClasses are the classes authnd decides on itself (entries.go): the
// structural classes, inetOrgPerson's superclasses, and the auxiliary ones
// it adds from what a person has. Compared by name and, where the schema
// defines them, by the class a name resolves to, so that another NAME of one
// of them is refused too.
var derivedClasses = []string{
	"top", "account", "person", "organizationalPerson", "inetOrgPerson",
	"posixAccount", "ldapPublicKey", "sambaSamAccount", "uidObject",
	"posixGroup", "groupOfNames", "organizationalRole",
}

// A declaration is one list of declared classes, where it was written.
type declaration struct {
	// block is how the block is named in a sentence: users "sql", user
	// "alice", group "staff".
	block string
	// field is object_classes or group_object_classes.
	field string
	// of says what carries them: "its people", "its groups", "this person".
	of    string
	rng   hcl.Range
	names []string
}

// at is "c.hcl:12:3: ", or nothing for a block with no recorded position.
func (d declaration) at() string {
	if d.rng.Filename == "" {
		return ""
	}
	return position(d.rng) + ": "
}

// declarations is every list of declared classes in the configuration, in
// the order sources are asked: the user and group blocks, then the users
// blocks.
func (c *config) declarations() []declaration {
	var out []declaration
	for _, u := range c.Users {
		if len(u.ObjectClasses) > 0 {
			out = append(out, declaration{fmt.Sprintf("user %q", u.Name), "object_classes", "this person", u.ObjectClassesRange, u.ObjectClasses})
		}
	}
	for _, g := range c.Groups {
		if len(g.ObjectClasses) > 0 {
			out = append(out, declaration{fmt.Sprintf("group %q", g.Name), "object_classes", "this group", g.ObjectClassesRange, g.ObjectClasses})
		}
	}
	for _, b := range c.Directories {
		block := fmt.Sprintf("users %q", b.Kind)
		if len(b.ObjectClasses) > 0 {
			out = append(out, declaration{block, "object_classes", "its people", b.ObjectClassesRange, b.ObjectClasses})
		}
		if len(b.GroupObjectClasses) > 0 {
			out = append(out, declaration{block, "group_object_classes", "its groups", b.GroupObjectClassesRange, b.GroupObjectClasses})
		}
	}
	return out
}

// checkDeclared holds every declared class to the schema served, and keeps
// the ones that pass for publish. Every refusal is returned at once, so that
// one restart shows all of them.
func (s *server) checkDeclared() error {
	s.declared = map[string]*schema.ObjectClass{}
	var errs []error
	for _, d := range s.cfg.declarations() {
		for _, n := range d.names {
			oc, err := s.declarable(n)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s%s %s: %w", d.at(), d.block, d.field, err))
				continue
			}
			s.declared[strings.ToLower(n)] = oc
		}
	}
	return errors.Join(errs...)
}

// declarable is the class a name declares, or why it cannot be declared.
func (s *server) declarable(name string) (*schema.ObjectClass, error) {
	oc := s.schema.ObjectClass(name)
	for _, d := range derivedClasses {
		if strings.EqualFold(d, name) || (oc != nil && oc == s.schema.ObjectClass(d)) {
			return nil, fmt.Errorf("%s is a class authnd derives itself, from what each person or group has "+
				"(see `authnd check`), and a declaration cannot overrule that", name)
		}
	}
	if oc == nil {
		return nil, fmt.Errorf("the schema served here does not define %s: load the file that does with "+
			"schema_files, or define it in a schema block", name)
	}
	switch oc.Kind {
	case schema.Auxiliary:
		return oc, nil
	case schema.Structural:
		return nil, fmt.Errorf("%s is STRUCTURAL, and an entry has exactly one structural chain (RFC 4512 §2.4.2), "+
			"which authnd chooses: only an AUXILIARY class (§4.1.1) can be declared", name)
	}
	return nil, fmt.Errorf("%s is ABSTRACT, which is only ever a superclass (RFC 4512 §2.4.1): "+
		"only an AUXILIARY class (§4.1.1) can be declared", name)
}

// withDeclared is classes with each declared class not in skip added after
// its superclasses, as RFC 4512 §3.3 requires ("all superclasses of the
// named classes SHALL be implicitly added as well if not already present"),
// and the declared classes that were added. A class already there -- by any
// of its names -- is not added twice.
func (s *server) withDeclared(classes, declared []string, skip map[string]bool) (out, added []string) {
	out = slices.Clone(classes)
	present := func(c *schema.ObjectClass) bool {
		if strings.EqualFold(c.Name(), "top") {
			return true // listed first, by every entry, outside classes
		}
		return slices.ContainsFunc(out, func(have string) bool { return s.schema.ObjectClass(have) == c })
	}
	var walk func(c *schema.ObjectClass)
	walk = func(c *schema.ObjectClass) {
		for _, sup := range c.Superiors() {
			walk(sup)
		}
		if !present(c) {
			out = append(out, c.Name())
		}
	}
	for _, n := range declared {
		oc := s.declared[strings.ToLower(n)]
		if oc == nil || skipped(oc, skip) || slices.Contains(added, oc.Name()) {
			continue
		}
		walk(oc)
		added = append(added, oc.Name())
	}
	return out, added
}

// A leftOff is a class an entry is published without, and why: a declared
// class whose MUST is missing, or an auxiliary class -- declared or derived
// -- that the DIT content rule of the entry's structural class does not
// allow.
type leftOff struct {
	class   string
	missing []string
	// rule is the DIT content rule whose AUX does not list the class -- or,
	// with super, does not list super, a superclass the class needs listed
	// beside it (RFC 4512 §3.3).
	rule, super string
}

// unmet is the classes e must be published without: the declared classes
// whose MUST attributes e does not have, and the auxiliary classes the DIT
// content rule of its structural class does not list in AUX -- read off
// schema.Validate's MissingRequired and AuxiliaryNotAllowed problems, so
// that the reading of the schema that decides is Validate's, as in
// validated.
//
// ⛔ A class the content rule does not allow is LEFT OFF, as a declared
// class missing a MUST is, and for the same reason: the person stays
// published, with what the rule allows, and both are said. The attributes
// only that class allowed are then dropped by validated like any other
// attribute no class of the entry allows, and the ones authnd derives for
// it (sshPublicKey for ldapPublicKey, sambaSID and sambaNTPassword for
// sambaSamAccount) are not added (personEntry). Withholding the whole person
// for a class the site's rule does not want is the other choice, and it
// takes them out of every search for something they did not choose.
func (s *server) unmet(e *entry) (off []leftOff, skip map[string]bool) {
	var v *schema.ValidationError
	if !errors.As(s.validate(e), &v) {
		return nil, nil
	}
	skip = map[string]bool{}
	for _, p := range v.Problems {
		if p.Kind != schema.AuxiliaryNotAllowed {
			continue
		}
		oc := s.schema.ObjectClass(p.Class)
		if oc == nil || skip[strings.ToLower(oc.Name())] {
			continue
		}
		rule := ""
		if st := structuralOf(s.schema, e.shape); st != nil {
			if r := s.schema.DITContentRuleOf(st); r != nil {
				rule = r.Name()
			}
		}
		off = append(off, leftOff{class: oc.Name(), rule: rule})
		skip[strings.ToLower(oc.Name())] = true
	}
	// A declared class whose superclass is left off goes with it, and is
	// said: withDeclared would leave it off silently otherwise.
	rules := map[string]string{} // left-off class -> its rule
	for _, l := range off {
		rules[strings.ToLower(l.class)] = l.rule
	}
	for _, name := range e.declared {
		oc := s.schema.ObjectClass(name)
		if skip[strings.ToLower(oc.Name())] {
			continue
		}
		if sup := skippedBy(oc, skip); sup != nil {
			off = append(off, leftOff{class: oc.Name(), rule: rules[strings.ToLower(sup.Name())], super: sup.Name()})
			skip[strings.ToLower(oc.Name())] = true
		}
	}
	for _, name := range e.declared {
		oc := s.schema.ObjectClass(name)
		var missing []string
		for _, p := range v.Problems {
			if p.Kind == schema.MissingRequired && slices.Contains(oc.MustTypes(), s.schema.AttributeType(p.Attribute)) {
				missing = append(missing, p.Attribute)
			}
		}
		if len(missing) > 0 && !skip[strings.ToLower(oc.Name())] {
			off = append(off, leftOff{class: oc.Name(), missing: missing})
			skip[strings.ToLower(oc.Name())] = true
		}
	}
	return off, skip
}

// structuralOf is the most subordinate structural class of an entry's
// chain, which is the one its DIT content rule is for (RFC 4512 §4.1.6).
func structuralOf(s *schema.Schema, shape []string) *schema.ObjectClass {
	var leaf *schema.ObjectClass
	for _, n := range shape {
		if oc := s.ObjectClass(n); oc != nil && oc.Kind == schema.Structural && (leaf == nil || oc.IsA(leaf)) {
			leaf = oc
		}
	}
	return leaf
}

// skipped reports whether a class, or one of its superclasses, is in skip:
// a class whose superclass is left off goes too (RFC 4512 §3.3).
func skipped(oc *schema.ObjectClass, skip map[string]bool) bool {
	return skip[strings.ToLower(oc.Name())] || skippedBy(oc, skip) != nil
}

// skippedBy is the first superclass of oc, at any depth, that is in skip,
// or nil. Class chains are short and acyclic (Build refuses a cycle).
func skippedBy(oc *schema.ObjectClass, skip map[string]bool) *schema.ObjectClass {
	for _, sup := range oc.Superiors() {
		if skip[strings.ToLower(sup.Name())] {
			return sup
		}
		if s := skippedBy(sup, skip); s != nil {
			return s
		}
	}
	return nil
}

// undeclared is the classes a source handed out that were not checked at
// startup. It cannot happen -- every class comes from a declaration
// checkDeclared read -- and if it ever does, the class is left off and said,
// rather than published unchecked.
func (s *server) undeclared(names []string) []leftOff {
	var out []leftOff
	for _, n := range names {
		if s.declared[strings.ToLower(n)] == nil {
			out = append(out, leftOff{class: n})
		}
	}
	return out
}

// leftOffLines are the sentences that say which declared classes an entry is
// published without, and why, about what: a name in `check`, a DN at startup.
func leftOffLines(e *entry, what string) []string {
	var out []string
	for _, l := range e.leftOff {
		if l.super != "" {
			out = append(out, fmt.Sprintf("%s is published without %s: its superclass %s is not allowed by the DIT content rule %s (not in its AUX)",
				what, l.class, l.super, l.rule))
			continue
		}
		if l.rule != "" {
			out = append(out, fmt.Sprintf("%s is published without %s: the DIT content rule %s does not allow it (not in its AUX)", what, l.class, l.rule))
			continue
		}
		if len(l.missing) == 0 {
			out = append(out, fmt.Sprintf("%s is published without %s: the class was not checked at startup", what, l.class))
			continue
		}
		out = append(out, fmt.Sprintf("%s is published without %s, which its source declares: %s has %s, which %s requires",
			what, l.class, what, describeMissing(l.missing), l.class))
	}
	return out
}

// schemaLines say what the site added to the schema, what each source
// declares, and where two sources declare different classes for one group:
// the same lines at startup and in `check`.
func (s *server) schemaLines() []string {
	var out []string
	for _, a := range s.added {
		line := fmt.Sprintf("schema: %s adds %s", a.where, describeAddition(a.defs))
		if strings.HasPrefix(a.where, "the schema block") {
			if names := namesOf(a.defs); len(names) > 0 {
				line += ": " + list(names)
			}
		}
		out = append(out, line)
	}
	for _, d := range s.cfg.declarations() {
		out = append(out, fmt.Sprintf("%s%s declares %s for %s", d.at(), d.block, list(d.names), d.of))
	}
	return append(out, s.groupClassConflicts()...)
}

// groupClassConflicts are the groups two sources declare different classes
// for.
//
// go-authn/directory's rule (Set.GroupObjectClasses): the first source that
// has the group and declares classes for it decides, and a later source's
// list is ignored -- silently, because adding a block must not stop a server
// that declares the group locally. Silent is right for a server and wrong for
// `check`, whose job is to say what a configuration does: a later list that
// says something else is a list somebody wrote and nothing reads.
func (s *server) groupClassConflicts() []string {
	var out []string
	for _, g := range s.groupNames() {
		type said struct {
			who     string
			classes []string
		}
		var all []said
		for _, src := range s.dir.Sources() {
			gc, ok := src.(directory.GroupObjectClasser)
			if !ok {
				continue
			}
			c, err := gc.GroupObjectClasses(g)
			if err != nil || c.Len() == 0 {
				continue
			}
			all = append(all, said{src.Describe(), c.Names()})
		}
		for _, later := range all[min(1, len(all)):] {
			if sameClasses(all[0].classes, later.classes) {
				continue
			}
			out = append(out, fmt.Sprintf("group %s: %s declares %s and %s declares %s; the first is published "+
				"and the second is ignored (the first source that declares classes for a group decides)",
				g, all[0].who, list(all[0].classes), later.who, list(later.classes)))
		}
	}
	return out
}

// sameClasses is two lists naming the same classes, in any order and case.
func sameClasses(a, b []string) bool {
	norm := func(l []string) []string {
		out := make([]string, len(l))
		for i, n := range l {
			out[i] = strings.ToLower(n)
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(norm(a), norm(b))
}
