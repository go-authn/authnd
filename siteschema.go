// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-authn/ldap/schema"
	"github.com/go-authn/ldap/schema/hclschema"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Site schemas: what a site adds to the schema this server serves and holds
// every entry to.
//
//	schema_files = ["/etc/authnd/supann.schema", "/etc/authnd/eduperson.ldif"]
//
//	schema {
//	  attribute_type "siteBadge" {
//	    oid    = "1.3.6.1.4.1.99999.1.1"
//	    syntax = "1.3.6.1.4.1.1466.115.121.1.15"
//	  }
//	  object_class "sitePerson" {
//	    oid  = "1.3.6.1.4.1.99999.2.1"
//	    kind = "auxiliary"
//	    may  = ["siteBadge"]
//	  }
//	}
//
// The schema is built in this order, and a definition may refer to anything
// before it: the standard schema (go-authn/ldap's schema.StandardFiles),
// samba.schema when the samba block is there, each of schema_files, then the
// schema blocks. A relative path in schema_files is relative to the working
// directory, as every other path in this configuration is (password_file,
// cert_file, keytab, dsn_file): one rule for every path, rather than a second
// rule for one key.
//
// ⛔ THE FILES ARE READ AS PUBLISHED, by go-authn/ldap's slapd-compatible
// readers (schema.Read: any term order, slapd and RFC 2849 continuations,
// base64, {N} prefixes, objectidentifier macros defined before use, across
// files). Nothing is converted beforehand, so the file a site's slapd loads
// is the file this server loads.
//
// ⛔ A FILE THAT DOES NOT BUILD REFUSES STARTUP, AND `check`, WITH THE FILE AND
// THE LINE. That includes a definition a file REDEFINES -- the same OID or
// the same name as one already there -- whether its text is the same or not.
// This is slapd's own rule. A schema file's attributetype goes through
// parse_at (servers/slapd/schemaparse.c), which calls at_add(at, 1, ...) and
// refuses on any non-zero code; at_insert (servers/slapd/at.c) answers an OID
// or a name already indexed with at_check_dup, which returns
// SLAP_SCHERR_ATTR_DUP ("Duplicate attributeType") when the OID and names are
// the same and SLAP_SCHERR_ATTR_INCONSISTENT ("Inconsistent duplicate
// attributeType") when they are not. The only caller that tolerates the
// former is register_at(def, ad, dupok) -- slapd's hard-coded schema, never a
// file. Object classes are the same (parse_oc, oc_add, oc_check_dup,
// register_oc in oc.c). A redefinition accepted here would also have to pick
// a winner, which is a silent change to what every client is told the
// standard attribute is; refusing names the line instead.
//
// The schema blocks are decoded by go-authn/ldap's hclschema, the same
// decoder that reads an .hcl schema file, so the rule that every value is a
// literal (no variables, functions or ${...}) holds here exactly as it does
// there. hclschema decodes from bytes only. Each block is handed to it as its
// own text AT ITS OWN PLACE in its file -- the bytes before the block are
// blanked, keeping the line breaks -- so every position it reports is the
// configuration file's own, and its bounds (4 MiB, 64 levels of nesting) are
// measured on that text. See schemaBlockFiles for why this and not a new
// Body-level API in go-authn/ldap.

// A schemaBlock is one `schema { ... }`: its body is kept as it was parsed and
// decoded by hclschema, not by gohcl.
type schemaBlock struct {
	Body     hcl.Body  `hcl:",body"`
	DefRange hcl.Range `hcl:",def_range"`
}

// An addition is what one schema file or one schema block added on top of
// what was there before it.
type addition struct {
	// where is the file as named in schema_files, or "the schema block at
	// c.hcl:12".
	where string
	defs  *schema.Definitions
}

// builtSchema is the schema this server serves, and what the site added to
// the standard one.
type builtSchema struct {
	schema *schema.Schema
	added  []addition
}

// directorySchema is the schema this server publishes and holds every entry
// to: the standard one, Samba's three definitions when the samba block is
// there, and what schema_files and the schema blocks add.
func directorySchema(cfg *config) (*builtSchema, error) {
	baseFiles := schema.StandardFiles()
	if cfg.Samba != nil {
		baseFiles = append(baseFiles, schema.File{Name: "samba.schema", Data: sambaSchema})
	}
	base, err := schema.Read(baseFiles...)
	if err != nil {
		return nil, err
	}
	sch, err := schema.BuildFrom(base)
	if err != nil {
		return nil, err
	}
	b := &builtSchema{schema: sch}
	if len(cfg.SchemaFiles) == 0 && len(cfg.Schemas) == 0 {
		return b, nil
	}

	owners := ownersOf(base, "the standard schema")
	if cfg.Samba != nil {
		owners = ownersOf(base, "the standard schema, or samba.schema (the samba block)")
	}
	var read []schema.File
	site := &schema.Definitions{}
	for _, path := range cfg.SchemaFiles {
		data, err := readSchemaFile(path)
		if err != nil {
			return nil, fmt.Errorf("schema_files: %w", err)
		}
		f := schema.File{Name: path, Data: data}
		// Read with the files before it: an objectidentifier macro one file
		// defines may be used by the next, as slapd allows across includes.
		all, err := schema.Read(append(read, f)...)
		if err != nil {
			return nil, fmt.Errorf("schema_files: %w", err)
		}
		mine := since(all, site)
		if _, err := schema.BuildFrom(base, all); err != nil {
			return nil, fmt.Errorf("schema_files: %s", refusal(err, mine, owners, func(c culprit) string {
				if line := locate(read, f, c); line > 0 {
					return fmt.Sprintf("%s:%d", path, line)
				}
				return path
			}))
		}
		owners.add(mine, path)
		read, site = append(read, f), all
		b.added = append(b.added, addition{where: path, defs: mine})
	}

	files, err := cfg.schemaBlockFiles()
	if err != nil {
		return nil, err
	}
	local := &schema.Definitions{}
	for i, f := range files {
		all, err := hclschema.Decode(files[:i+1]...)
		if err != nil {
			return nil, fmt.Errorf("schema block: %w", err)
		}
		mine := since(all, local)
		block := cfg.Schemas[i]
		where := "the schema block at " + position(block.DefRange)
		if _, err := schema.BuildFrom(base, site, all); err != nil {
			return nil, fmt.Errorf("schema block: %s", refusal(err, mine, owners, func(c culprit) string {
				return position(labelled(block.Body, f.Name, c))
			}))
		}
		owners.add(mine, where)
		local = all
		b.added = append(b.added, addition{where: where, defs: mine})
	}
	if b.schema, err = schema.BuildFrom(base, site, local); err != nil {
		return nil, err // every step above built; this is the same set
	}
	return b, nil
}

// readSchemaFile reads one of schema_files: a regular file, and no more than
// schema.MaxFileSize bytes of it.
//
// ⛔ The bound is go-authn/ldap's, and schema.Read applies it -- to bytes
// already in memory. Read through a LimitReader, a file past it is refused
// after MaxFileSize+1 bytes rather than after all of them, and a path that
// is not a regular file (a FIFO would block startup forever, /dev/zero would
// never end) is refused before anything is read.
func readSchemaFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, schema.MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(data) > schema.MaxFileSize {
		return nil, fmt.Errorf("%s is more than the %d bytes a schema file may have", path, schema.MaxFileSize)
	}
	return data, nil
}

// schemaBlockFiles is each schema block as a file hclschema.Decode reads: the
// configuration file's bytes up to the block's closing brace, with every byte
// before its opening brace blanked (a line break stays a line break, anything
// else becomes a space).
//
// hclschema has no API that takes an hcl.Body, and this is the way chosen
// over adding one to go-authn/ldap:
//
//   - The literal-only rule, the duplicate and macro rules, and the bounds
//     hclschema applies are the ones an .hcl schema file gets, by
//     construction: it is the same function on the same text. A Body-level
//     API would be a second entry point, and its bounds (MaxFileSize,
//     MaxNesting) are defined on bytes it would no longer see.
//   - Every position in an error is the operator's file, line and column,
//     because nothing before the block moved.
//   - It ships in this release, rather than after a go-authn/ldap release
//     this one would have to wait for.
//
// The ranges come from the parser that read the configuration, not from a
// scan for braces, so a brace in a string or a heredoc cannot misplace them.
func (c *config) schemaBlockFiles() ([]schema.File, error) {
	var out []schema.File
	for _, sb := range c.Schemas {
		body, ok := sb.Body.(*hclsyntax.Body)
		if !ok {
			return nil, fmt.Errorf("%s: a schema block must be written in HCL's native syntax", position(sb.DefRange))
		}
		r := body.SrcRange
		src, ok := c.sources[r.Filename]
		if !ok || r.Start.Byte < 0 || r.End.Byte > len(src) || r.Start.Byte >= r.End.Byte {
			return nil, fmt.Errorf("%s: the schema block's text is not where the parser said it was", position(sb.DefRange))
		}
		start, end := r.Start.Byte, r.End.Byte
		if src[start] == '{' && src[end-1] == '}' {
			start, end = start+1, end-1
		}
		data := make([]byte, end)
		for i := 0; i < start; i++ {
			if src[i] == '\n' {
				data[i] = '\n'
			} else {
				data[i] = ' '
			}
		}
		copy(data[start:], src[start:end])
		out = append(out, schema.File{Name: r.Filename, Data: data})
	}
	return out, nil
}

// position is a range as file:line:column, what an editor jumps to.
func position(r hcl.Range) string {
	if r.Filename == "" {
		return "?"
	}
	return fmt.Sprintf("%s:%d:%d", r.Filename, r.Start.Line, r.Start.Column)
}

// since is what all holds beyond before: the definitions one more file added.
// schema.Read and hclschema.Decode append in file order, kind by kind.
func since(all, before *schema.Definitions) *schema.Definitions {
	return &schema.Definitions{
		ObjectIdentifiers: all.ObjectIdentifiers[len(before.ObjectIdentifiers):],
		Syntaxes:          all.Syntaxes[len(before.Syntaxes):],
		MatchingRules:     all.MatchingRules[len(before.MatchingRules):],
		AttributeTypes:    all.AttributeTypes[len(before.AttributeTypes):],
		ObjectClasses:     all.ObjectClasses[len(before.ObjectClasses):],
	}
}

// owners says which file defined each OID and name, so that a redefinition
// can name the definition it collides with.
type owners map[string]owned

type owned struct {
	where string
	def   fmt.Stringer
}

func ownersOf(d *schema.Definitions, where string) owners {
	o := owners{}
	o.add(d, where)
	return o
}

func (o owners) add(d *schema.Definitions, where string) {
	put := func(kind, oid string, names []string, def fmt.Stringer) {
		o[kind+" "+oid] = owned{where, def}
		for _, n := range names {
			o[kind+" "+strings.ToLower(n)] = owned{where, def}
		}
	}
	for _, x := range d.Syntaxes {
		put("syntax", x.OID, nil, x)
	}
	for _, x := range d.MatchingRules {
		put("matching rule", x.OID, x.Names, x)
	}
	for _, x := range d.AttributeTypes {
		put("attribute type", x.OID, x.Names, x)
	}
	for _, x := range d.ObjectClasses {
		put("object class", x.OID, x.Names, x)
	}
}

// A culprit is the definition a build refused, in the file that added it.
type culprit struct {
	kind  string // "attribute type", "object class", "matching rule", "syntax"
	index int    // among that file's definitions of that kind
	oid   string
	names []string
	def   fmt.Stringer
}

func (c culprit) name() string {
	if len(c.names) > 0 {
		return c.names[0]
	}
	return c.oid
}

// findCulprit is the definition of d that schema.BuildFrom's error is about.
//
// go-authn/ldap v0.9.0's link errors are not typed: each names the definition
// it refuses, first, in a fixed sentence ("schema: the attribute type X has
// ...", "... is defined twice", "the name \"x\" is given to two ..."). This
// matches those sentences against the definitions of the one file the build
// was refused for -- every file before it built -- and the tests hold each
// sentence to a refusal with a line number, so a change of wording upstream
// fails here rather than losing the line. When several match, the last
// wins: of two definitions with one OID, the second is the redefinition.
func findCulprit(err error, d *schema.Definitions) (culprit, bool) {
	msg := err.Error()
	var found culprit
	ok := false
	try := func(c culprit, prefixes ...string) {
		for _, p := range prefixes {
			if strings.HasPrefix(msg, p) {
				found, ok = c, true
				return
			}
		}
	}
	names := func(what string, list []string) []string {
		var out []string
		for _, n := range list {
			out = append(out, fmt.Sprintf("schema: the name %q is given to two %ss", n, what))
		}
		return out
	}
	for i, x := range d.Syntaxes {
		try(culprit{"syntax", i, x.OID, nil, x}, "schema: the syntax "+x.OID+" is defined twice")
	}
	for i, x := range d.MatchingRules {
		c := culprit{"matching rule", i, x.OID, x.Names, x}
		try(c, append(names("matching rule", x.Names),
			"schema: the matching rule "+x.Name()+" ", "schema: the matching rule "+x.OID+" is defined twice")...)
	}
	for i, x := range d.AttributeTypes {
		c := culprit{"attribute type", i, x.OID, x.Names, x}
		try(c, append(names("attribute type", x.Names),
			"schema: the attribute type "+x.Name()+" ", "schema: the attribute type "+x.OID+" is defined twice")...)
	}
	for i, x := range d.ObjectClasses {
		c := culprit{"object class", i, x.OID, x.Names, x}
		try(c, append(names("object class", x.Names),
			"schema: the object class "+x.Name()+" ", "schema: the object class "+x.OID+" is defined twice",
			"schema: the abstract class "+x.Name()+" ", "schema: the structural class "+x.Name()+" ",
			"schema: the auxiliary class "+x.Name()+" ")...)
	}
	return found, ok
}

// refusal says why a file's definitions did not build, at the place where
// says the culprit is.
func refusal(err error, mine *schema.Definitions, o owners, where func(culprit) string) string {
	c, ok := findCulprit(err, mine)
	if !ok {
		return err.Error()
	}
	at := where(c)
	var prev owned
	var have bool
	for _, k := range append([]string{c.oid}, c.names...) {
		if prev, have = o[c.kind+" "+strings.ToLower(k)]; have {
			break
		}
	}
	if !have {
		return fmt.Sprintf("%s: %s", at, strings.TrimPrefix(err.Error(), "schema: "))
	}
	same := "a different definition"
	if prev.def.String() == c.def.String() {
		same = "the same definition, word for word"
	}
	return fmt.Sprintf("%s: the %s %s (%s) is already defined by %s, and this is %s: "+
		"a schema file adds definitions and never replaces one -- slapd refuses this too "+
		"(\"Duplicate %s\", servers/slapd/at.c and oc.c). Remove it from this file",
		at, c.kind, c.name(), c.oid, prev.where, same, slapdKind(c.kind))
}

// slapdKind is how slapd's error table spells a kind (schemaparse.c, err2text).
func slapdKind(kind string) string {
	switch kind {
	case "attribute type":
		return "attributeType"
	case "object class":
		return "objectClass"
	case "matching rule":
		return "matchingRule"
	}
	return "ldapSyntax"
}

// count is how many definitions of a kind d holds.
func (c culprit) count(d *schema.Definitions) int {
	switch c.kind {
	case "syntax":
		return len(d.Syntaxes)
	case "matching rule":
		return len(d.MatchingRules)
	case "attribute type":
		return len(d.AttributeTypes)
	}
	return len(d.ObjectClasses)
}

// locate is the line of f the culprit's definition starts on, or 0.
//
// schema.Definitions carry no positions, so the reader itself is asked: f cut
// before a line that starts a record -- a line that does not begin with white
// space, after a line that does not end in a joining backslash, which is
// where both of its forms start a new definition (slapd.conf(5); RFC 2849) --
// is a file whose definitions are the ones before that line, read exactly as
// the whole file was. The line is found by bisection over those cuts: the
// first cut holding more than index definitions of the kind is the record
// after the culprit's.
func locate(before []schema.File, f schema.File, c culprit) int {
	type cut struct{ line, off int }
	var cuts []cut
	off, prevJoins := 0, false
	for i, raw := range bytes.Split(f.Data, []byte("\n")) {
		l := bytes.TrimSuffix(raw, []byte("\r"))
		if len(l) > 0 && l[0] != ' ' && l[0] != '\t' && !prevJoins {
			cuts = append(cuts, cut{i + 1, off})
		}
		prevJoins = bytes.HasSuffix(l, []byte(`\`)) && !bytes.HasSuffix(l, []byte(`\\`))
		off += len(raw) + 1
	}
	prev, err := schema.Read(before...)
	if err != nil {
		return 0
	}
	base := c.count(prev)
	holds := func(j int) (bool, error) {
		if j == len(cuts) {
			return true, nil
		}
		d, err := schema.Read(append(before, schema.File{Name: f.Name, Data: f.Data[:cuts[j].off]})...)
		if err != nil {
			return false, err
		}
		return c.count(d)-base > c.index, nil
	}
	lo, hi := 0, len(cuts)
	for lo < hi {
		mid := (lo + hi) / 2
		ok, err := holds(mid)
		if err != nil {
			return 0
		}
		if ok {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	if lo == 0 {
		return 0
	}
	return cuts[lo-1].line
}

// labelled is where a schema block defines the culprit: the block of its
// kind labelled with one of its names or its OID, or the schema block itself.
func labelled(b hcl.Body, file string, c culprit) hcl.Range {
	kinds := map[string]string{"attribute type": "attribute_type", "object class": "object_class",
		"matching rule": "matching_rule", "syntax": "ldap_syntax"}
	body, ok := b.(*hclsyntax.Body)
	if !ok {
		return hcl.Range{Filename: file}
	}
	for _, blk := range body.Blocks {
		if blk.Type != kinds[c.kind] || len(blk.Labels) == 0 {
			continue
		}
		for _, k := range append([]string{c.oid}, c.names...) {
			if strings.EqualFold(blk.Labels[0], k) {
				return blk.DefRange()
			}
		}
	}
	return body.SrcRange
}

// describeAddition is "67 attribute types and 8 object classes".
func describeAddition(d *schema.Definitions) string {
	var parts []string
	for _, p := range []struct {
		n           int
		one, plural string
	}{
		{len(d.ObjectIdentifiers), "object identifier macro", "object identifier macros"},
		{len(d.Syntaxes), "syntax", "syntaxes"},
		{len(d.MatchingRules), "matching rule", "matching rules"},
		{len(d.AttributeTypes), "attribute type", "attribute types"},
		{len(d.ObjectClasses), "object class", "object classes"},
	} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, plural(p.n, p.one, p.plural)))
		}
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return list(parts)
}

// namesOf is the names of what d defines, types then classes.
func namesOf(d *schema.Definitions) []string {
	var out []string
	for _, x := range d.AttributeTypes {
		out = append(out, x.Name())
	}
	for _, x := range d.ObjectClasses {
		out = append(out, x.Name())
	}
	return out
}

// errNotDeclarable is the error a declared object class is refused with.
var errNotDeclarable = errors.New("not a class a configuration can declare")
