// SPDX-License-Identifier: BSD-3-Clause

package main

import (
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
// decoded by hclschema, not by gohcl. (",remain" rather than ",body": with
// ",body" gohcl also checks the body against the struct's empty schema and
// refuses every block in it.)
type schemaBlock struct {
	Body     hcl.Body  `hcl:",remain"`
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
			return nil, fmt.Errorf("schema_files: %s", refusal(err, mine, owners, path))
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
	for i := range files {
		all, err := hclschema.Decode(files[:i+1]...)
		if err != nil {
			return nil, fmt.Errorf("schema block: %w", err)
		}
		mine := since(all, local)
		block := cfg.Schemas[i]
		where := "the schema block at " + position(block.DefRange)
		if _, err := schema.BuildFrom(base, site, all); err != nil {
			return nil, fmt.Errorf("schema block: %s", refusal(err, mine, owners, position(block.DefRange)))
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

// refusal says why the definitions one file or block added did not build,
// at the line of the definition refused.
//
// go-authn/ldap's *schema.BuildError says which definition it refused, why,
// and where the definition starts -- the file and line the reader found it
// on, before any continuation line was joined to it, or the block's own
// line and column -- so nothing here reads the message to find the
// definition, or re-reads the file to find its line. where (the file as
// named in schema_files, or the block's position) is said instead only when
// the error carries no position, which a definition read from a file or a
// block always has; an error that is not a BuildError is said as it is.
//
// A DuplicateOID or DuplicateName whose first definition is the standard
// schema's, Samba's, or an earlier file's or block's is a redefinition, and
// is said as one: what defined it first, where, and whether the two say the
// same thing.
func refusal(err error, mine *schema.Definitions, o owners, where string) string {
	var be *schema.BuildError
	if !errors.As(err, &be) {
		return err.Error()
	}
	at := where
	if be.Pos.IsValid() {
		at = be.Pos.String()
	}
	prev, redefined := owned{}, false
	if be.Kind == schema.DuplicateOID || be.Kind == schema.DuplicateName {
		prev, redefined = o[be.Element.String()+" "+strings.ToLower(be.RefOID)]
	}
	if !redefined {
		// The message without its position, as BuildError words one that
		// has none: "schema: " and ldap's sentence.
		bare := *be
		bare.Pos = schema.Position{}
		return fmt.Sprintf("%s: %s (%s)", at, strings.TrimPrefix(bare.Error(), "schema: "), be.Kind)
	}
	name := be.Name
	if name == "" {
		name = be.OID
	}
	first := prev.where
	switch {
	case be.RefPos.IsValid() && be.RefPos.File == prev.where:
		first = be.RefPos.String() // an earlier file: its own line
	case be.RefPos.IsValid():
		first += " (" + be.RefPos.String() + ")" // which file of the standard schema, or which block
	}
	same := "a different definition"
	if def := definitionAt(mine, be); def != nil && prev.def.String() == def.String() {
		same = "the same definition, word for word"
	}
	return fmt.Sprintf("%s: the %s %s (%s) is already defined by %s, and this is %s: "+
		"a schema file adds definitions and never replaces one -- slapd refuses this too "+
		"(\"Duplicate %s\", servers/slapd/at.c and oc.c). Remove it from this file",
		at, be.Element, name, be.OID, first, same, slapdKind(be.Element.String()))
}

// definitionAt is the definition of d a BuildError is about: the one of its
// element with its OID that starts where it says.
func definitionAt(d *schema.Definitions, be *schema.BuildError) fmt.Stringer {
	match := func(oid string, pos schema.Position) bool { return oid == be.OID && pos == be.Pos }
	switch be.Element {
	case schema.ElementSyntax:
		for _, x := range d.Syntaxes {
			if match(x.OID, x.Pos) {
				return x
			}
		}
	case schema.ElementMatchingRule:
		for _, x := range d.MatchingRules {
			if match(x.OID, x.Pos) {
				return x
			}
		}
	case schema.ElementAttributeType:
		for _, x := range d.AttributeTypes {
			if match(x.OID, x.Pos) {
				return x
			}
		}
	case schema.ElementObjectClass:
		for _, x := range d.ObjectClasses {
			if match(x.OID, x.Pos) {
				return x
			}
		}
	}
	return nil
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
