// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	_ "embed"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/go-authn/directory"
)

// sambaSchema is the part of Samba's schema that publish_nt_hash needs:
// sambaSamAccount, sambaSID and sambaNTPassword. See the file for where each
// definition comes from, and why it was written rather than copied.
//
//go:embed samba.schema
var sambaSchema []byte

// defaultRIDBase is Samba's default "algorithmic rid base" (smb.conf(5)),
// and BASE_RID (0x3e8, source3/include/includes.h), below which Samba refuses
// one.
const defaultRIDBase = 1000

// checkSamba refuses publish_nt_hash without the domain a sambaSID needs, and
// a samba block that would publish SIDs Samba does not compute.
//
// ⛔ THIS REFUSES A CONFIGURATION THAT v0.10.2 SERVED. publish_nt_hash = true
// alone published sambaNTPassword on an entry with no sambaSamAccount, which
// is the only class that allows it, and no sambaSID, which that class
// requires. Every entry this server publishes is now held to the schema it
// publishes, so that entry cannot be published as it was. The two other ways
// out are both silent: dropping the attribute takes SMB away from every
// person with nothing on the console, and dropping the entry takes the
// person away. A refusal at startup is said where somebody is watching, and
// says what to add.
func (c *config) checkSamba() error {
	if c.Samba == nil {
		if c.PublishNTHash {
			return fmt.Errorf("publish_nt_hash needs a samba block: sambaNTPassword belongs to Samba's sambaSamAccount, " +
				"whose MUST is uid and sambaSID, and a SID needs the domain's. Add\n\n" +
				"  samba {\n    domain_sid = \"S-1-5-21-...\"   # the SMB server's: `net getlocalsid` prints it\n  }\n\n" +
				"and each person's sambaSID is their own sambaSID attribute, or domain_sid-(2 x uidNumber + 1000), " +
				"Samba's algorithmic mapping; `authnd check` lists who has neither")
		}
		return nil
	}
	if !c.PublishNTHash {
		return fmt.Errorf("a samba block without publish_nt_hash publishes nothing: it is the domain of the sambaSID " +
			"that sambaNTPassword needs. Remove it, or set publish_nt_hash = true")
	}
	if _, err := parseSID(c.Samba.DomainSID); err != nil {
		return fmt.Errorf("samba: domain_sid %q: %w", c.Samba.DomainSID, err)
	}
	if b := c.Samba.RIDBase; b != 0 && (b < defaultRIDBase || b%2 != 0) {
		// Samba does not refuse these: algorithmic_rid_base() in
		// source3/passdb/passdb.c logs and uses 1000, or adds one to an odd
		// base. Taken as written here, the SIDs published would not be the
		// ones Samba computes; corrected silently, the configuration would
		// say one thing and do another.
		return fmt.Errorf("samba: algorithmic_rid_base = %d: Samba requires an even number of at least %d "+
			"(source3/passdb/passdb.c), and would use another one than this", b, defaultRIDBase)
	}
	return nil
}

// ridBase is the configured algorithmic rid base, or Samba's default.
func (b *sambaBlock) ridBase() uint64 {
	if b.RIDBase == 0 {
		return defaultRIDBase
	}
	return uint64(b.RIDBase)
}

// parseSID reads a SID in its string form, S-1-<authority>-<sub>..., and
// refuses one that cannot be a domain's: it needs at least one sub-authority,
// and room for the RID a person's SID appends (15 sub-authorities at most,
// [MS-DTYP] 2.4.2).
func parseSID(s string) ([]uint64, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 4 || parts[0] != "S" || parts[1] != "1" {
		return nil, fmt.Errorf("not a SID: it is written S-1-5-21-<three numbers>, as `net getlocalsid` prints it")
	}
	if len(parts)-3 > 14 {
		return nil, fmt.Errorf("%d sub-authorities leave no room for a RID (a SID has at most 15)", len(parts)-3)
	}
	var out []uint64
	for i, p := range parts[2:] {
		limit := uint64(math.MaxUint32)
		if i == 0 {
			limit = 1<<48 - 1 // the identifier authority is six bytes
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil || n > limit || p != strconv.FormatUint(n, 10) {
			return nil, fmt.Errorf("%q is not a number a SID can hold there", p)
		}
		out = append(out, n)
	}
	return out, nil
}

// sambaSID is the SID a person is published with, and where it came from.
// An empty sid comes with the reason there is none.
func (s *server) sambaSID(id *directory.Identity) (sid, why string) {
	if s.cfg.Samba == nil {
		return "", "no samba block"
	}
	if given := id.Attributes().Get("sambaSID"); len(given) > 0 {
		return given[0], ""
	}
	uids := id.Attributes().Get("uidNumber")
	if len(uids) == 0 {
		return "", "no sambaSID and no uidNumber to derive one from"
	}
	uid, err := strconv.ParseUint(uids[0], 10, 64)
	if err != nil {
		return "", fmt.Sprintf("uidNumber %q is not a number to derive a sambaSID from", uids[0])
	}
	// algorithmic_pdb_uid_to_user_rid: uid * RID_MULTIPLIER + base, OR
	// USER_RID_TYPE (0). The largest RID Samba maps back is 0xfffffffe
	// (max_algorithmic_uid).
	rid := uid*2 + s.cfg.Samba.ridBase()
	if uid > math.MaxUint32 || rid > 0xfffffffe {
		return "", fmt.Sprintf("uidNumber %d is too large for Samba's algorithmic mapping (the RID would be past 0xfffffffe)", uid)
	}
	return s.cfg.Samba.DomainSID + "-" + strconv.FormatUint(rid, 10), ""
}
