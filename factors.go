// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/go-authn/directory"
	"github.com/go-authn/mfa"
	"github.com/go-authn/totp"
)

// A second factor, over a protocol that has room for exactly one field.
//
// LDAP's simple bind carries a name and a password and nothing else. There is
// no place to put a code, no round trip to ask for one, and a client that
// speaks LDAP will not learn one. So the code goes on the END of the password
// -- "hunter2314159" -- which is what every appliance that has ever done this
// does, and what people already know how to type.
//
// ⛔ The consequences, since they are not obvious:
//
//   - The split is by LENGTH: the last N characters are the code, the rest is
//     the password. A password ending in digits is therefore fine, and a
//     password SHORTER than the code cannot be told apart from one -- so a
//     bind whose whole field is the size of a code is refused rather than
//     guessed at.
//
//   - Both halves are checked whatever happens. Returning early when the
//     password is wrong would say, in the time taken, whether the password or
//     the code was the wrong one.
//
//   - A person with no secret enrolled has REFUSED nothing. mfa counts that
//     separately, and the server can then say "you have no second factor"
//     rather than "wrong code" -- to the log, not to the client, which is told
//     only that the bind failed.

// splitCode takes the code off the end of what was typed.
func splitCode(given string, digits int) (password, code string, ok bool) {
	if len(given) <= digits {
		// Not "the password is empty": a field the size of a code is a person
		// who typed only the code, or a password nobody can tell from one.
		return "", "", false
	}
	return given[:len(given)-digits], given[len(given)-digits:], true
}

// factorsFor is what the policy will ask about this person, given what they
// typed at the bind.
func (s *server) factorsFor(id *directory.Identity, given string) ([]mfa.Factor, error) {
	digits := s.mfaDigits()
	password, code, ok := splitCode(given, digits)
	if !ok {
		return nil, fmt.Errorf("what was typed is %d characters, and the last %d of it are the code",
			len(given), digits)
	}
	return []mfa.Factor{
		knowledge{name: "your password", verify: id.Verify, given: password},
		totp.Factor(id.Name(), id.TOTPSecret(), []byte(code), s.codes),
	}, nil
}

// knowledge is the password, as a factor.
//
// It is here rather than in a library because what "the right password" means
// belongs to the identity: a comparison this process can do, or a bind against
// a directory that holds the password and will not give it up.
type knowledge struct {
	name   string
	verify func(string) error
	given  string
}

func (k knowledge) Name() string   { return k.name }
func (k knowledge) Kind() mfa.Kind { return mfa.Knowledge }

func (k knowledge) Verify(context.Context) error {
	if k.verify == nil {
		return mfa.Unavailable(fmt.Errorf("nothing here can check a password for this person"))
	}
	return k.verify(k.given)
}

// verifyPassword is the one-factor path: no policy, no code, just the
// identity's own check.
func verifyPassword(id *directory.Identity, given string) error {
	return id.Verify(given)
}

// constantTimeEqual is used where the comparison is against something this
// process holds, rather than against a directory that will answer for us.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// describePolicy says what a bind will be asked for, for `check` to print.
func describePolicy(p mfa.Policy, digits int) string {
	if p.Count < 2 {
		return "a password"
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("a password with a %d-digit code after it", digits))
	if p.DistinctKinds {
		parts = append(parts, "of two different kinds")
	}
	return strings.Join(parts, ", ")
}
