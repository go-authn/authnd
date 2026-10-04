// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"

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
//   - ⛔ But a code is COUNTED only behind the right password. The limits on
//     codes (a pause after a few wrong ones, a lockout after a hundred) are
//     there against guessing codes, and they belong to the person: counting
//     the code of a bind whose password was wrong let anybody who knew a NAME
//     freeze its owner for fifteen minutes with five binds, and lock them out
//     for good with a hundred. Behind a wrong password the code is still
//     computed, against nothing that remembers, so the time taken says no
//     more than it did.
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
	pw := &knowledge{name: "your password", verify: id.Verify, given: password}
	return []mfa.Factor{pw, s.codeBehind(pw, id.Name(), id.TOTPSecret(), code)}, nil
}

// codeBehind is the code, counted against its owner only when the password
// in front of it was right.
func (s *server) codeBehind(pw *knowledge, name string, secret []byte, code string) mfa.Factor {
	return afterPassword{
		Factor:    totp.Factor(name, secret, []byte(code), s.codes),
		stateless: totp.Factor(name, secret, []byte(code), nil),
		pw:        pw,
		opts:      s.codes.Options,
		secret:    secret,
		code:      []byte(code),
	}
}

// afterPassword asks the Verifier, which counts, only once the password has
// been proven. Otherwise the code is checked with the same work and nothing
// remembered, and refused whatever it was.
type afterPassword struct {
	mfa.Factor
	stateless    mfa.Factor
	pw           *knowledge
	opts         totp.Options
	secret, code []byte
}

func (f afterPassword) Verify(ctx context.Context) error {
	if f.pw.Verify(ctx) == nil {
		return f.Factor.Verify(ctx)
	}
	if len(f.secret) == 0 {
		// Nobody enrolled: still said as such, which counts nothing either.
		return f.stateless.Verify(ctx)
	}
	_ = totp.Verify(f.secret, f.code, f.opts)
	return errNotCounted
}

var errNotCounted = fmt.Errorf("not looked at, since the password in front of it was wrong")

// knowledge is the password, as a factor.
//
// It is here rather than in a library because what "the right password" means
// belongs to the identity: a comparison this process can do, or a bind against
// a directory that holds the password and will not give it up.
//
// The password is checked ONCE however often it is asked, because the code
// behind it asks too, and a second check would be a second bind against a
// directory -- and a second count against a directory's own lockout.
type knowledge struct {
	name   string
	verify func(string) error
	given  string

	once sync.Once
	err  error
}

func (k *knowledge) Name() string   { return k.name }
func (k *knowledge) Kind() mfa.Kind { return mfa.Knowledge }

func (k *knowledge) Verify(context.Context) error {
	k.once.Do(func() {
		if k.verify == nil {
			k.err = mfa.Unavailable(fmt.Errorf("nothing here can check a password for this person"))
			return
		}
		k.err = k.verify(k.given)
	})
	return k.err
}

// verifyPassword is the one-factor path: no policy, no code, just the
// identity's own check.
func verifyPassword(id *directory.Identity, given string) error {
	return id.Verify(given)
}

// constantTimeEqual is used where the comparison is against something this
// process holds, rather than against a directory that will answer for us.
//
// ⛔ subtle.ConstantTimeCompare is constant-time only for inputs of the SAME
// length: it returns at once when the lengths differ, so comparing a guess
// against the secret itself answers "how long is it" one guess at a time. Both
// sides are hashed first, and the comparison is of two 32-byte digests --
// fixed length, whatever was typed.
func constantTimeEqual(a, b string) bool {
	da, db := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(da[:], db[:]) == 1
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
