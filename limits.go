// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
)

// Limits on what a client, or a slow source, may cost this server.
//
// ⛔ Bibliography: go-authn/ldap v0.12.0 server.go (MaxConnections,
// MaxConnectionsPerIP, Timeout) and RFC 4511 4.4.1 (a connection over the
// limit is sent a notice of disconnection, result code busy, and closed);
// 4.1.9 / appendix A.2 (busy 51 and unavailable 52 are "try later", and
// invalidCredentials 49 is the only code that says the credentials are wrong).
const (
	// defaultMaxConnections is what a configuration that says nothing gets:
	// well under the descriptor limit of a stock Linux service (1024 soft is
	// the floor on old kernels, 1048576 on systemd >= 240), so a flood is
	// refused with busy instead of ending the process at EMFILE. A site with a
	// low `ulimit -n` lowers it; "0" removes the limit.
	defaultMaxConnections = 4096
	// defaultOperationTimeout bounds one LDAP operation: a bind that waits on
	// an upstream directory is answered unavailable (52) before it, and any
	// other operation that is still running is answered timeLimitExceeded (3)
	// by the library at it.
	defaultOperationTimeout = 30 * time.Second
	// defaultStartupTimeout bounds opening and first reading every source.
	defaultStartupTimeout = 60 * time.Second
)

// limits is the resolved form of the max_connections, max_connections_per_ip,
// operation_timeout and startup_timeout keys.
type limits struct {
	maxConns, perIP int
	operation       time.Duration
	startup         time.Duration
}

// limits resolves the configuration to numbers; checkLimits has validated it.
func (c *config) limits() limits {
	l := limits{maxConns: defaultMaxConnections, operation: defaultOperationTimeout, startup: defaultStartupTimeout}
	if c.MaxConnections != nil {
		l.maxConns = *c.MaxConnections
	}
	if c.MaxConnectionsPerIP != nil {
		l.perIP = *c.MaxConnectionsPerIP
	}
	if c.OperationTimeout != "" {
		l.operation, _ = time.ParseDuration(c.OperationTimeout)
	}
	if c.StartupTimeout != "" {
		l.startup, _ = time.ParseDuration(c.StartupTimeout)
	}
	return l
}

func (c *config) checkLimits() error {
	for _, n := range []struct {
		key string
		v   *int
	}{{"max_connections", c.MaxConnections}, {"max_connections_per_ip", c.MaxConnectionsPerIP}} {
		if n.v != nil && *n.v < 0 {
			return fmt.Errorf("%s %d: zero or more (0 means no limit)", n.key, *n.v)
		}
	}
	if c.MaxConnections != nil && c.MaxConnectionsPerIP != nil &&
		*c.MaxConnections > 0 && *c.MaxConnectionsPerIP > *c.MaxConnections {
		return fmt.Errorf("max_connections_per_ip %d is more than max_connections %d: it could never apply",
			*c.MaxConnectionsPerIP, *c.MaxConnections)
	}
	for _, d := range []struct{ key, v string }{{"operation_timeout", c.OperationTimeout}, {"startup_timeout", c.StartupTimeout}} {
		if d.v == "" {
			continue
		}
		t, err := time.ParseDuration(d.v)
		if err != nil {
			return fmt.Errorf("%s %q: %w (for example \"30s\", or \"0\" for no limit)", d.key, d.v, err)
		}
		if t < 0 || (t > 0 && t < 100*time.Millisecond) {
			return fmt.Errorf("%s %q: at least 100ms, or 0 for no limit", d.key, d.v)
		}
	}
	return nil
}

// limitLines is what `check` prints, so that an administrator sees the
// defaults they are running with rather than the ones they assume.
func (c *config) limitLines() []string {
	l := c.limits()
	count := func(n int) string {
		if n == 0 {
			return "no limit"
		}
		return fmt.Sprint(n)
	}
	dur := func(d time.Duration) string {
		if d == 0 {
			return "no limit"
		}
		return d.String()
	}
	return []string{
		fmt.Sprintf("limits: %s connections, %s per address; an operation may take %s; startup may take %s",
			count(l.maxConns), count(l.perIP), dur(l.operation), dur(l.startup)),
	}
}

// outage reports whether err says a source could not be ASKED, as opposed to
// answering no. go-authn/directory v0.17.0 ErrUnavailable.
func outage(err error) bool { return errors.Is(err, directory.ErrUnavailable) }

// verifyWithin asks id to verify a password, and gives up when ctx ends.
//
// ⛔ Identity.Verify takes no context, and an identity from ldapdir is a bind
// against another server: one that accepts the connection and never answers
// held the client until the library's own deadline, and was then reported as
// timeLimitExceeded. A deadline here is an outage of the source, and says so
// (ErrUnavailable), which the bind turns into LDAP unavailable (52). The
// abandoned goroutine ends when the source answers or its own client times
// out; it holds no lock.
func verifyWithin(ctx context.Context, id *directory.Identity, given string) error {
	return within(ctx, func() error { return id.Verify(given) })
}

// within runs f and returns its error, or ErrUnavailable once ctx is done.
func within(ctx context.Context, f func() error) error {
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return directory.AsUnavailable(fmt.Errorf("the source did not answer in time: %w", ctx.Err()))
	}
}

// bindBudget is how long a bind may wait on a source: a little less than the
// operation timeout, so that this answer (52) is the one the client gets and
// not the library's timeLimitExceeded (3) at the full deadline.
func (s *server) bindBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	op := s.cfg.limits().operation
	if op <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, op-op/10)
}

// sourceNames says which sources startup is about to open, for an error that
// has to name the one that did not answer.
func sourceNames(blocks []hcldir.Block) string {
	if len(blocks) == 0 {
		return "no external source"
	}
	var parts []string
	for _, b := range blocks {
		name := b.Kind
		if b.URL != "" {
			if u, err := url.Parse(b.URL); err == nil {
				name += " " + u.Redacted()
			}
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, ", ")
}

// startup runs the part of open() that talks to sources, bounded by
// startup_timeout, and names the stage it was in when the time ran out.
//
// ⛔ Before this, open() waited on a source for as long as the source cared to
// make it wait, so a systemd unit started against a half-up database sat in
// "activating" with nothing in the journal. The work cannot be cancelled (the
// source libraries take no context), so it runs in a goroutine that owns its
// own cleanup: if nobody is waiting any more, it closes what it opened.
func (s *server) startup(work func(stage func(string)) error) error {
	limit := s.cfg.limits().startup
	if limit <= 0 {
		err := work(func(string) {})
		if err != nil {
			s.dir.Close()
		}
		return err
	}
	var stage atomic.Value
	stage.Store("starting")
	var mu sync.Mutex
	var finished, abandoned bool
	var once sync.Once
	cleanup := func() { once.Do(func() { s.dir.Close() }) }
	done := make(chan error, 1)
	go func() {
		err := work(func(st string) { stage.Store(st) })
		mu.Lock()
		finished = true
		gone := abandoned
		mu.Unlock()
		if gone {
			cleanup()
		}
		done <- err
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			cleanup()
		}
		return err
	case <-timer.C:
		mu.Lock()
		abandoned = true
		late := finished // finished while we gave up: nobody will use it
		mu.Unlock()
		if late {
			cleanup()
		}
		return fmt.Errorf("startup did not finish within %s (startup_timeout): %s did not answer",
			limit, stage.Load())
	}
}
