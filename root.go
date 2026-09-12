// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"syscall"
	"text/tabwriter"

	"github.com/go-authn/directory"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// options is what the flags say.
type options struct {
	files []string
}

func (o *options) bind(f *pflag.FlagSet) {
	f.StringArrayVarP(&o.files, "config", "c", nil,
		"an HCL file, or a directory of .hcl files (repeatable)")
}

const longHelp = `authnd is an LDAP server for people who are somewhere else: a SQL database, a
configuration file, or another directory.

    authnd --config /etc/authnd.d
    authnd check /etc/authnd.d

It binds and searches over go-authn/directory's sources, so that what a
database holds can be read by anything that knows how to ask a directory.

What it refuses is the design:

  - the UNAUTHENTICATED BIND, which a real directory answers with success and
    which means "I am anonymous" rather than "I proved this name";
  - ANONYMOUS SEARCH, because a directory that answers everybody has published
    its people to everybody;
  - a CREDENTIAL over a plaintext socket: sambaNTPassword is not a password
    hash in the sense a login form means, and publishing it takes TLS or a
    listener that is not on the network.`

func newRootCmd() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:           "authnd [flags]",
		Short:         "an LDAP server for people who are somewhere else",
		Long:          longHelp,
		Version:       version(),
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE:          func(cmd *cobra.Command, args []string) error { return serve(cmd, o, args) },
	}
	o.bind(cmd.Flags())
	cmd.AddCommand(newCheckCmd(o))
	return cmd
}

func newCheckCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check [file or directory...]",
		Short: "read the configuration, open every source, and say what would be served",
		Long: `check opens every source -- the database, the directory, the files -- and
prints what this configuration would publish and to whom, WITHOUT listening.

It is what to run before restarting something people are logging in through.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := configOf(o, args)
			if err != nil {
				return err
			}
			return report(cmd, cfg)
		},
	}
	o.bind(cmd.Flags())
	return cmd
}

func configOf(o *options, args []string) (*config, error) {
	paths := append([]string{}, o.files...)
	paths = append(paths, args...)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no configuration: give a .hcl file or a directory of them")
	}
	return loadConfig(paths)
}

func serve(cmd *cobra.Command, o *options, args []string) error {
	cfg, err := configOf(o, args)
	if err != nil {
		return err
	}
	srv, err := open(cfg, cmd.OutOrStdout())
	if err != nil {
		return err
	}
	defer srv.Close()
	if err := srv.listen(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.serve() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		fmt.Fprintln(cmd.OutOrStdout(), "\nstopping")
		srv.Close()
		return <-done
	}
}

// report is `check`: everything this configuration would publish, and the
// awkward half said out loud.
func report(cmd *cobra.Command, cfg *config) error {
	out := cmd.OutOrStdout()
	srv, err := open(cfg, out)
	if err != nil {
		return err
	}
	defer srv.Close()

	fmt.Fprintf(out, "%s://%s, base %s\n\n", srv.scheme(), cfg.Listen, cfg.BaseDN)

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USER\tFROM\tCAN PROVE\tPUBLISHED AS")
	for _, id := range srv.sorted() {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", id.Name(), id.Where(), proves(id), published(srv, id))
	}
	if err := w.Flush(); err != nil {
		return err
	}

	strangers := map[string][]string{}
	if groups := srv.groupNames(); len(groups) > 0 {
		fmt.Fprintln(out)
		w = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "GROUP\tMEMBERS")
		for _, g := range groups {
			members, err := srv.dir.Members(g)
			if err != nil {
				fmt.Fprintf(w, "%s\t%v\n", g, err)
				continue
			}
			fmt.Fprintf(w, "%s\t%s\n", g, list(members))
			for _, m := range members {
				if _, known := srv.who[m]; !known {
					strangers[g] = append(strangers[g], m)
				}
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	kerberosReport(out, cfg, srv.sorted())

	// A group naming somebody no source here has an entry for. Published as
	// it stands -- memberUid is a string, and a proxy in front of one system
	// legitimately carries names another one owns -- but said out loud,
	// because the other reading is a typo that silently grants nothing.
	for _, g := range slices.Sorted(maps.Keys(strangers)) {
		fmt.Fprintf(out, "%s names %s, who %s here: the group is published as it stands, "+
			"and nothing here can prove them\n",
			g, list(strangers[g]), plural(len(strangers[g]), "has no entry", "have no entries"))
	}

	// What a bind must carry, and who cannot satisfy it. A policy of two
	// factors and a person with one is a person who cannot log in, and that
	// is worth knowing before the restart rather than after it.
	fmt.Fprintf(out, "\na bind carries %s\n", describePolicy(srv.policy, srv.mfaDigits()))
	if srv.wantsCode() {
		var without []string
		for _, id := range srv.sorted() {
			if !id.Can(directory.TOTPSecret) {
				without = append(without, id.Name())
			}
		}
		if len(without) > 0 {
			fmt.Fprintf(out, "%s %s no second factor here, and cannot bind while one is required\n",
				list(without), plural(len(without), "has", "have"))
		}
	}

	if len(srv.readers) == 0 {
		fmt.Fprintln(out, "no reader is declared: nothing may search, and every bind still works")
	} else {
		var names []string
		for _, r := range cfg.Readers {
			names = append(names, r.DN)
		}
		fmt.Fprintf(out, "%s may search; every other bound client may not\n", list(names))
	}
	// ⛔ The sentence a site needs BEFORE it points a file server here.
	if cfg.PublishNTHash {
		fmt.Fprintf(out, "sambaNTPassword is published%s: it IS the credential, "+
			"and whoever reads it authenticates as that person over NTLMv2\n", overWhat(cfg))
	} else {
		fmt.Fprintln(out, "sambaNTPassword is not published, so nothing here can authenticate an SMB session "+
			"(NTLMv2 needs the password or its MD4, and a bind cannot answer it)")
	}
	fmt.Fprintln(out, "\nthis configuration can be served")
	return nil
}

// proves is what a source could give for somebody: never what it IS.
func proves(id *directory.Identity) string {
	var have []string
	switch {
	case id.Can(directory.Password):
		have = append(have, "a password")
	case id.Can(directory.Verifier):
		have = append(have, "a password check")
	}
	if id.Can(directory.NTHash) && !id.Can(directory.Password) {
		have = append(have, "an NT hash")
	}
	if n := len(id.Keys()); n > 0 {
		have = append(have, fmt.Sprintf("%d %s", n, plural(n, "key", "keys")))
	}
	if id.Can(directory.TOTPSecret) {
		have = append(have, "a one-time-code secret")
	}
	if len(have) == 0 {
		return "nothing"
	}
	return list(have)
}

// published is the attributes this person's entry will carry.
func published(s *server, id *directory.Identity) string {
	attrs := []string{"uid", "cn"}
	if s.cfg.PublishNTHash {
		if _, err := id.NTKey(); err == nil {
			attrs = append(attrs, "sambaNTPassword")
		}
	}
	if len(id.Keys()) > 0 {
		attrs = append(attrs, "sshPublicKey")
	}
	return list(attrs)
}

// overWhat says what protects the wire, since that is the whole condition
// under which publishing a credential is defensible.
func overWhat(cfg *config) string {
	if cfg.tls() {
		return " over TLS"
	}
	return " on a loopback listener"
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "(devel)"
}
