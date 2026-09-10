// Package cmd builds the flareadm command tree (docs/cli.md) and runs it.
package cmd

import (
	"context"
	stderrors "errors"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/account"
	"github.com/hnkNkm/flareadm/cmd/api"
	"github.com/hnkNkm/flareadm/cmd/auth"
	"github.com/hnkNkm/flareadm/cmd/cache"
	"github.com/hnkNkm/flareadm/cmd/certificate"
	"github.com/hnkNkm/flareadm/cmd/configure"
	"github.com/hnkNkm/flareadm/cmd/dns"
	"github.com/hnkNkm/flareadm/cmd/kv"
	"github.com/hnkNkm/flareadm/cmd/pagerule"
	"github.com/hnkNkm/flareadm/cmd/profile"
	"github.com/hnkNkm/flareadm/cmd/r2"
	"github.com/hnkNkm/flareadm/cmd/redirect"
	"github.com/hnkNkm/flareadm/cmd/ruleset"
	"github.com/hnkNkm/flareadm/cmd/ssl"
	"github.com/hnkNkm/flareadm/cmd/waf"
	"github.com/hnkNkm/flareadm/cmd/zone"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/version"
)

// NewCommand assembles the full command tree bound to a runtime.
func NewCommand(rt *app.Runtime) *cobra.Command {
	root := &cobra.Command{
		Use:           "flareadm",
		Short:         "FlareADM - fast, standalone administration CLI for Cloudflare",
		Long:          "flareadm is a standalone administration CLI for Cloudflare: a single native Go\nbinary for inspecting, configuring and operating remote Cloudflare resources\nfrom a terminal, a script, a CI pipeline or an AI agent.",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return rt.Init()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return errors.Usage("unknown command %q for %q", args[0], cmd.CommandPath())
		},
	}

	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return errors.Usage("%s", err.Error())
	})
	root.SetVersionTemplate("{{.Name}} version {{.Version}}\n")

	root.PersistentFlags().StringVar(&rt.ProfileFlag, "profile", "", "profile to use (default: FLAREADM_PROFILE or \"default\")")
	root.PersistentFlags().StringVar(&rt.AccountIDFlag, "account-id", "", "Cloudflare account id (overrides profile and FLAREADM_ACCOUNT_ID)")
	root.PersistentFlags().StringVar(&rt.ZoneFlag, "zone", "", "zone name or id (fallback: profile default_zone)")
	root.PersistentFlags().StringVar(&rt.OutputFlag, "output", "", "output format: table, json, yaml, text")
	root.PersistentFlags().BoolVar(&rt.JSONFlag, "json", false, "output the normalized JSON envelope (alias for --output json)")
	root.PersistentFlags().BoolVar(&rt.RawFlag, "raw", false, "bypass normalization; print the closest Cloudflare API response")
	root.PersistentFlags().IntVar(&rt.PageSizeFlag, "page-size", 0, "number of items per API page (default: 100)")
	root.PersistentFlags().IntVar(&rt.MaxItemsFlag, "max-items", 0, "stop after this many items (0 = no limit)")
	root.PersistentFlags().BoolVar(&rt.NoPaginateFlag, "no-paginate", false, "fetch only the first page")
	root.PersistentFlags().BoolVar(&rt.YesFlag, "yes", false, "skip confirmation prompts")
	root.PersistentFlags().BoolVar(&rt.DryRunFlag, "dry-run", false, "preview the operation without executing it")
	root.PersistentFlags().BoolVar(&rt.NoInputFlag, "no-input", false, "never prompt for input")
	root.PersistentFlags().BoolVar(&rt.NoColorFlag, "no-color", false, "disable colored output")
	root.PersistentFlags().BoolVar(&rt.VerboseFlag, "verbose", false, "verbose diagnostics on stderr")
	root.PersistentFlags().BoolVar(&rt.DebugFlag, "debug", false, "debug diagnostics on stderr (credentials redacted)")
	root.PersistentFlags().DurationVar(&rt.TimeoutFlag, "timeout", 0, "per-request attempt timeout (default: 30s)")
	root.PersistentFlags().StringVar(&rt.EndpointURLFlag, "endpoint-url", "", "Cloudflare API base URL (default: https://api.cloudflare.com/client/v4/)")

	root.AddCommand(versionCmd(rt))
	root.AddCommand(configure.New(rt))
	root.AddCommand(profile.New(rt))
	root.AddCommand(auth.New(rt))
	root.AddCommand(account.New(rt))
	root.AddCommand(zone.New(rt))
	root.AddCommand(dns.New(rt))
	root.AddCommand(ssl.New(rt))
	root.AddCommand(certificate.New(rt))
	root.AddCommand(ruleset.New(rt))
	root.AddCommand(waf.New(rt))
	root.AddCommand(redirect.New(rt))
	root.AddCommand(r2.New(rt))
	root.AddCommand(kv.New(rt))
	root.AddCommand(pagerule.New(rt))
	root.AddCommand(cache.New(rt))
	root.AddCommand(api.New(rt))
	addCompletion(root, rt)

	return root
}

// Run executes the CLI and returns the process exit code. All output goes to
// out/errOut; diagnostics use errOut only.
func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	rt := app.NewRuntime(in, out, errOut)
	root := NewCommand(rt)
	root.SetOut(out)
	root.SetErr(errOut)
	root.SetArgs(args)

	err := root.ExecuteContext(ctx)
	if err == nil {
		return errors.CodeSuccess
	}
	var exit *errors.ExitError
	if stderrors.As(err, &exit) {
		printError(errOut, rt.Redact(err.Error()))
		return exit.Code
	}
	// Cobra leaves plain errors for unknown subcommands/flags.
	if strings.HasPrefix(err.Error(), "unknown command") {
		printError(errOut, rt.Redact(err.Error()))
		return errors.CodeInvalid
	}
	printError(errOut, rt.Redact(err.Error()))
	return errors.CodeUnclassified
}

func printError(w io.Writer, msg string) {
	_, _ = io.WriteString(w, "Error: ")
	_, _ = io.WriteString(w, msg)
	_, _ = io.WriteString(w, "\n")
}
