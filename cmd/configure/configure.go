// Package configure implements `flareadm configure init|get|set|list`.
//
// These commands are local-only: they read and write the TOML configuration
// file and never touch the network. They follow the AWS `aws configure`
// model: get/set operate on the active profile (--profile, FLAREADM_PROFILE
// or "default") and set creates the profile implicitly.
package configure

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/auth"
	"github.com/hnkNkm/flareadm/internal/config"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
	"github.com/hnkNkm/flareadm/internal/profile"
)

// New builds the configure command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Manage the local FlareADM configuration",
		Long: "Configure the local FlareADM configuration file (config.toml).\n" +
			"Profiles reference the environment variable holding the API token;\n" +
			"tokens are never stored in the file.",
	}
	cmd.AddCommand(
		newInit(rt),
		newGet(rt),
		newSet(rt),
		newList(rt),
	)
	return cmd
}

// keyRow is the normalized shape of one configuration key.
type keyRow struct {
	Key    string `json:"key" yaml:"key"`
	Value  string `json:"value" yaml:"value"`
	Source string `json:"source" yaml:"source"`
}

// profileValues returns the supported keys of a profile.
func profileValues(p *config.Profile) map[string]string {
	out := map[string]string{}
	if p == nil {
		return out
	}
	out["account_id"] = p.AccountID
	out["api_token_env"] = p.APITokenEnv
	out["default_zone"] = p.DefaultZone
	return out
}

// validKey checks a configuration key name.
func validKey(key string) bool {
	for _, k := range profile.ConfigKeys {
		if k == key {
			return true
		}
	}
	return false
}

// newInit writes an initial configuration with one profile. It fails when
// the configuration file already exists with content.
func newInit(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create an initial configuration file",
		Long: "Create the configuration file with a profile that reads the API token\n" +
			"from the environment. Refuses to overwrite an existing configuration.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			if !cfg.Empty() {
				return errors.New(errors.CodeConflict,
					"configuration already exists at %s; use 'profile create' or 'configure set' to change it",
					cfg.Path())
			}

			name := rt.ActiveProfileName()
			cfg.Set(name, config.Profile{APITokenEnv: pickTokenEnv(rt)})
			if err := cfg.Save(); err != nil {
				return errors.Wrap(errors.CodeUnclassified, "saving configuration", err)
			}
			_, _ = fmt.Fprintf(rt.Err, "Initialized FlareADM configuration at %s (profile %q)\n", cfg.Path(), name)
			return nil
		},
	}
}

// pickTokenEnv chooses the api_token_env value for configure init: the
// first set credential environment variable in resolution order, or the
// conventional CLOUDFLARE_API_TOKEN.
func pickTokenEnv(rt *app.Runtime) string {
	for _, name := range auth.CredentialEnvOrder {
		if v := rt.Getenv(name); v != "" {
			return name
		}
	}
	return "CLOUDFLARE_API_TOKEN"
}

// newGet prints the value of KEY in the active profile, or the whole
// profile when no key is given.
func newGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get [KEY]",
		Short: "Print a configuration value for the active profile",
		Long: "Print the value of KEY (account_id, api_token_env or default_zone) for the\n" +
			"active profile, or the whole profile when KEY is omitted.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			p, _ := cfg.Profile(rt.ActiveProfileName())
			values := profileValues(&p)

			if len(args) == 1 {
				key := args[0]
				if !validKey(key) {
					return errors.Usage("unknown configuration key %q (supported: %s)", key, strings.Join(profile.ConfigKeys, ", "))
				}
				if rt.Format() == output.Table {
					_, _ = fmt.Fprintln(rt.Out, values[key])
					return nil
				}
				return rt.Printer().Emit(keyRow{Key: key, Value: values[key], Source: "config"})
			}

			rows := make([]keyRow, 0, len(profile.ConfigKeys))
			for _, k := range profile.ConfigKeys {
				rows = append(rows, keyRow{Key: k, Value: values[k], Source: "config"})
			}
			if rt.Format() == output.Table {
				tbl := make([][]string, 0, len(rows))
				for _, r := range rows {
					tbl = append(tbl, []string{r.Key, r.Value})
				}
				return rt.Printer().PrintTable([]string{"KEY", "VALUE"}, tbl)
			}
			return rt.Printer().Emit(rows)
		},
	}
}

// newSet writes KEY VALUE into the active profile, creating it when
// missing.
func newSet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "set KEY VALUE",
		Short: "Set a configuration value for the active profile",
		Long: "Set KEY (account_id, api_token_env or default_zone) to VALUE in the active\n" +
			"profile, creating the profile when it does not exist.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]
			if !validKey(key) {
				return errors.Usage("unknown configuration key %q (supported: %s)", key, strings.Join(profile.ConfigKeys, ", "))
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			name := rt.ActiveProfileName()
			p, _ := cfg.Profile(name)
			switch key {
			case "account_id":
				p.AccountID = value
			case "api_token_env":
				p.APITokenEnv = value
			case "default_zone":
				p.DefaultZone = value
			}
			cfg.Set(name, p)
			if err := cfg.Save(); err != nil {
				return errors.Wrap(errors.CodeUnclassified, "saving configuration", err)
			}
			rt.Logger().Infof("set %s for profile %q in %s", key, name, cfg.Path())
			return nil
		},
	}
}

// newList shows the effective configuration of the active profile with
// sources. Token values are never printed: only presence and the resolved
// source variable.
func newList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the effective configuration of the active profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			p, _ := cfg.Profile(rt.ActiveProfileName())
			values := profileValues(&p)

			rows := make([]keyRow, 0, len(profile.ConfigKeys)+1)
			for _, k := range profile.ConfigKeys {
				src := "unset"
				if values[k] != "" {
					src = "config"
				}
				rows = append(rows, keyRow{Key: k, Value: values[k], Source: src})
			}
			if cred, ok := auth.Resolve(&p); ok {
				rows = append(rows, keyRow{Key: "api_token", Value: "[set]", Source: "env " + cred.Source})
			} else {
				rows = append(rows, keyRow{Key: "api_token", Value: "[unset]", Source: "none"})
			}

			if rt.Format() == output.Table {
				tbl := make([][]string, 0, len(rows))
				for _, r := range rows {
					tbl = append(tbl, []string{r.Key, r.Value, r.Source})
				}
				return rt.Printer().PrintTable([]string{"KEY", "VALUE", "SOURCE"}, tbl)
			}
			return rt.Printer().Emit(rows)
		},
	}
}
