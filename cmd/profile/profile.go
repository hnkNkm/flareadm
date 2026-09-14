// Package profile implements `flareadm profile list|get|create|update|delete`.
//
// These commands manage named profiles in the local configuration file.
// They are local-only and never touch the network. delete is destructive:
// it confirms interactively (or with --yes) and supports --dry-run.
package profile

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/config"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// profileData is the normalized shape of one profile in machine output.
type profileData struct {
	Name          string `json:"name" yaml:"name"`
	AccountID     string `json:"account_id,omitempty" yaml:"account_id,omitempty"`
	APITokenEnv   string `json:"api_token_env,omitempty" yaml:"api_token_env,omitempty"`
	DefaultZone   string `json:"default_zone,omitempty" yaml:"default_zone,omitempty"`
	OAuthClientID string `json:"oauth_client_id,omitempty" yaml:"oauth_client_id,omitempty"`
}

func fromProfile(name string, p config.Profile) profileData {
	return profileData{
		Name: name, AccountID: p.AccountID, APITokenEnv: p.APITokenEnv,
		DefaultZone: p.DefaultZone, OAuthClientID: p.OAuthClientID,
	}
}

// New builds the profile command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage configuration profiles",
		Long:  "Manage named profiles in the local FlareADM configuration file.",
	}
	cmd.AddCommand(
		newList(rt),
		newGet(rt),
		newCreate(rt),
		newUpdate(rt),
		newDelete(rt),
	)
	return cmd
}

func load(rt *app.Runtime) (*config.Config, error) { return rt.Config() }

// profileFlags are the shared create/update options.
type profileFlags struct {
	accountID     string
	apiTokenEnv   string
	defaultZone   string
	oauthClientID string
}

func addProfileFlags(cmd *cobra.Command, pf *profileFlags) {
	cmd.Flags().StringVar(&pf.accountID, "account-id", "", "account id for the profile")
	cmd.Flags().StringVar(&pf.apiTokenEnv, "api-token-env", "", "name of the environment variable holding the API token")
	cmd.Flags().StringVar(&pf.defaultZone, "default-zone", "", "default zone name or id for the profile")
	cmd.Flags().StringVar(&pf.oauthClientID, "oauth-client-id", "", "OAuth client id used by 'auth login'")
}

func (pf profileFlags) apply(p *config.Profile) {
	if pf.accountID != "" {
		p.AccountID = pf.accountID
	}
	if pf.apiTokenEnv != "" {
		p.APITokenEnv = pf.apiTokenEnv
	}
	if pf.defaultZone != "" {
		p.DefaultZone = pf.defaultZone
	}
	if pf.oauthClientID != "" {
		p.OAuthClientID = pf.oauthClientID
	}
}

// changed reports whether any flag was explicitly set.
func (pf profileFlags) changed(cmd *cobra.Command) bool {
	for _, name := range []string{"account-id", "api-token-env", "default-zone", "oauth-client-id"} {
		if cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

// newList lists profile names.
func newList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load(rt)
			if err != nil {
				return err
			}
			active := rt.ActiveProfileName()
			if rt.Format() == output.Table {
				rows := make([][]string, 0, len(cfg.Names()))
				for _, name := range cfg.Names() {
					marker := ""
					if name == active {
						marker = "*"
					}
					rows = append(rows, []string{name, marker})
				}
				return rt.Printer().PrintTable([]string{"NAME", "ACTIVE"}, rows)
			}
			data := make([]profileData, 0, len(cfg.Names()))
			for _, name := range cfg.Names() {
				p, _ := cfg.Profile(name)
				data = append(data, fromProfile(name, p))
			}
			return rt.Printer().Emit(data)
		},
	}
}

// newGet shows one profile's settings.
func newGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get [NAME]",
		Short: "Show one profile's settings",
		Long:  "Show the settings of NAME (default: the active profile).",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load(rt)
			if err != nil {
				return err
			}
			name := rt.ActiveProfileName()
			if len(args) == 1 {
				name = args[0]
			}
			p, ok := cfg.Profile(name)
			if !ok {
				return errors.New(errors.CodeNotFound, "profile %q does not exist", name)
			}
			row := fromProfile(name, p)
			if rt.Format() == output.Table {
				rows := [][]string{
					{"account_id", p.AccountID},
					{"api_token_env", p.APITokenEnv},
					{"default_zone", p.DefaultZone},
					{"oauth_client_id", p.OAuthClientID},
				}
				return rt.Printer().PrintTable([]string{"KEY", "VALUE"}, rows)
			}
			return rt.Printer().Emit(row)
		},
	}
}

// newCreate adds a profile.
func newCreate(rt *app.Runtime) *cobra.Command {
	var pf profileFlags
	cmd := &cobra.Command{
		Use:   "create NAME",
		Short: "Create a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if strings.TrimSpace(name) == "" {
				return errors.Usage("profile name must not be empty")
			}
			cfg, err := load(rt)
			if err != nil {
				return err
			}
			if _, exists := cfg.Profile(name); exists {
				return errors.New(errors.CodeConflict, "profile %q already exists", name)
			}
			p := config.Profile{}
			pf.apply(&p)
			cfg.Set(name, p)
			if err := cfg.Save(); err != nil {
				return errors.Wrap(errors.CodeUnclassified, "saving configuration", err)
			}
			rt.Logger().Infof("created profile %q in %s", name, cfg.Path())
			return nil
		},
	}
	addProfileFlags(cmd, &pf)
	_ = cmd.RegisterFlagCompletionFunc("default-zone", cmdutil.Zones(rt))
	return cmd
}

// newUpdate modifies an existing profile.
func newUpdate(rt *app.Runtime) *cobra.Command {
	var pf profileFlags
	cmd := &cobra.Command{
		Use:   "update NAME",
		Short: "Update a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := load(rt)
			if err != nil {
				return err
			}
			p, ok := cfg.Profile(name)
			if !ok {
				return errors.New(errors.CodeNotFound, "profile %q does not exist", name)
			}
			if !pf.changed(cmd) {
				return errors.Usage("nothing to update; pass at least one of --account-id, --api-token-env, --default-zone, --oauth-client-id")
			}
			pf.apply(&p)
			cfg.Set(name, p)
			if err := cfg.Save(); err != nil {
				return errors.Wrap(errors.CodeUnclassified, "saving configuration", err)
			}
			rt.Logger().Infof("updated profile %q in %s", name, cfg.Path())
			return nil
		},
	}
	addProfileFlags(cmd, &pf)
	_ = cmd.RegisterFlagCompletionFunc("default-zone", cmdutil.Zones(rt))
	return cmd
}

// newDelete removes a profile after confirmation.
func newDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete NAME",
		Short: "Delete a profile",
		Long: "Delete a profile from the configuration file. Destructive: prompts for\n" +
			"confirmation unless --yes is given; --dry-run previews the deletion.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := load(rt)
			if err != nil {
				return err
			}
			p, ok := cfg.Profile(name)
			if !ok {
				return errors.New(errors.CodeNotFound, "profile %q does not exist", name)
			}

			preview := fmt.Sprintf("Would delete profile %q (%s)", name, describe(p))
			if rt.DryRunFlag {
				if rt.Format() == output.Table {
					_, _ = fmt.Fprintln(rt.Out, preview)
					return nil
				}
				return rt.Printer().Emit(fromProfile(name, p))
			}

			if err := rt.Confirm(fmt.Sprintf("Delete profile %q?", name)); err != nil {
				return err
			}
			cfg.Delete(name)
			if err := cfg.Save(); err != nil {
				return errors.Wrap(errors.CodeUnclassified, "saving configuration", err)
			}
			rt.Logger().Infof("deleted profile %q from %s", name, cfg.Path())
			return nil
		},
	}
	return cmd
}

func describe(p config.Profile) string {
	parts := []string{}
	if p.AccountID != "" {
		parts = append(parts, "account_id="+p.AccountID)
	}
	if p.APITokenEnv != "" {
		parts = append(parts, "api_token_env="+p.APITokenEnv)
	}
	if p.DefaultZone != "" {
		parts = append(parts, "default_zone="+p.DefaultZone)
	}
	if p.OAuthClientID != "" {
		parts = append(parts, "oauth_client_id="+p.OAuthClientID)
	}
	if len(parts) == 0 {
		return "no settings"
	}
	return strings.Join(parts, ", ")
}
