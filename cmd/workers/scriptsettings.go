package workers

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// cloudflareScriptSettings aliases the adapter model for the row helpers.
type cloudflareScriptSettings = cloudflare.WorkerScriptSettings

// rawToAny decodes a raw JSON value for credential scanning.
func rawToAny(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

type settingsFlagValues struct {
	rt                 *app.Runtime
	CompatibilityDate  string
	CompatibilityFlags string
	UsageModel         string
	Tags               string
	Bindings           string
	Annotations        string
	CacheOptions       string
	Limits             string
	Observability      string
	Placement          string
	TailConsumers      string
	Settings           string
	Logpush            bool
}

func addSettingsFlags(rt *app.Runtime, cmd *cobra.Command, f *settingsFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.CompatibilityDate, "compatibility-date", "", "compatibility date (for example 2026-01-01)")
	cmd.Flags().StringVar(&f.CompatibilityFlags, "compatibility-flags", "", "comma-separated compatibility flags")
	cmd.Flags().StringVar(&f.UsageModel, "usage-model", "", "usage model (standard, bundled, unbound)")
	cmd.Flags().BoolVar(&f.Logpush, "logpush", false, "enable Logpush for the script")
	cmd.Flags().StringVar(&f.Tags, "tags", "", "comma-separated tags")
	cmd.Flags().StringVar(&f.Bindings, "bindings", "", "bindings array as @file only (secret_text and plain_text values are treated as credentials)")
	cmd.Flags().StringVar(&f.Annotations, "annotations", "", "annotations object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.CacheOptions, "cache-options", "", "cache options object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Limits, "limits", "", "limits object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Observability, "observability", "", "observability object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Placement, "placement", "", "placement object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.TailConsumers, "tail-consumers", "", "tail consumers array as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional settings as a JSON object, inline or @file")
}

func (f *settingsFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("compatibility-date") {
		body["compatibility_date"] = f.CompatibilityDate
	}
	if changed("compatibility-flags") {
		body["compatibility_flags"] = cmdutil.SplitList(f.CompatibilityFlags)
	}
	if changed("usage-model") {
		body["usage_model"] = f.UsageModel
	}
	if changed("logpush") {
		body["logpush"] = f.Logpush
	}
	if changed("tags") {
		body["tags"] = cmdutil.SplitList(f.Tags)
	}
	if changed("bindings") {
		text, err := cmdutil.FileOnly("bindings", f.Bindings)
		if err != nil {
			return nil, err
		}
		arr, err := cmdutil.ParseSecretCarryingBindings(f.rt, "bindings", text)
		if err != nil {
			return nil, err
		}
		body["bindings"] = arr
	}
	for _, item := range []struct {
		flag  string
		value string
		key   string
	}{
		{"annotations", f.Annotations, "annotations"},
		{"cache-options", f.CacheOptions, "cache_options"},
		{"limits", f.Limits, "limits"},
		{"observability", f.Observability, "observability"},
		{"placement", f.Placement, "placement"},
	} {
		if !changed(item.flag) {
			continue
		}
		obj, err := cmdutil.ParseSecretCarryingObject(f.rt, item.flag, item.value)
		if err != nil {
			return nil, err
		}
		body[item.key] = obj
	}
	if changed("tail-consumers") {
		arr, err := cmdutil.ParseJSONArrayList("tail-consumers", f.TailConsumers)
		if err != nil {
			return nil, err
		}
		body["tail_consumers"] = arr
	}
	if changed("settings") {
		extra, err := cmdutil.ParseSecretCarryingSettings(f.rt, "settings", f.Settings)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			body[k] = v
		}
	}
	return body, nil
}

func newScriptSettingsGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings",
		Short: "Script settings and bindings",
		Long:  "Script settings (/accounts/{account_id}/workers/scripts/{script}/settings): bindings, compatibility date and flags, limits, observability, tags, placement and tail consumers. Updates are merged into the current settings, so unmodeled fields survive.",
	}
	cmd.AddCommand(newScriptSettingsGet(rt))
	cmd.AddCommand(newScriptSettingsUpdate(rt))
	return cmd
}

func newScriptSettingsGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get SCRIPT",
		Short: "Show a script's settings",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerScriptSettings(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			// Bindings the API returns are registered before rendering so they
			// cannot leak into later diagnostics of this run.
			if len(res.Item.Bindings) > 0 {
				cmdutil.ProtectBindingValues(rt, rawToAny(res.Item.Bindings))
			}
			return app.RenderGet(rt, res, []string{"COMPAT DATE", "USAGE MODEL", "TAGS", "BINDINGS"}, func(s cloudflareScriptSettings) []string {
				return []string{s.CompatibilityDate, s.UsageModel, joinList(s.Tags), cmdutil.CompactJSON(s.Bindings)}
			})
		},
	}
}

func newScriptSettingsUpdate(rt *app.Runtime) *cobra.Command {
	var f settingsFlagValues
	cmd := &cobra.Command{
		Use:   "update SCRIPT",
		Short: "Update a script's settings",
		Long: "Update script settings. Provided fields are merged into the current settings\n" +
			"and the result is PATCHed, so fields this CLI does not model are preserved.\n\n" +
			"--bindings is @file-only because bindings carry credentials (secret_text and\n" +
			"plain_text values are registered as protected secrets).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one settings flag or --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update settings of script "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateWorkerScriptSettings(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"COMPAT DATE", "USAGE MODEL", "TAGS", "BINDINGS"}, func(s cloudflareScriptSettings) []string {
				return []string{s.CompatibilityDate, s.UsageModel, joinList(s.Tags), cmdutil.CompactJSON(s.Bindings)}
			})
		},
	}
	addSettingsFlags(rt, cmd, &f)
	return cmd
}
