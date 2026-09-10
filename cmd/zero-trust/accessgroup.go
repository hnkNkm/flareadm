package zerotrust

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func accessGroupRow(g cloudflare.AccessGroup) []string {
	return []string{g.ID, g.Name, compactJSON(g.Include), compactJSON(g.Require), scalarString(g.IsDefault)}
}

func accessGroupHeaders() []string {
	return []string{"ID", "NAME", "INCLUDE", "REQUIRE", "DEFAULT"}
}

type groupFlagValues struct {
	rt       *app.Runtime
	Name     string
	Include  string
	Exclude  string
	Require  string
	Settings string
	IsDeflt  bool
}

func addGroupFlags(rt *app.Runtime, cmd *cobra.Command, f *groupFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "group name (required on create)")
	cmd.Flags().StringVar(&f.Include, "include", "", "include rules as a JSON array (required on create), inline or @file")
	cmd.Flags().StringVar(&f.Exclude, "exclude", "", "exclude rules as a JSON array, inline or @file")
	cmd.Flags().StringVar(&f.Require, "require", "", "require rules as a JSON array, inline or @file")
	cmd.Flags().BoolVar(&f.IsDeflt, "is-default", false, "make the group the account default")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional group fields as a JSON object, inline or @file")
}

func (f *groupFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	for _, item := range []struct {
		flag  string
		value string
		key   string
	}{
		{"include", f.Include, "include"},
		{"exclude", f.Exclude, "exclude"},
		{"require", f.Require, "require"},
	} {
		if !changed(item.flag) {
			continue
		}
		arr, err := parseJSONArrayList(item.flag, item.value)
		if err != nil {
			return nil, err
		}
		body[item.key] = arr
	}
	if changed("is-default") {
		body["is_default"] = f.IsDeflt
	}
	if changed("settings") {
		extra, err := parseSecretCarryingSettings(f.rt, "settings", f.Settings)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			body[k] = v
		}
	}
	return body, nil
}

func newAccessGroupGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Access groups",
		Long:  "Access groups (/accounts/{account_id}/access/groups).",
	}
	cmd.AddCommand(newAccessGroupList(rt))
	cmd.AddCommand(newAccessGroupGet(rt))
	cmd.AddCommand(newAccessGroupCreate(rt))
	cmd.AddCommand(newAccessGroupUpdate(rt))
	cmd.AddCommand(newAccessGroupDelete(rt))
	return cmd
}

func newAccessGroupList(rt *app.Runtime) *cobra.Command {
	var f cloudflare.AccessGroupQuery
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Access groups",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAccessGroups(cmd.Context(), ref.ID, f, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, accessGroupHeaders(), accessGroupRow)
		},
	}
	cmd.Flags().StringVar(&f.Name, "name", "", "only groups with this exact name")
	cmd.Flags().StringVar(&f.Search, "search", "", "search groups by name")
	return cmd
}

func newAccessGroupGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get GROUP_ID",
		Short: "Show one Access group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetAccessGroup(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accessGroupHeaders(), accessGroupRow)
		},
	}
}

func newAccessGroupCreate(rt *app.Runtime) *cobra.Command {
	var f groupFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --include @rules.json",
		Short: "Create an Access group",
		Long: "Create an Access group.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust access group create --name contractors \\\n" +
			"    --include @include.json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if !cmd.Flags().Changed("include") {
				return errors.Usage("--include is required (JSON array of rules)")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create access group "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateAccessGroup(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accessGroupHeaders(), accessGroupRow)
		},
	}
	addGroupFlags(rt, cmd, &f)
	return cmd
}

func newAccessGroupUpdate(rt *app.Runtime) *cobra.Command {
	var f groupFlagValues
	cmd := &cobra.Command{
		Use:   "update GROUP_ID",
		Short: "Update an Access group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one group flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update access group "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateAccessGroup(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accessGroupHeaders(), accessGroupRow)
		},
	}
	addGroupFlags(rt, cmd, &f)
	return cmd
}

func newAccessGroupDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete GROUP_ID",
		Short: "Delete an Access group",
		Long: "Delete an Access group. Destructive: prompts for confirmation unless --yes\n" +
			"is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetAccessGroup(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete access group "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete access group " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteAccessGroup(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted access group %s", args[0])
			return nil
		},
	}
	return cmd
}
