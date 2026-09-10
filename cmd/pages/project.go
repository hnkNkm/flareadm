package pages

import (
	"encoding/json"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

func projectRow(p cloudflare.PagesProject) []string {
	return []string{p.Name, p.Subdomain, p.ProductionBranch, p.Framework, strconv.FormatBool(p.UsesFunctions), strconv.Itoa(len(p.Domains))}
}

func projectHeaders() []string {
	return []string{"NAME", "SUBDOMAIN", "PRODUCTION BRANCH", "FRAMEWORK", "FUNCTIONS", "DOMAINS"}
}

func newProjectGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Pages projects",
		Long:  "Pages projects (/accounts/{account_id}/pages/projects). Project domains and deployments are subresources.",
	}
	cmd.AddCommand(newProjectList(rt))
	cmd.AddCommand(newProjectGet(rt))
	cmd.AddCommand(newProjectCreate(rt))
	cmd.AddCommand(newProjectUpdate(rt))
	cmd.AddCommand(newProjectDelete(rt))
	cmd.AddCommand(newProjectDeploymentGroup(rt))
	cmd.AddCommand(newProjectDomainGroup(rt))
	return cmd
}

func newProjectList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Pages projects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListPagesProjects(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, projectHeaders(), projectRow)
		},
	}
}

func newProjectGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get PROJECT",
		Short: "Show one Pages project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetPagesProject(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, projectHeaders(), projectRow)
		},
	}
}

type projectFlagValues struct {
	rt            *app.Runtime
	Name          string
	Production    string
	BuildConfig   string
	DeployConfigs string
	Source        string
	Settings      string
}

func addProjectFlags(rt *app.Runtime, cmd *cobra.Command, f *projectFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "project name")
	cmd.Flags().StringVar(&f.Production, "production-branch", "", "production branch")
	cmd.Flags().StringVar(&f.BuildConfig, "build-config", "", "build configuration object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.DeployConfigs, "deployment-configs", "", "deployment configuration object as @file only (environment variables are credentials)")
	cmd.Flags().StringVar(&f.Source, "source", "", "source control configuration object as @file only (repo credentials)")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional project fields as a JSON object, inline or @file")
}

func (f *projectFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("production-branch") {
		body["production_branch"] = f.Production
	}
	if changed("build-config") {
		obj, err := cmdutil.ParseSecretCarryingObject(f.rt, "build-config", f.BuildConfig)
		if err != nil {
			return nil, err
		}
		body["build_config"] = obj
	}
	if changed("deployment-configs") {
		text, err := cmdutil.FileOnly("deployment-configs", f.DeployConfigs)
		if err != nil {
			return nil, err
		}
		obj, err := cmdutil.ParseJSONObjectText("deployment-configs", text)
		if err != nil {
			return nil, err
		}
		var decoded any
		if err := jsonUnmarshal(obj, &decoded); err == nil {
			cmdutil.ProtectEnvVarValues(f.rt, decoded)
		}
		body["deployment_configs"] = obj
	}
	if changed("source") {
		text, err := cmdutil.FileOnly("source", f.Source)
		if err != nil {
			return nil, err
		}
		obj, err := cmdutil.ParseSecretCarryingObject(f.rt, "source", text)
		if err != nil {
			return nil, err
		}
		body["source"] = obj
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

func newProjectCreate(rt *app.Runtime) *cobra.Command {
	var f projectFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --production-branch BRANCH",
		Short: "Create a Pages project",
		Long: "Create a Pages project.\n\n" +
			"Example:\n" +
			"  flareadm pages project create --name docs --production-branch main \\\n" +
			"    --build-config '{\"build_command\":\"npm run build\",\"destination_dir\":\"dist\"}'\n\n" +
			"--deployment-configs and --source are @file-only: deployment configurations\n" +
			"carry environment variable values and source configurations carry repository\n" +
			"credentials. Those values are registered as protected secrets and never appear\n" +
			"in diagnostics, error text or previews.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if f.Production == "" {
				return errors.Usage("--production-branch is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create Pages project "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreatePagesProject(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, projectHeaders(), projectRow)
		},
	}
	addProjectFlags(rt, cmd, &f)
	return cmd
}

func newProjectUpdate(rt *app.Runtime) *cobra.Command {
	var f projectFlagValues
	cmd := &cobra.Command{
		Use:   "update PROJECT",
		Short: "Update a Pages project",
		Long: "Update a Pages project. Provided fields are merged into the current project and\n" +
			"the result is PATCHed, so unmodeled build_config and deployment_configs fields\n" +
			"are preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one project flag or --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update Pages project "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdatePagesProject(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, projectHeaders(), projectRow)
		},
	}
	addProjectFlags(rt, cmd, &f)
	return cmd
}

func newProjectDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete PROJECT",
		Short: "Delete a Pages project",
		Long: "Delete a Pages project and its deployments. Destructive: prompts for\n" +
			"confirmation unless --yes is given; --dry-run previews the deletion without\n" +
			"confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete Pages project "+args[0])
			}
			if err := rt.Confirm("Delete Pages project " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeletePagesProject(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted Pages project %s", args[0])
			return nil
		},
	}
	return cmd
}
