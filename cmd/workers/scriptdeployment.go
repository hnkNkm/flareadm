package workers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func deploymentRow(d cloudflare.WorkerDeployment) []string {
	versions := make([]string, 0, len(d.Versions))
	for _, v := range d.Versions {
		versions = append(versions, v.VersionID+"@"+strconv.FormatFloat(v.Percentage, 'f', -1, 64)+"%")
	}
	return []string{d.ID, dateOnly(d.CreatedOn), d.Strategy, strings.Join(versions, ","), d.AuthorEmail}
}

func deploymentHeaders() []string {
	return []string{"ID", "CREATED", "STRATEGY", "VERSIONS", "AUTHOR"}
}

func newScriptDeploymentGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deployment",
		Short: "Script deployments",
		Long:  "Script deployments (/accounts/{account_id}/workers/scripts/{script}/deployments). A deployment assigns traffic percentages to immutable versions.",
	}
	cmd.AddCommand(newScriptDeploymentList(rt))
	cmd.AddCommand(newScriptDeploymentGet(rt))
	cmd.AddCommand(newScriptDeploymentCreate(rt))
	cmd.AddCommand(newScriptDeploymentDelete(rt))
	return cmd
}

func newScriptDeploymentList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list SCRIPT",
		Short: "List a script's deployments",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListWorkerDeployments(cmd.Context(), ref.ID, args[0], rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, deploymentHeaders(), deploymentRow)
		},
	}
}

func newScriptDeploymentGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get SCRIPT DEPLOYMENT_ID",
		Short: "Show one deployment",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerDeployment(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, deploymentHeaders(), deploymentRow)
		},
	}
}

// parseVersionShares turns --version VERSION_ID=PERCENTAGE into deployment parts.
func parseVersionShares(values []string) ([]map[string]any, error) {
	parts := make([]map[string]any, 0, len(values))
	for _, v := range values {
		id, percent, ok := strings.Cut(v, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			return nil, errors.Usage("--version must have the form VERSION_ID=PERCENTAGE (got %q)", v)
		}
		percentage, err := strconv.ParseFloat(strings.TrimSpace(percent), 64)
		if err != nil {
			return nil, errors.Usage("--version %s has an invalid percentage %q", id, percent)
		}
		parts = append(parts, map[string]any{"version_id": id, "percentage": percentage})
	}
	return parts, nil
}

func newScriptDeploymentCreate(rt *app.Runtime) *cobra.Command {
	var strategy, deploymentFlag, annotationsFlag string
	var versionFlags []string
	var force bool
	cmd := &cobra.Command{
		Use:   "create SCRIPT --version VERSION_ID=PERCENTAGE",
		Short: "Deploy script versions",
		Long: "Create a deployment. Either describe it with --strategy and repeated --version\n" +
			"flags, or pass a complete deployment object with --deployment @file.\n\n" +
			"Example:\n" +
			"  flareadm workers script deployment create hello --version <version-id>=100\n\n" +
			"The deployment takes effect immediately; --dry-run previews the plan without\n" +
			"deploying.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var deployment map[string]any
			if cmd.Flags().Changed("deployment") {
				raw, err := cmdutil.ParseSecretCarryingObject(rt, "deployment", deploymentFlag)
				if err != nil {
					return err
				}
				if err := jsonUnmarshal(raw, &deployment); err != nil {
					return errors.Usage("--deployment must be a JSON object")
				}
			} else {
				deployment = map[string]any{}
				if strategy != "" {
					deployment["strategy"] = strategy
				}
				versions, err := parseVersionShares(versionFlags)
				if err != nil {
					return err
				}
				if len(versions) == 0 {
					return errors.Usage("at least one --version VERSION_ID=PERCENTAGE is required (or pass --deployment @file)")
				}
				deployment["versions"] = versions
				if cmd.Flags().Changed("annotations") {
					annotations, err := cmdutil.ParseSecretCarryingObject(rt, "annotations", annotationsFlag)
					if err != nil {
						return err
					}
					deployment["annotations"] = annotations
				}
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, fmt.Sprintf("Would deploy script %s (%s)", args[0], deploymentPlan(deployment)))
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateWorkerDeployment(cmd.Context(), ref.ID, args[0], deployment, force)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, deploymentHeaders(), deploymentRow)
		},
	}
	cmd.Flags().StringVar(&strategy, "strategy", "", "deployment strategy (for example percentage)")
	cmd.Flags().StringArrayVar(&versionFlags, "version", nil, "version share as VERSION_ID=PERCENTAGE (repeatable)")
	cmd.Flags().StringVar(&annotationsFlag, "annotations", "", "deployment annotations as JSON, inline or @file")
	cmd.Flags().StringVar(&deploymentFlag, "deployment", "", "complete deployment object as JSON, inline or @file (wins over --strategy/--version)")
	cmd.Flags().BoolVar(&force, "force", false, "deploy even when normally blocked (for example when a secret changed)")
	return cmd
}

// deploymentPlan summarizes a deployment without dumping bindings.
func deploymentPlan(deployment map[string]any) string {
	versions, _ := deployment["versions"].([]map[string]any)
	if versions == nil {
		if raw, ok := deployment["versions"].([]any); ok {
			for _, item := range raw {
				if obj, ok := item.(map[string]any); ok {
					versions = append(versions, obj)
				}
			}
		}
	}
	parts := make([]string, 0, len(versions))
	for _, v := range versions {
		parts = append(parts, fmt.Sprintf("%v=%v%%", v["version_id"], v["percentage"]))
	}
	if len(parts) == 0 {
		return "custom deployment"
	}
	return strings.Join(parts, ", ")
}

func newScriptDeploymentDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete SCRIPT DEPLOYMENT_ID",
		Short: "Delete a deployment",
		Long: "Delete a deployment. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete deployment "+args[1]+" of script "+args[0])
			}
			if err := rt.Confirm("Delete deployment " + args[1] + " of script " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeleteWorkerDeployment(cmd.Context(), ref.ID, args[0], args[1]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted deployment %s", args[1])
			return nil
		},
	}
	return cmd
}
