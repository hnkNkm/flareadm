package pages

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
)

func deploymentRow(d cloudflare.PagesDeployment) []string {
	return []string{d.ID, d.ShortID, d.Environment, d.URL, dateOnly(d.CreatedOn), stageName(d.LatestStage)}
}

func deploymentHeaders() []string {
	return []string{"ID", "SHORT ID", "ENVIRONMENT", "URL", "CREATED", "STATUS"}
}

// stageName extracts the name of the latest build stage.
func stageName(bytes json.RawMessage) string {
	if len(bytes) == 0 {
		return ""
	}
	var stage struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := jsonUnmarshal(bytes, &stage); err != nil {
		return ""
	}
	if stage.Name == "" {
		return stage.Status
	}
	if stage.Status == "" {
		return stage.Name
	}
	return fmt.Sprintf("%s (%s)", stage.Name, stage.Status)
}

func newProjectDeploymentGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deployment",
		Short: "Pages deployments",
		Long:  "Deployments of a Pages project (/accounts/{account_id}/pages/projects/{project}/deployments). Creating a deployment requires the direct-upload manifest and asset upload session, which this CLI does not model; retry and rollback use verbs outside the documented command vocabulary.",
	}
	cmd.AddCommand(newProjectDeploymentList(rt))
	cmd.AddCommand(newProjectDeploymentGet(rt))
	cmd.AddCommand(newProjectDeploymentDelete(rt))
	return cmd
}

func newProjectDeploymentList(rt *app.Runtime) *cobra.Command {
	var environment string
	cmd := &cobra.Command{
		Use:   "list PROJECT",
		Short: "List a project's deployments",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListPagesDeployments(cmd.Context(), ref.ID, args[0], cloudflare.PagesDeploymentQuery{Environment: environment}, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, deploymentHeaders(), deploymentRow)
		},
	}
	cmd.Flags().StringVar(&environment, "env", "", "only deployments of this environment (production, preview)")
	return cmd
}

func newProjectDeploymentGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get PROJECT DEPLOYMENT_ID",
		Short: "Show one deployment",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetPagesDeployment(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, deploymentHeaders(), deploymentRow)
		},
	}
}

func newProjectDeploymentDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete PROJECT DEPLOYMENT_ID",
		Short: "Delete a deployment",
		Long: "Delete a deployment. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete Pages deployment "+args[1]+" of project "+args[0])
			}
			if err := rt.Confirm("Delete Pages deployment " + args[1] + " of project " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeletePagesDeployment(cmd.Context(), ref.ID, args[0], args[1]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted Pages deployment %s", args[1])
			return nil
		},
	}
	return cmd
}
