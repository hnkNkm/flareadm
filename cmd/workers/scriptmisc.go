package workers

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
)

func newScriptScheduleGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Script cron schedule",
		Long:  "Cron triggers of a script (/accounts/{account_id}/workers/scripts/{script}/schedules).",
	}
	cmd.AddCommand(newScriptScheduleGet(rt))
	cmd.AddCommand(newScriptScheduleUpdate(rt))
	return cmd
}

func newScriptScheduleGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get SCRIPT",
		Short: "Show a script's cron schedule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerSchedule(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"CRON"}, func(s cloudflare.WorkerSchedule) []string {
				return []string{strings.Join(s.Crons, "; ")}
			})
		},
	}
}

func newScriptScheduleUpdate(rt *app.Runtime) *cobra.Command {
	var crons []string
	cmd := &cobra.Command{
		Use:   "update SCRIPT --cron 'EXPRESSION'",
		Short: "Replace a script's cron schedule",
		Long: "Replace the cron triggers of a script. Passing no --cron clears the schedule.\n\n" +
			"Example:\n" +
			"  flareadm workers script schedule update nightly --cron '0 3 * * *'",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				if len(crons) == 0 {
					return cmdutil.PreviewLine(rt, "Would clear the cron schedule of script "+args[0])
				}
				return cmdutil.PreviewLine(rt, "Would set the cron schedule of script "+args[0]+" ("+strings.Join(crons, "; ")+")")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateWorkerSchedule(cmd.Context(), ref.ID, args[0], crons)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"CRON"}, func(s cloudflare.WorkerSchedule) []string {
				return []string{strings.Join(s.Crons, "; ")}
			})
		},
	}
	cmd.Flags().StringArrayVar(&crons, "cron", nil, "cron expression (repeatable; omit to clear the schedule)")
	return cmd
}

func scriptSubdomainRow(s cloudflare.WorkerScriptSubdomain) []string {
	return []string{boolString(s.Enabled), boolString(s.PreviewsEnabled)}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func newScriptSubdomainGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Script workers.dev subdomain",
		Long:  "workers.dev availability of a script (/accounts/{account_id}/workers/scripts/{script}/subdomain).",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get SCRIPT",
		Short: "Show workers.dev state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerScriptSubdomain(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ENABLED", "PREVIEWS ENABLED"}, scriptSubdomainRow)
		},
	})
	cmd.AddCommand(newScriptSubdomainEnable(rt))
	cmd.AddCommand(newScriptSubdomainDisable(rt))
	return cmd
}

func newScriptSubdomainEnable(rt *app.Runtime) *cobra.Command {
	var previews bool
	cmd := &cobra.Command{
		Use:   "enable SCRIPT",
		Short: "Enable workers.dev for a script",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would enable workers.dev for script "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.EnableWorkerScriptSubdomain(cmd.Context(), ref.ID, args[0], previews)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ENABLED", "PREVIEWS ENABLED"}, scriptSubdomainRow)
		},
	}
	cmd.Flags().BoolVar(&previews, "previews", false, "also enable preview URLs")
	return cmd
}

func newScriptSubdomainDisable(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable SCRIPT",
		Short: "Disable workers.dev for a script",
		Long: "Disable the workers.dev route of a script. Prompts for confirmation unless\n" +
			"--yes is given; --dry-run previews the change without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would disable workers.dev for script "+args[0])
			}
			if err := rt.Confirm("Disable workers.dev for script " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.DisableWorkerScriptSubdomain(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ENABLED", "PREVIEWS ENABLED"}, scriptSubdomainRow)
		},
	}
	return cmd
}
