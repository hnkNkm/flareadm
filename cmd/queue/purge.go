package queue

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
)

func newPurgeGroup(rt *app.Runtime) *cobra.Command {
	var permanentFlag bool
	cmd := &cobra.Command{
		Use:   "purge [QUEUE_ID]",
		Short: "Queue purge jobs",
		Long: "Start a queue purge (`queue purge QUEUE_ID`) or inspect the current purge job\n" +
			"(`queue purge get QUEUE_ID`). Purging is destructive: it prompts for\n" +
			"confirmation unless --yes is given; --dry-run previews the purge without\n" +
			"confirming. --permanent deletes messages permanently.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			queueID := args[0]
			if rt.DryRunFlag {
				return previewLine(rt, "Would purge queue "+queueID)
			}
			if err := rt.Confirm("Purge queue " + queueID + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.StartQueuePurge(cmd.Context(), ref.ID, queueID, permanentFlag)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"NAME", "QUEUE ID", "DELAY (S)", "RETENTION (S)", "PAUSED"}, queueRow)
		},
	}
	cmd.Flags().BoolVar(&permanentFlag, "permanent", false, "delete messages permanently")
	cmd.AddCommand(newPurgeGet(rt))
	return cmd
}

func newPurgeGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get QUEUE_ID",
		Short: "Show the queue purge job status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.QueuePurgeStatusGet(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			row := func(s cloudflare.QueuePurgeStatus) []string { return []string{s.Completed, s.StartedAt} }
			return app.RenderGet(rt, res, []string{"COMPLETED", "STARTED AT"}, row)
		},
	}
}
