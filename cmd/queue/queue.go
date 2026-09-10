// Package queue implements `flareadm queue ...`: Cloudflare Queues
// administration (queues, consumers, messages and purge jobs).
package queue

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// New builds the queue command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "queue",
		Short: "Queues administration",
		Long:  "Cloudflare Queues administration. Account scope is resolved through the standard account resolution.",
	}
	cmd.AddCommand(newQueueList(rt))
	cmd.AddCommand(newQueueGet(rt))
	cmd.AddCommand(newQueueCreate(rt))
	cmd.AddCommand(newQueueUpdate(rt))
	cmd.AddCommand(newQueueDelete(rt))
	cmd.AddCommand(newQueueMetrics(rt))
	cmd.AddCommand(newConsumerGroup(rt))
	cmd.AddCommand(newMessageGroup(rt))
	cmd.AddCommand(newPurgeGroup(rt))
	return cmd
}

func queueRow(q cloudflare.Queue) []string {
	delay, retention, paused := "", "", ""
	if q.Settings != nil {
		delay = strconv.FormatFloat(q.Settings.DeliveryDelay, 'f', 0, 64)
		retention = strconv.FormatFloat(q.Settings.MessageRetentionPeriod, 'f', 0, 64)
		paused = fmt.Sprintf("%t", q.Settings.DeliveryPaused)
	}
	return []string{q.QueueName, q.QueueID, delay, retention, paused}
}

func previewLine(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": rt.Redact(line)})
}

func newQueueList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List queues",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListQueues(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"NAME", "QUEUE ID", "DELAY (S)", "RETENTION (S)", "PAUSED"}, queueRow)
		},
	}
}

func newQueueGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get QUEUE_ID",
		Short: "Show one queue",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetQueue(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"NAME", "QUEUE ID", "DELAY (S)", "RETENTION (S)", "PAUSED"}, queueRow)
		},
	}
}

func newQueueCreate(rt *app.Runtime) *cobra.Command {
	var nameFlag string
	cmd := &cobra.Command{
		Use:   "create --name NAME",
		Short: "Create a queue",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nameFlag == "" {
				return errors.Usage("--name is required")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create queue "+nameFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateQueue(cmd.Context(), ref.ID, nameFlag)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"NAME", "QUEUE ID", "DELAY (S)", "RETENTION (S)", "PAUSED"}, queueRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "queue name (required)")
	return cmd
}

func newQueueUpdate(rt *app.Runtime) *cobra.Command {
	var delayFlag, retentionFlag int64
	var pausedFlag bool
	cmd := &cobra.Command{
		Use:   "update QUEUE_ID",
		Short: "Update queue settings",
		Long: "Update queue delivery settings. Omitted settings keep their values.\n" +
			"Use --delivery-paused=false to resume delivery.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			up := cloudflare.QueueUpdate{}
			if cmd.Flags().Changed("delivery-delay") {
				v := float64(delayFlag)
				up.DeliveryDelay = &v
			}
			if cmd.Flags().Changed("message-retention-period") {
				v := float64(retentionFlag)
				up.MessageRetentionPeriod = &v
			}
			if cmd.Flags().Changed("delivery-paused") {
				v := pausedFlag
				up.DeliveryPaused = &v
			}
			if up.DeliveryDelay == nil && up.MessageRetentionPeriod == nil && up.DeliveryPaused == nil {
				return errors.Usage("nothing to update; pass at least one of --delivery-delay, --message-retention-period, --delivery-paused")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update queue "+args[0])
			}
			res, err := client.UpdateQueue(cmd.Context(), ref.ID, args[0], up)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"NAME", "QUEUE ID", "DELAY (S)", "RETENTION (S)", "PAUSED"}, queueRow)
		},
	}
	cmd.Flags().Int64Var(&delayFlag, "delivery-delay", 0, "delivery delay in seconds")
	cmd.Flags().Int64Var(&retentionFlag, "message-retention-period", 0, "message retention period in seconds")
	cmd.Flags().BoolVar(&pausedFlag, "delivery-paused", false, "pause (true) or resume (false) delivery")
	return cmd
}

func newQueueDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete QUEUE_ID",
		Short: "Delete a queue",
		Long: "Delete a queue. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetQueue(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete queue "+existing.Item.QueueName)
			}
			if err := rt.Confirm("Delete queue " + existing.Item.QueueName + "?"); err != nil {
				return err
			}
			if err := client.DeleteQueue(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted queue %s", args[0])
			return nil
		},
	}
	return cmd
}

func newQueueMetrics(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "metrics QUEUE_ID",
		Short: "Show queue backlog metrics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.QueueMetricsGet(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			row := func(m cloudflare.QueueMetrics) []string {
				return []string{
					strconv.FormatFloat(m.BacklogBytes, 'f', 0, 64),
					strconv.FormatFloat(m.BacklogCount, 'f', 0, 64),
					strconv.FormatFloat(m.OldestMessageTimestampMs, 'f', 0, 64),
				}
			}
			return app.RenderGet(rt, res, []string{"BACKLOG BYTES", "BACKLOG COUNT", "OLDEST MESSAGE (MS)"}, row)
		},
	}
}
