package queue

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func consumerRow(c cloudflare.QueueConsumer) []string {
	return []string{c.ConsumerID, c.Type, c.ScriptName, c.DeadLetterQueue}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func newConsumerGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "consumer",
		Short: "Queue consumers",
	}
	cmd.AddCommand(newConsumerList(rt))
	cmd.AddCommand(newConsumerGet(rt))
	cmd.AddCommand(newConsumerCreate(rt))
	cmd.AddCommand(newConsumerUpdate(rt))
	cmd.AddCommand(newConsumerDelete(rt))
	return cmd
}

func newConsumerList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list QUEUE_ID",
		Short: "List consumers of a queue",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListConsumers(cmd.Context(), ref.ID, args[0], rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"CONSUMER ID", "TYPE", "SCRIPT", "DEAD LETTER QUEUE"}, consumerRow)
		},
	}
}

func newConsumerGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get QUEUE_ID CONSUMER_ID",
		Short: "Show one consumer",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetConsumer(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"CONSUMER ID", "TYPE", "SCRIPT", "DEAD LETTER QUEUE"}, consumerRow)
		},
	}
}

// consumerFlags are the shared consumer create/update flags.
type consumerFlags struct {
	typ, script, deadLetter, settings string
}

func addConsumerFlags(cmd *cobra.Command, cf *consumerFlags) {
	cmd.Flags().StringVar(&cf.typ, "type", "", "consumer type (worker, http_pull)")
	cmd.Flags().StringVar(&cf.script, "script", "", "Worker script name (worker consumers)")
	cmd.Flags().StringVar(&cf.deadLetter, "dead-letter-queue", "", "dead letter queue name")
	cmd.Flags().StringVar(&cf.settings, "settings", "", "consumer settings as a JSON object, inline or @file (for example batch_size, max_batch_timeout, max_retries)")
}

func (cf *consumerFlags) params(cmd *cobra.Command) (cloudflare.QueueConsumerParams, error) {
	p := cloudflare.QueueConsumerParams{}
	if cmd.Flags().Changed("type") {
		if !contains(cloudflare.QueueConsumerTypes, cf.typ) {
			return p, errors.Usage("invalid --type %q (supported: %s)", cf.typ, strings.Join(cloudflare.QueueConsumerTypes, ", "))
		}
		p.Type = cf.typ
	}
	if cmd.Flags().Changed("script") {
		p.ScriptName = cf.script
	}
	if cmd.Flags().Changed("dead-letter-queue") {
		p.DeadLetterQueue = cf.deadLetter
	}
	if cmd.Flags().Changed("settings") {
		parsed, err := cmdutil.ParseJSONObject("settings", cf.settings)
		if err != nil {
			return p, err
		}
		p.Settings = parsed
	}
	return p, nil
}

func newConsumerCreate(rt *app.Runtime) *cobra.Command {
	var cf consumerFlags
	cmd := &cobra.Command{
		Use:   "create QUEUE_ID",
		Short: "Create a consumer",
		Long: "Create a queue consumer.\n\n" +
			"Examples:\n" +
			"  flareadm queue consumer create <queue-id> --type worker --script my-worker\n" +
			"  flareadm queue consumer create <queue-id> --type http_pull --settings '{\"batch_size\":10}'",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := cf.params(cmd)
			if err != nil {
				return err
			}
			if p.Type == "" {
				return errors.Usage("--type is required (worker, http_pull)")
			}
			if p.Type == "worker" && p.ScriptName == "" {
				return errors.Usage("--script is required for worker consumers")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create "+p.Type+" consumer on queue "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateConsumer(cmd.Context(), ref.ID, args[0], p)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"CONSUMER ID", "TYPE", "SCRIPT", "DEAD LETTER QUEUE"}, consumerRow)
		},
	}
	addConsumerFlags(cmd, &cf)
	return cmd
}

func newConsumerUpdate(rt *app.Runtime) *cobra.Command {
	var cf consumerFlags
	cmd := &cobra.Command{
		Use:   "update QUEUE_ID CONSUMER_ID",
		Short: "Update a consumer",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := cf.params(cmd)
			if err != nil {
				return err
			}
			changed := cmd.Flags().Changed("type") || cmd.Flags().Changed("script") ||
				cmd.Flags().Changed("dead-letter-queue") || cmd.Flags().Changed("settings")
			if !changed {
				return errors.Usage("nothing to update; pass at least one of --type, --script, --dead-letter-queue, --settings")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update consumer "+args[1]+" of queue "+args[0])
			}
			res, err := client.UpdateConsumer(cmd.Context(), ref.ID, args[0], args[1], p)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"CONSUMER ID", "TYPE", "SCRIPT", "DEAD LETTER QUEUE"}, consumerRow)
		},
	}
	addConsumerFlags(cmd, &cf)
	return cmd
}

func newConsumerDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete QUEUE_ID CONSUMER_ID",
		Short: "Delete a consumer",
		Long: "Delete a queue consumer. Destructive: prompts for confirmation unless\n" +
			"--yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetConsumer(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete consumer "+existing.Item.ConsumerID+" from queue "+args[0])
			}
			if err := rt.Confirm("Delete consumer " + existing.Item.ConsumerID + "?"); err != nil {
				return err
			}
			if err := client.DeleteConsumer(cmd.Context(), ref.ID, args[0], args[1]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted consumer %s", args[1])
			return nil
		},
	}
	return cmd
}
