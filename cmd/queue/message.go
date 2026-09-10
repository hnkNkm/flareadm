package queue

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

const bodyLimit = 60

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func messageRow(m cloudflare.QueueMessage) []string {
	return []string{m.ID, strconv.FormatFloat(m.Attempts, 'f', 0, 64), strconv.FormatFloat(m.TimestampMs, 'f', 0, 64), truncate(m.Body, bodyLimit), m.LeaseID}
}

func messageHeaders() []string {
	return []string{"ID", "ATTEMPTS", "TIMESTAMP (MS)", "BODY", "LEASE ID"}
}

func newMessageGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "message",
		Short: "Queue messages",
	}
	cmd.AddCommand(newMessagePush(rt))
	cmd.AddCommand(newMessagePull(rt))
	cmd.AddCommand(newMessagePeek(rt))
	cmd.AddCommand(newMessageAck(rt))
	cmd.AddCommand(newMessageDelete(rt))
	return cmd
}

func newMessagePush(rt *app.Runtime) *cobra.Command {
	var bodyFlag, contentType, bulkFlag string
	var delayFlag int64
	cmd := &cobra.Command{
		Use:   "push QUEUE_ID (--body VALUE | --bulk @file)",
		Short: "Publish messages",
		Long: "Publish one message or a batch.\n\n" +
			"Examples:\n" +
			"  flareadm queue message push <queue-id> --body @payload.json --content-type json\n" +
			"  flareadm queue message push <queue-id> --body 'hello' --content-type text\n" +
			"  flareadm queue message push <queue-id> --bulk @messages.json\n\n" +
			"--body accepts inline text or @file; --content-type json requires the body to\n" +
			"be valid JSON. --bulk takes a JSON array of message objects\n" +
			"({body, content_type, delay_seconds}). Message payloads are never written\n" +
			"to debug logs or error output.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hasBody := cmd.Flags().Changed("body")
			hasBulk := cmd.Flags().Changed("bulk")
			if hasBody == hasBulk {
				return errors.Usage("pass exactly one of --body VALUE or --bulk @file")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if hasBulk {
				messages, err := cmdutil.ParseJSONArray("bulk", bulkFlag)
				if err != nil {
					return err
				}
				rt.ProtectSecret(string(messages))
				if rt.DryRunFlag {
					return previewLine(rt, "Would publish a message batch to queue "+args[0])
				}
				res, err := client.BulkPushMessages(cmd.Context(), ref.ID, args[0], []json.RawMessage{messages}, float64(delayFlag))
				if err != nil {
					return err
				}
				return renderMetadata(rt, res)
			}

			raw, err := cmdutil.ValueOrFile("body", bodyFlag)
			if err != nil {
				return err
			}
			if raw == "" {
				return errors.Usage("--body must not be empty")
			}
			rt.ProtectSecret(raw)
			ct := contentType
			if ct == "" {
				ct = "text"
			}
			if !contains(cloudflare.QueueContentTypes, ct) {
				return errors.Usage("invalid --content-type %q (supported: text, json)", contentType)
			}
			var value json.RawMessage
			if ct == "json" {
				if !json.Valid([]byte(raw)) {
					return errors.Usage("--content-type json requires a valid JSON body")
				}
				value = json.RawMessage(raw)
			} else {
				encoded, err := json.Marshal(raw)
				if err != nil {
					return err
				}
				value = encoded
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would publish one message to queue "+args[0])
			}
			res, err := client.PushMessage(cmd.Context(), ref.ID, args[0], cloudflare.QueuePushParams{
				Body: value, ContentType: ct, DelaySeconds: float64(delayFlag),
			})
			if err != nil {
				return err
			}
			return renderMetadata(rt, res)
		},
	}
	cmd.Flags().StringVar(&bodyFlag, "body", "", "message body, inline or @file")
	cmd.Flags().StringVar(&bulkFlag, "bulk", "", "batch of message objects as a JSON array, inline or @file")
	cmd.Flags().StringVar(&contentType, "content-type", "text", "message content type (text, json)")
	cmd.Flags().Int64Var(&delayFlag, "delay-seconds", 0, "delay before delivery in seconds")
	return cmd
}

// renderMetadata renders a push response (result metadata).
func renderMetadata(rt *app.Runtime, res *cloudflare.GetResult[json.RawMessage]) error {
	if rt.Raw() {
		return rt.Printer().Raw(res.RawBody)
	}
	meta := "{}"
	if len(res.Item) > 0 {
		meta = string(res.Item)
	}
	if rt.Format() == output.Table {
		row := func(s string) []string { return []string{truncate(s, 80)} }
		return rt.Printer().PrintTable([]string{"RESULT"}, [][]string{row(meta)})
	}
	return rt.Printer().Emit(map[string]any{"result": json.RawMessage(meta)})
}

func newMessagePull(rt *app.Runtime) *cobra.Command {
	var batchFlag, visibilityFlag int64
	cmd := &cobra.Command{
		Use:   "pull QUEUE_ID",
		Short: "Pull messages",
		Long: "Pull messages from a queue. Pulled messages are leased; acknowledge them\n" +
			"with `queue message ack --ack <lease-id>` or let the visibility timeout\n" +
			"expire.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.PullMessages(cmd.Context(), ref.ID, args[0], int(batchFlag), visibilityFlag)
			if err != nil {
				return err
			}
			return renderPull(rt, res)
		},
	}
	cmd.Flags().Int64Var(&batchFlag, "batch-size", 0, "maximum number of messages to pull")
	cmd.Flags().Int64Var(&visibilityFlag, "visibility-timeout-ms", 0, "visibility timeout in milliseconds")
	return cmd
}

func newMessagePeek(rt *app.Runtime) *cobra.Command {
	var batchFlag int64
	cmd := &cobra.Command{
		Use:   "peek QUEUE_ID",
		Short: "Peek messages without consuming them",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.PeekMessages(cmd.Context(), ref.ID, args[0], int(batchFlag))
			if err != nil {
				return err
			}
			return renderPull(rt, res)
		},
	}
	cmd.Flags().Int64Var(&batchFlag, "batch-size", 0, "maximum number of messages to peek")
	return cmd
}

func renderPull(rt *app.Runtime, res *cloudflare.GetResult[cloudflare.QueuePullResult]) error {
	if rt.Raw() {
		return rt.Printer().Raw(res.RawBody)
	}
	if rt.Format() != output.Table {
		return rt.Printer().Emit(res.Item)
	}
	rows := make([][]string, 0, len(res.Item.Messages))
	for _, m := range res.Item.Messages {
		rows = append(rows, messageRow(m))
	}
	return rt.Printer().PrintTable(messageHeaders(), rows)
}

func newMessageAck(rt *app.Runtime) *cobra.Command {
	var ackFlags, retryFlags []string
	cmd := &cobra.Command{
		Use:   "ack QUEUE_ID",
		Short: "Acknowledge or retry leased messages",
		Long: "Acknowledge messages (--ack LEASE_ID) or request redelivery\n" +
			"(--retry LEASE_ID). Both flags are repeatable.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.AckMessages(cmd.Context(), ref.ID, args[0], ackFlags, retryFlags)
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			row := func(a cloudflare.QueueAckResult) []string {
				return []string{strconv.FormatFloat(a.AckCount, 'f', 0, 64), strconv.FormatFloat(a.RetryCount, 'f', 0, 64)}
			}
			return app.RenderGet(rt, res, []string{"ACKED", "RETRIED"}, row)
		},
	}
	cmd.Flags().StringArrayVar(&ackFlags, "ack", nil, "lease id to acknowledge (repeatable)")
	cmd.Flags().StringArrayVar(&retryFlags, "retry", nil, "lease id to retry (repeatable)")
	return cmd
}

func newMessageDelete(rt *app.Runtime) *cobra.Command {
	var refFlags []string
	cmd := &cobra.Command{
		Use:   "delete QUEUE_ID --ref LEASE_ID",
		Short: "Delete specific messages by ref",
		Long: "Delete messages by ref/lease id (the API's targeted message purge).\n" +
			"Destructive: prompts for confirmation unless --yes is given; --dry-run\n" +
			"previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(refFlags) == 0 {
				return errors.Usage("pass at least one --ref LEASE_ID")
			}
			if rt.DryRunFlag {
				return previewLine(rt, fmt.Sprintf("Would delete %d message(s) from queue %s", len(refFlags), args[0]))
			}
			if err := rt.Confirm(fmt.Sprintf("Delete %d message(s) from queue %s?", len(refFlags), args[0])); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.PurgeMessages(cmd.Context(), ref.ID, args[0], refFlags); err != nil {
				return err
			}
			rt.Logger().Infof("deleted %d message(s) from queue %s", len(refFlags), args[0])
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&refFlags, "ref", nil, "message ref/lease id (repeatable)")
	return cmd
}
