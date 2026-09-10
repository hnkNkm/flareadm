package notifications

import (
	"encoding/json"
	"sort"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

func newPagerdutyGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pagerduty",
		Short: "PagerDuty destinations",
		Long:  "PagerDuty destinations (/accounts/{account_id}/alerting/v3/destinations/pagerduty). Connecting and linking is an interactive third-party flow and is not implemented; the integration can be listed and disconnected.",
	}
	cmd.AddCommand(newPagerdutyList(rt))
	cmd.AddCommand(newPagerdutyDelete(rt))
	return cmd
}

func newPagerdutyList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List PagerDuty destinations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAlertingPagerduty(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "NAME"}, func(p cloudflare.AlertingPagerduty) []string {
				return []string{p.ID, p.Name}
			})
		},
	}
}

func newPagerdutyDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Disconnect PagerDuty",
		Long: "Disconnect the account's PagerDuty integration. Destructive: every PagerDuty\n" +
			"notification stops. Prompts for confirmation unless --yes is given; --dry-run\n" +
			"previews the change without confirming.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would disconnect the PagerDuty integration")
			}
			if err := rt.Confirm("Disconnect the account PagerDuty integration?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeleteAlertingPagerduty(cmd.Context(), ref.ID); err != nil {
				return err
			}
			rt.Logger().Infof("disconnected the PagerDuty integration")
			return nil
		},
	}
	return cmd
}

func silenceRow(s cloudflare.AlertingSilence) []string {
	return []string{s.ID, s.PolicyID, s.StartTime, s.EndTime}
}

func silenceHeaders() []string {
	return []string{"ID", "POLICY ID", "START", "END"}
}

func newSilenceGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "silence",
		Short: "Notification silences",
		Long:  "Notification silences (/accounts/{account_id}/alerting/v3/silences). Update uses the API's collection endpoint (the only update path), with the silence id in the body.",
	}
	cmd.AddCommand(newSilenceList(rt))
	cmd.AddCommand(newSilenceGet(rt))
	cmd.AddCommand(newSilenceCreate(rt))
	cmd.AddCommand(newSilenceUpdate(rt))
	cmd.AddCommand(newSilenceDelete(rt))
	return cmd
}

func newSilenceList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List silences",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAlertingSilences(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, silenceHeaders(), silenceRow)
		},
	}
}

func newSilenceGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get SILENCE_ID",
		Short: "Show one silence",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetAlertingSilence(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, silenceHeaders(), silenceRow)
		},
	}
}

func newSilenceCreate(rt *app.Runtime) *cobra.Command {
	var policyID, startTime, endTime string
	cmd := &cobra.Command{
		Use:   "create --policy-id POLICY_ID --start-time TIME --end-time TIME",
		Short: "Create a silence",
		Long: "Create a silence.\n\n" +
			"Example:\n" +
			"  flareadm notifications silence create --policy-id <policy> \\\n" +
			"    --start-time 2026-01-01T00:00:00Z --end-time 2026-01-02T00:00:00Z",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if policyID == "" {
				return errors.Usage("--policy-id is required")
			}
			if startTime == "" {
				return errors.Usage("--start-time is required")
			}
			if endTime == "" {
				return errors.Usage("--end-time is required")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would silence policy "+policyID+" from "+startTime+" to "+endTime)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateAlertingSilence(cmd.Context(), ref.ID, map[string]any{
				"policy_id": policyID, "start_time": startTime, "end_time": endTime,
			})
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, silenceHeaders(), silenceRow)
		},
	}
	cmd.Flags().StringVar(&policyID, "policy-id", "", "policy to silence (required)")
	cmd.Flags().StringVar(&startTime, "start-time", "", "start time, RFC3339 (required)")
	cmd.Flags().StringVar(&endTime, "end-time", "", "end time, RFC3339 (required)")
	return cmd
}

func newSilenceUpdate(rt *app.Runtime) *cobra.Command {
	var startTime, endTime string
	cmd := &cobra.Command{
		Use:   "update SILENCE_ID",
		Short: "Update a silence",
		Long: "Update a silence's time window. The current values are read first and merged\n" +
			"into the collection PUT the API expects.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("start-time") {
				body["start_time"] = startTime
			}
			if cmd.Flags().Changed("end-time") {
				body["end_time"] = endTime
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one of --start-time, --end-time")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update silence "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateAlertingSilence(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, silenceHeaders(), silenceRow)
		},
	}
	cmd.Flags().StringVar(&startTime, "start-time", "", "new start time, RFC3339")
	cmd.Flags().StringVar(&endTime, "end-time", "", "new end time, RFC3339")
	return cmd
}

func newSilenceDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete SILENCE_ID",
		Short: "Delete a silence",
		Long: "Delete a silence. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete silence "+args[0])
			}
			if err := rt.Confirm("Delete silence " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeleteAlertingSilence(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted silence %s", args[0])
			return nil
		},
	}
	return cmd
}

func historyRow(h cloudflare.AlertingHistory) []string {
	return []string{h.Sent, h.AlertType, h.MechanismType, h.PolicyID, h.Name}
}

func historyHeaders() []string {
	return []string{"SENT", "ALERT TYPE", "MECHANISM", "POLICY ID", "NAME"}
}

func newHistoryGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Notification delivery history",
		Long:  "Sent notifications (/accounts/{account_id}/alerting/v3/history).",
	}
	cmd.AddCommand(newHistoryList(rt))
	return cmd
}

func newHistoryList(rt *app.Runtime) *cobra.Command {
	var since, before string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sent notifications",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAlertingHistory(cmd.Context(), ref.ID, cloudflare.AlertingHistoryQuery{Since: since, Before: before}, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, historyHeaders(), historyRow)
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "only notifications sent at or after this RFC3339 time")
	cmd.Flags().StringVar(&before, "before", "", "only notifications sent before this RFC3339 time")
	return cmd
}

func newAlertTypeGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alert-type",
		Short: "Alert types available to the account",
		Long:  "Alert types that can be used in policies (/accounts/{account_id}/alerting/v3/available_alerts). The API returns an untyped map, rendered as JSON.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available alert types",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAlertingAvailable(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return renderUntyped(rt, res.Item, res.RawBody)
		},
	})
	return cmd
}

// renderUntyped prints map-shaped API payloads: machine formats emit the decoded
// value, tables render one row per key with the value as compact JSON.
func renderUntyped(rt *app.Runtime, raw json.RawMessage, body []byte) error {
	if rt.Raw() {
		return rt.Printer().Raw(body)
	}
	if rt.Format() != output.Table {
		return rt.Printer().Emit(raw)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return rt.Printer().PrintTable([]string{"VALUE"}, [][]string{{cmdutil.CompactJSON(raw)}})
	}
	keys := make([]string, 0, len(decoded))
	for k := range decoded {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, []string{k, cmdutil.CompactJSON(decoded[k])})
	}
	return rt.Printer().PrintTable([]string{"ALERT TYPE", "DETAILS"}, rows)
}
