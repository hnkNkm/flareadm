// Package auditlog implements `flareadm audit-log ...`: account audit logs.
package auditlog

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// New builds the audit-log command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit-log",
		Short: "Account audit logs",
		Long:  "Account audit logs (/accounts/{account_id}/audit_logs), newest first.",
	}
	cmd.AddCommand(newList(rt))
	return cmd
}

func row(l cloudflare.AuditLog) []string {
	return []string{l.When, l.Actor.Email, l.Action.Type, l.Resource.Type, l.Resource.ID, l.Actor.IP}
}

func headers() []string {
	return []string{"WHEN", "ACTOR", "ACTION", "RESOURCE TYPE", "RESOURCE ID", "IP"}
}

func newList(rt *app.Runtime) *cobra.Command {
	var f cloudflare.AuditLogQuery
	var hideUserLogs bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit log entries",
		Long: "List audit logs.\n\n" +
			"Example:\n" +
			"  flareadm audit-log list --since 2026-01-01T00:00:00Z --action dns_record_edit",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f.HideUserLogs = hideUserLogs
			if f.Direction != "" && f.Direction != "asc" && f.Direction != "desc" {
				return errorsUsage()
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAuditLogs(cmd.Context(), ref.ID, f, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, headers(), row)
		},
	}
	cmd.Flags().StringVar(&f.Since, "since", "", "only entries at or after this RFC3339 time")
	cmd.Flags().StringVar(&f.Before, "before", "", "only entries before this RFC3339 time")
	cmd.Flags().StringVar(&f.Action, "action", "", "only entries with this action type")
	cmd.Flags().StringVar(&f.Actor, "actor", "", "only entries by this actor (email or id)")
	cmd.Flags().StringVar(&f.Zone, "zone", "", "only entries for this zone name")
	cmd.Flags().StringVar(&f.Direction, "direction", "", "sort direction (asc, desc)")
	_ = cmd.RegisterFlagCompletionFunc("direction", cmdutil.Enums("asc", "desc"))
	cmd.Flags().StringVar(&f.ID, "id", "", "only the entry with this id")
	cmd.Flags().BoolVar(&hideUserLogs, "hide-user-logs", false, "hide user-initiated entries")
	return cmd
}

func errorsUsage() error {
	return errors.New(errors.CodeInvalid, "invalid --direction (supported: asc, desc)")
}
