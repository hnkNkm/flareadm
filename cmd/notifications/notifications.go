// Package notifications implements `flareadm notifications ...`: Cloudflare
// notification policies, destinations, silences and history.
package notifications

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
)

// New builds the notifications command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notifications",
		Short: "Cloudflare notifications",
		Long:  "Cloudflare Notifications (the /alerting/v3 API): policies, webhook and PagerDuty destinations, silences and delivery history. Everything is account-scoped.",
	}
	cmd.AddCommand(newPolicyGroup(rt))
	cmd.AddCommand(newWebhookGroup(rt))
	cmd.AddCommand(newPagerdutyGroup(rt))
	cmd.AddCommand(newSilenceGroup(rt))
	cmd.AddCommand(newHistoryGroup(rt))
	cmd.AddCommand(newAlertTypeGroup(rt))
	return cmd
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}
