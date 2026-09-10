// Package waf implements `flareadm waf ...`: the WAF-oriented view over the
// rulesets API (managed rulesets and action overrides).
package waf

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
)

// wafPhases are the ruleset phases that make up the WAF surface.
var wafPhases = []string{
	"http_request_firewall_managed",
	"http_request_firewall_custom",
	"http_ratelimit",
	"http_response_firewall_managed",
}

// New builds the waf command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "waf",
		Short: "Web Application Firewall (rulesets view)",
		Long: "WAF administration through the rulesets API. Managed rulesets are\n" +
			"deployed by Cloudflare; operators change their behavior with rule\n" +
			"overrides via `waf ruleset update --rules @overrides.json`.",
	}
	cmd.AddCommand(newRulesetGroup(rt))
	return cmd
}
