// Package redirect implements `flareadm redirect rule ...`: Redirect Rules
// (the http_request_dynamic_redirect phase entrypoint).
package redirect

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/phaserulecmd"
	"github.com/hnkNkm/flareadm/internal/app"
)

// New builds the redirect command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "redirect",
		Short: "Redirect Rules administration",
	}
	cmd.AddCommand(phaserulecmd.New(rt, phaserulecmd.Config{
		Phase:     "http_request_dynamic_redirect",
		Short:     "Redirect rules",
		RuleNoun:  "redirect",
		PhasesRef: "http_request_dynamic_redirect",
		Example: "flareadm redirect rule create --zone example.com --action redirect \\\n" +
			"    --expression \"(http.request.uri.path eq \\\"/old\\\")\" --action-parameters @params.json",
	}))
	return cmd
}
