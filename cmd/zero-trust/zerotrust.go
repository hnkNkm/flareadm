// Package zerotrust implements `flareadm zero-trust ...`: Cloudflare Tunnel
// administration and Zero Trust account settings.
package zerotrust

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// New builds the zero-trust command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zero-trust",
		Short: "Zero Trust administration",
		Long:  "Zero Trust administration (Cloudflare Tunnel and account organization settings). Account scope is resolved through the standard account resolution.",
	}
	cmd.AddCommand(newAccessGroup(rt))
	cmd.AddCommand(newDeviceGroup(rt))
	cmd.AddCommand(newGatewayGroup(rt))
	cmd.AddCommand(newTunnelGroup(rt))
	cmd.AddCommand(newRouteGroup(rt))
	cmd.AddCommand(newOrganizationGroup(rt))
	return cmd
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func previewLine(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": rt.Redact(line)})
}

// fileOnly reads a credential flag that accepts only the @file form.
func fileOnly(flag, v string) (string, error) {
	if len(v) == 0 || v[0] != '@' {
		return "", errors.Usage(
			"--%s accepts only the @file form (for example @secret.txt); inline secret values are rejected because process arguments are observable",
			flag)
	}
	return cmdutilValueOrFile(flag, v)
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

var _ = cloudflare.TunnelConfigSrcValues
