package zerotrust

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
)

// newAccessGroup builds the `zero-trust access ...` command group.
//
// Two policy scopes exist and are addressed as distinct command paths:
//   - `access policy ...` edits reusable account-level policies
//     (/accounts/{a}/access/policies);
//   - `access app policy ...` edits a single application's policies
//     (/accounts/{a}/access/apps/{app_id}/policies), mirroring the API
//     hierarchy the way `kv namespace key` does.
func newAccessGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Zero Trust Access (applications, policies, groups, identity providers, service tokens)",
	}
	cmd.AddCommand(newAccessAppGroup(rt))
	cmd.AddCommand(newAccessPolicyGroup(rt))
	cmd.AddCommand(newAccessGroupGroup(rt))
	cmd.AddCommand(newAccessIDPGroup(rt))
	cmd.AddCommand(newAccessServiceTokenGroup(rt))
	return cmd
}
