// Package account implements `flareadm account list|get`.
package account

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/resolver"
)

// New builds the account command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Cloudflare accounts",
	}
	cmd.AddCommand(newList(rt))
	cmd.AddCommand(newGet(rt))
	return cmd
}

func accountRow(a cloudflare.Account) []string {
	return []string{a.ID, a.Name}
}

// newList lists the accounts accessible to the token.
func newList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List accessible accounts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := rt.CloudClient()
			if err != nil {
				return err
			}
			res, err := client.ListAccounts(cmd.Context(), rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "NAME"}, accountRow)
		},
	}
}

// newGet shows one account (positional id, or the resolved account).
func newGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get [ACCOUNT_ID]",
		Short: "Show one account",
		Long: "Show one account. ACCOUNT_ID defaults to the resolved account\n" +
			"(--account-id, profile account_id, FLAREADM_ACCOUNT_ID, or the single\n" +
			"accessible account).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := rt.CloudClient()
			if err != nil {
				return err
			}
			accountID := ""
			if len(args) == 1 {
				accountID = args[0]
				if !cloudflare.ValidID(accountID) {
					return errors.Usage("invalid account id %q (expected a 32-character hex id)", accountID)
				}
			} else {
				prof, err := rt.ActiveProfilePtr()
				if err != nil {
					return err
				}
				ref, err := resolver.Account(cmd.Context(), client, rt.AccountIDFlag, prof, rt.Getenv)
				if err != nil {
					return err
				}
				accountID = ref.ID
				rt.Logger().Infof("resolved account %s (%s)", ref.ID, ref.Source)
			}
			res, err := client.GetAccount(cmd.Context(), accountID)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME"}, accountRow)
		},
	}
}
