// Package registrar implements `flareadm registrar ...`: registrar domain and
// registration administration.
package registrar

import (
	"encoding/json"
	"sort"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// New builds the registrar command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registrar",
		Short: "Cloudflare Registrar",
		Long:  "Cloudflare Registrar administration (domain inventory and registrations). Registration and transfer workflows (which require legal agreements, contacts and billing) are not implemented.",
	}
	cmd.AddCommand(newDomainGroup(rt))
	cmd.AddCommand(newRegistrationGroup(rt))
	return cmd
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func domainRow(d cloudflare.RegistrarDomain) []string {
	return []string{d.ID, strconv.FormatBool(d.Available), strconv.FormatBool(d.Locked), dateOnly(d.ExpiresAt), d.CurrentRegistrar}
}

func domainHeaders() []string {
	return []string{"DOMAIN", "AVAILABLE", "LOCKED", "EXPIRES", "REGISTRAR"}
}

func newDomainGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Registrar domains",
		Long:  "Registrar domain inventory (/accounts/{account_id}/registrar/domains).",
	}
	cmd.AddCommand(newDomainList(rt))
	cmd.AddCommand(newDomainGet(rt))
	cmd.AddCommand(newDomainUpdate(rt))
	return cmd
}

func newDomainList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registrar domains",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListRegistrarDomains(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, domainHeaders(), domainRow)
		},
	}
}

func newDomainGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get DOMAIN",
		Short: "Show one registrar domain",
		Long:  "Show a domain. The API response is untyped, so tables render it as setting/value rows.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetRegistrarDomain(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			if rt.Format() != output.Table {
				return rt.Printer().Emit(res.Item)
			}
			return renderObject(rt, res.Item)
		},
	}
}

func newDomainUpdate(rt *app.Runtime) *cobra.Command {
	var autoRenew, locked, privacy bool
	cmd := &cobra.Command{
		Use:   "update DOMAIN",
		Short: "Update registrar domain settings",
		Long: "Update the transfer lock, auto-renew and privacy settings of a domain. The\n" +
			"current object is read first and merged into the PUT, so unmodeled fields are\n" +
			"preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("auto-renew") {
				body["auto_renew"] = autoRenew
			}
			if cmd.Flags().Changed("locked") {
				body["locked"] = locked
			}
			if cmd.Flags().Changed("privacy") {
				body["privacy"] = privacy
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one of --auto-renew, --locked, --privacy")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update registrar domain "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateRegistrarDomain(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			if rt.Format() != output.Table {
				return rt.Printer().Emit(res.Item)
			}
			return renderObject(rt, res.Item)
		},
	}
	cmd.Flags().BoolVar(&autoRenew, "auto-renew", false, "auto-renew the domain (use --auto-renew=false to disable)")
	cmd.Flags().BoolVar(&locked, "locked", false, "transfer lock (use --locked=false to unlock)")
	cmd.Flags().BoolVar(&privacy, "privacy", false, "WHOIS privacy (use --privacy=false to disable)")
	return cmd
}

// renderObject prints an untyped object as sorted setting/value rows.
func renderObject(rt *app.Runtime, raw json.RawMessage) error {
	var decoded map[string]any
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
		rows = append(rows, []string{k, cmdutil.ScalarString(decoded[k])})
	}
	return rt.Printer().PrintTable([]string{"SETTING", "VALUE"}, rows)
}

func registrationRow(r cloudflare.RegistrarRegistration) []string {
	return []string{r.DomainName, r.Status, strconv.FormatBool(r.AutoRenew), strconv.FormatBool(r.Locked), r.PrivacyMode, dateOnly(r.ExpiresAt)}
}

func registrationHeaders() []string {
	return []string{"DOMAIN", "STATUS", "AUTO RENEW", "LOCKED", "PRIVACY", "EXPIRES"}
}

func newRegistrationGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registration",
		Short: "Domain registrations",
		Long:  "Registrations of the account (/accounts/{account_id}/registrar/registrations, cursor paginated). Creating a registration requires contacts, legal agreements and billing and is not implemented.",
	}
	cmd.AddCommand(newRegistrationList(rt))
	cmd.AddCommand(newRegistrationGet(rt))
	cmd.AddCommand(newRegistrationUpdate(rt))
	return cmd
}

func newRegistrationList(rt *app.Runtime) *cobra.Command {
	var q cloudflare.RegistrarRegistrationQuery
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registrations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if q.Direction != "" && q.Direction != "asc" && q.Direction != "desc" {
				return errors.Usage("invalid --direction (supported: asc, desc)")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListRegistrarRegistrations(cmd.Context(), ref.ID, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, registrationHeaders(), registrationRow)
		},
	}
	cmd.Flags().StringVar(&q.Direction, "direction", "", "sort direction (asc, desc)")
	_ = cmd.RegisterFlagCompletionFunc("direction", cmdutil.Enums("asc", "desc"))
	cmd.Flags().StringVar(&q.SortBy, "sort-by", "", "sort key (for example domain_name)")
	return cmd
}

func newRegistrationGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get DOMAIN",
		Short: "Show one registration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetRegistrarRegistration(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, registrationHeaders(), registrationRow)
		},
	}
}

func newRegistrationUpdate(rt *app.Runtime) *cobra.Command {
	var autoRenew bool
	cmd := &cobra.Command{
		Use:   "update DOMAIN",
		Short: "Update a registration",
		Long:  "Partially update a registration: only the provided fields change.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("auto-renew") {
				return errors.Usage("nothing to update; pass --auto-renew")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update registration "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateRegistrarRegistration(cmd.Context(), ref.ID, args[0], map[string]any{"auto_renew": autoRenew})
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, registrationHeaders(), registrationRow)
		},
	}
	cmd.Flags().BoolVar(&autoRenew, "auto-renew", false, "auto-renew the registration (use --auto-renew=false to disable)")
	return cmd
}
