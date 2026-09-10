package kv

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

func namespaceRow(n cloudflare.KVNamespace) []string {
	return []string{n.ID, n.Title}
}

func newNamespaceGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace",
		Short: "KV namespaces",
	}
	cmd.AddCommand(newNamespaceList(rt))
	cmd.AddCommand(newNamespaceGet(rt))
	cmd.AddCommand(newNamespaceCreate(rt))
	cmd.AddCommand(newNamespaceDelete(rt))
	return cmd
}

func newNamespaceList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List KV namespaces",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListKVNamespaces(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "TITLE"}, namespaceRow)
		},
	}
}

func newNamespaceGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get NAMESPACE_ID",
		Short: "Show one KV namespace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetKVNamespace(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "TITLE"}, namespaceRow)
		},
	}
}

func newNamespaceCreate(rt *app.Runtime) *cobra.Command {
	var titleFlag, jurisdictionFlag string
	cmd := &cobra.Command{
		Use:   "create --title TITLE",
		Short: "Create a KV namespace",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if titleFlag == "" {
				return errors.Usage("--title is required")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create KV namespace "+titleFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateKVNamespace(cmd.Context(), ref.ID, cloudflare.KVNamespaceCreateParams{
				Title: titleFlag, Jurisdiction: jurisdictionFlag,
			})
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "TITLE"}, namespaceRow)
		},
	}
	cmd.Flags().StringVar(&titleFlag, "title", "", "namespace title (required)")
	cmd.Flags().StringVar(&jurisdictionFlag, "jurisdiction", "", "namespace jurisdiction (eu, us, fedramp)")
	return cmd
}

func newNamespaceDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete NAMESPACE_ID",
		Short: "Delete a KV namespace",
		Long: "Delete a KV namespace and all of its keys. Destructive: prompts for\n" +
			"confirmation unless --yes is given; --dry-run previews the deletion.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetKVNamespace(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete KV namespace "+existing.Item.Title+" ("+existing.Item.ID+")")
			}
			if err := rt.Confirm("Delete KV namespace " + existing.Item.Title + "?"); err != nil {
				return err
			}
			if err := client.DeleteKVNamespace(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted KV namespace %s", args[0])
			return nil
		},
	}
	return cmd
}

func previewLine(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": rt.Redact(line)})
}
