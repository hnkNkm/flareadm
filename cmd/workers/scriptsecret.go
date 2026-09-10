package workers

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func secretRow(s cloudflare.WorkerSecret) []string {
	return []string{s.Name, s.Type, s.Algorithm, s.Format, joinList(s.Usages)}
}

func secretHeaders() []string {
	return []string{"NAME", "TYPE", "ALGORITHM", "FORMAT", "USAGES"}
}

func newScriptSecretGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Script secrets",
		Long:  "Script secrets (/accounts/{account_id}/workers/scripts/{script}/secrets).\n\nThe secret value is a credential: it is never returned by the API, is written as\n@file only, is registered as a protected secret before use, and never appears in\ndiagnostics, error text or --dry-run previews.",
	}
	cmd.AddCommand(newScriptSecretList(rt))
	cmd.AddCommand(newScriptSecretGet(rt))
	cmd.AddCommand(newScriptSecretCreate(rt))
	cmd.AddCommand(newScriptSecretDelete(rt))
	return cmd
}

func newScriptSecretList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list SCRIPT",
		Short: "List a script's secrets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListWorkerSecrets(cmd.Context(), ref.ID, args[0], rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, secretHeaders(), secretRow)
		},
	}
}

func newScriptSecretGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get SCRIPT NAME",
		Short: "Show a secret's metadata",
		Long:  "Show secret metadata. The API never returns the value itself.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerSecret(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, secretHeaders(), secretRow)
		},
	}
}

func newScriptSecretCreate(rt *app.Runtime) *cobra.Command {
	var nameFlag, typeFlag, textFlag, keyJWKFlag, formatFlag, usagesFlag string
	cmd := &cobra.Command{
		Use:   "create SCRIPT --name NAME --text @secret.txt",
		Short: "Create or replace a script secret",
		Long: "Create a secret, or replace its value when it already exists (the API's PUT is\n" +
			"an upsert; there is no separate update verb).\n\n" +
			"--text is @file-only: the value is a credential, is registered as a protected\n" +
			"secret and is never printed, logged or included in previews.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if nameFlag == "" {
				return errors.Usage("--name is required")
			}
			value := cloudflare.WorkerSecretValue{
				Name:   nameFlag,
				Type:   typeFlag,
				Format: formatFlag,
				Usages: cmdutil.SplitList(usagesFlag),
			}
			if cmd.Flags().Changed("text") {
				text, err := cmdutil.FileOnly("text", textFlag)
				if err != nil {
					return err
				}
				rt.ProtectSecret(text)
				value.Text = text
			}
			if cmd.Flags().Changed("key-jwk") {
				jwk, err := cmdutil.ParseSecretCarryingObject(rt, "key-jwk", keyJWKFlag)
				if err != nil {
					return err
				}
				value.KeyJWK = jwk
			}
			if value.Text == "" && len(value.KeyJWK) == 0 {
				return errors.Usage("--text is required (or --key-jwk for an asymmetric key)")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create or replace secret "+nameFlag+" on script "+args[0]+" (value hidden)")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateWorkerSecret(cmd.Context(), ref.ID, args[0], value)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, secretHeaders(), secretRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "secret name (required)")
	cmd.Flags().StringVar(&typeFlag, "type", "", "secret type (default secret_text)")
	cmd.Flags().StringVar(&textFlag, "text", "", "secret value as @file only")
	cmd.Flags().StringVar(&keyJWKFlag, "key-jwk", "", "asymmetric key as a JWK object, inline or @file")
	cmd.Flags().StringVar(&formatFlag, "format", "", "key format (for example jwk)")
	cmd.Flags().StringVar(&usagesFlag, "usages", "", "comma-separated key usages")
	return cmd
}

func newScriptSecretDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete SCRIPT NAME",
		Short: "Delete a script secret",
		Long: "Delete a secret. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete secret "+args[1]+" from script "+args[0])
			}
			if err := rt.Confirm("Delete secret " + args[1] + " from script " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeleteWorkerSecret(cmd.Context(), ref.ID, args[0], args[1]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted secret %s from script %s", args[1], args[0])
			return nil
		},
	}
	return cmd
}
