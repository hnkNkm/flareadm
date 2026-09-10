package kv

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

func keyRow(k cloudflare.KVKey) []string {
	return []string{k.Name, expirationString(k.Expiration), metadataString(k.Metadata)}
}

func expirationString(e float64) string {
	if e == 0 {
		return ""
	}
	return strconv.FormatFloat(e, 'f', 0, 64)
}

func metadataString(m json.RawMessage) string {
	if len(m) == 0 {
		return ""
	}
	return truncate(string(m), 40)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func newKeyGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "KV keys",
	}
	cmd.AddCommand(newKeyList(rt))
	cmd.AddCommand(newKeyGet(rt))
	cmd.AddCommand(newKeyPut(rt))
	cmd.AddCommand(newKeyDelete(rt))
	return cmd
}

func newKeyList(rt *app.Runtime) *cobra.Command {
	var namespaceFlag, prefixFlag string
	cmd := &cobra.Command{
		Use:   "list --namespace NAMESPACE_ID",
		Short: "List KV keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if namespaceFlag == "" {
				return errors.Usage("--namespace is required")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			q := cloudflare.KVKeyQuery{Prefix: prefixFlag}
			res, err := client.ListKVKeys(cmd.Context(), ref.ID, namespaceFlag, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"NAME", "EXPIRATION", "METADATA"}, keyRow)
		},
	}
	cmd.Flags().StringVar(&namespaceFlag, "namespace", "", "namespace id (required)")
	cmd.Flags().StringVar(&prefixFlag, "prefix", "", "only keys starting with this prefix")
	return cmd
}

func newKeyGet(rt *app.Runtime) *cobra.Command {
	var namespaceFlag string
	cmd := &cobra.Command{
		Use:   "get KEY --namespace NAMESPACE_ID",
		Short: "Print a KV value",
		Long: "Print the value of a key. The default, text and --raw output write the\n" +
			"value verbatim; --json and --output yaml wrap it in the normalized\n" +
			"envelope. Values are never written to debug logs.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if namespaceFlag == "" {
				return errors.Usage("--namespace is required")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			value, err := client.GetKVValue(cmd.Context(), ref.ID, namespaceFlag, args[0])
			if err != nil {
				return err
			}
			switch rt.Format() {
			case output.JSON, output.YAML:
				return rt.Printer().Emit(map[string]string{"key": args[0], "value": string(value)})
			default:
				// Default, text and raw write the value verbatim: byte for
				// byte, with no trailing newline added, so the output can be
				// piped or redirected losslessly.
				if len(value) == 0 {
					return nil
				}
				_, err := rt.Out.Write(value)
				return err
			}
		},
	}
	cmd.Flags().StringVar(&namespaceFlag, "namespace", "", "namespace id (required)")
	return cmd
}

func newKeyPut(rt *app.Runtime) *cobra.Command {
	var namespaceFlag, valueFlag, metadataFlag string
	var expiration, expirationTTL int64
	cmd := &cobra.Command{
		Use:   "put KEY --namespace NAMESPACE_ID --value VALUE",
		Short: "Write a KV value",
		Long: "Write a key value.\n\n" +
			"Examples:\n" +
			"  flareadm kv key put config --namespace <id> --value @config.json\n" +
			"  echo hello | flareadm kv key put greeting --namespace <id> --value @-\n\n" +
			"--value accepts inline text or @file (use @- for stdin). The value is sent\n" +
			"only to the Cloudflare API and is never printed or logged.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if namespaceFlag == "" {
				return errors.Usage("--namespace is required")
			}
			if !cmd.Flags().Changed("value") {
				return errors.Usage("--value is required (inline text or @file)")
			}
			value, err := readValue(valueFlag)
			if err != nil {
				return err
			}
			if len(value) == 0 {
				return errors.Usage("--value must not be empty")
			}
			rt.ProtectSecret(string(value))
			var metadata json.RawMessage
			if cmd.Flags().Changed("metadata") {
				metadata, err = cmdutil.ParseJSONObject("metadata", metadataFlag)
				if err != nil {
					return err
				}
			}
			if expiration > 0 && expirationTTL > 0 {
				return errors.Usage("--expiration and --expiration-ttl are mutually exclusive")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, fmt.Sprintf("Would write key %s (%d bytes)", args[0], len(value)))
			}
			if err := client.PutKVValue(cmd.Context(), ref.ID, namespaceFlag, args[0], cloudflare.KVPutParams{
				Value: value, Metadata: metadata, Expiration: expiration, ExpirationTTL: expirationTTL,
			}); err != nil {
				return err
			}
			rt.Logger().Infof("wrote key %s", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&namespaceFlag, "namespace", "", "namespace id (required)")
	cmd.Flags().StringVar(&valueFlag, "value", "", "value to write: inline text or @file (@- for stdin)")
	cmd.Flags().StringVar(&metadataFlag, "metadata", "", "metadata JSON object, inline or @file")
	cmd.Flags().Int64Var(&expiration, "expiration", 0, "absolute expiration (unix seconds)")
	cmd.Flags().Int64Var(&expirationTTL, "expiration-ttl", 0, "expiration relative to now (seconds)")
	return cmd
}

// readValue resolves --value: @file reads a file, @- reads stdin.
func readValue(v string) ([]byte, error) {
	if !strings.HasPrefix(v, "@") {
		return []byte(v), nil
	}
	path := v[1:]
	if path == "-" {
		return readAllStdin()
	}
	data, err := cmdutil.ValueOrFile("value", v)
	if err != nil {
		return nil, err
	}
	return []byte(data), nil
}

func newKeyDelete(rt *app.Runtime) *cobra.Command {
	var namespaceFlag string
	cmd := &cobra.Command{
		Use:   "delete KEY --namespace NAMESPACE_ID",
		Short: "Delete a KV key",
		Long: "Delete a key. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion. The key must exist (otherwise exit 5).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if namespaceFlag == "" {
				return errors.Usage("--namespace is required")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			// Verify existence through the key list (there is no metadata GET).
			res, err := client.ListKVKeys(cmd.Context(), ref.ID, namespaceFlag,
				cloudflare.KVKeyQuery{Prefix: args[0]}, rt.Policy())
			if err != nil {
				return err
			}
			found := false
			for _, k := range res.Items {
				if k.Name == args[0] {
					found = true
					break
				}
			}
			if !found {
				return errors.New(errors.CodeNotFound, "key %q not found in namespace %s", args[0], namespaceFlag)
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete key "+args[0])
			}
			if err := rt.Confirm("Delete key " + args[0] + "?"); err != nil {
				return err
			}
			if err := client.DeleteKVKey(cmd.Context(), ref.ID, namespaceFlag, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted key %s", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&namespaceFlag, "namespace", "", "namespace id (required)")
	return cmd
}
