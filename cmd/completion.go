package cmd

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// addCompletion registers `flareadm completion <bash|zsh|fish|powershell>`.
// The generated scripts are also checked into completions/.
func addCompletion(root *cobra.Command, rt *app.Runtime) {
	root.CompletionOptions.DisableDefaultCmd = true

	completion := &cobra.Command{
		Use:   "completion <bash|zsh|fish|powershell>",
		Short: "Generate a shell completion script",
		Long: "Generate a shell completion script for flareadm.\n\n" +
			"Example:\n" +
			"  flareadm completion bash > /etc/bash_completion.d/flareadm\n" +
			"  flareadm completion zsh > \"${fpath[1]}/_flareadm\"",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cmdutil.Enums("bash", "zsh", "fish", "powershell"),
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(w, true)
			case "zsh":
				return root.GenZshCompletion(w)
			case "fish":
				return root.GenFishCompletion(w, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(w)
			default:
				return errors.Usage("unsupported shell %q (supported: bash, zsh, fish, powershell)", args[0])
			}
		},
	}
	root.AddCommand(completion)
}
