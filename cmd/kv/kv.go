// Package kv implements `flareadm kv namespace ...` and `flareadm kv key ...`.
package kv

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
)

// New builds the kv command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kv",
		Short: "Workers KV administration",
		Long:  "Workers KV namespace and key administration. Account scope is resolved through the standard account resolution.",
	}
	cmd.AddCommand(newNamespaceGroup(rt))
	cmd.AddCommand(newKeyGroup(rt))
	return cmd
}
