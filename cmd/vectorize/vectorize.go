// Package vectorize implements `flareadm vectorize ...`: Vectorize index and
// vector administration.
package vectorize

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// metricValues are the accepted index distance metrics.
var metricValues = []string{"cosine", "euclidean", "dot-product"}

// metadataIndexTypes are the accepted metadata index types.
var metadataIndexTypes = []string{"string", "number", "boolean"}

// New builds the vectorize command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vectorize",
		Short: "Vectorize index and vector administration",
		Long:  "Vectorize administration. Account scope is resolved through the standard account resolution.",
	}
	cmd.AddCommand(newIndexGroup(rt))
	cmd.AddCommand(newVectorGroup(rt))
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

func requireFile(flag, v string) error {
	if len(v) == 0 || v[0] != '@' {
		return errors.Usage("--%s accepts only the @file form (for example @vectors.ndjson)", flag)
	}
	return nil
}
