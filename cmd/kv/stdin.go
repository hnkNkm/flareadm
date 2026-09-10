package kv

import (
	"io"
	"os"
)

// readAllStdin reads the whole standard input (used by --value @-).
func readAllStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}
