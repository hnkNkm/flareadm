// Command flareadm is a fast, standalone administration CLI for Cloudflare.
package main

import (
	"context"
	"os"

	"github.com/hnkNkm/flareadm/cmd"
)

func main() {
	os.Exit(cmd.Run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
