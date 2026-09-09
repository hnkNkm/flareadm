// Package confirm implements destructive-operation confirmation
// (docs/cli.md):
//
//   - interactive terminals prompt "[y/N]";
//   - --yes skips the prompt;
//   - when stdin is not interactive (or --no-input is set) and --yes is
//     absent, confirmation fails with exit code 2 instead of hanging.
package confirm

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// Prompter reads interactive answers.
type Prompter struct {
	Stdin       io.Reader
	Stdout      io.Writer
	Yes         bool // --yes: skip prompt, proceed
	NoInput     bool // --no-input: never prompt
	Interactive bool // stdin is a terminal
}

// Confirm checks destructive-operation consent. It returns nil when the
// operation may proceed. Prompt text is written to Stdout so the user sees
// the question in the same stream as normal output; on non-interactive
// runs nothing is written.
func (p *Prompter) Confirm(question string) error {
	if p.Yes {
		return nil
	}
	if !p.Interactive || p.NoInput {
		return errors.New(errors.CodeInvalid,
			"%s confirmation required; rerun with --yes to confirm (stdin is %s)",
			strings.TrimRight(question, "? "), inputState(p.Interactive, p.NoInput))
	}

	reader := bufio.NewReader(p.Stdin)
	for {
		_, _ = fmt.Fprintf(p.Stdout, "%s [y/N] ", question)
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil && line == "" {
			// EOF or read error with no answer: treat as decline.
			return errors.New(errors.CodeUnclassified, "confirmation aborted")
		}
		switch strings.ToLower(line) {
		case "y", "yes", "true":
			return nil
		case "", "n", "no", "false":
			return errors.New(errors.CodeUnclassified, "aborted")
		}
		if err != nil && err != io.EOF {
			return errors.New(errors.CodeUnclassified, "confirmation aborted")
		}
	}
}

func inputState(interactive, noInput bool) string {
	switch {
	case noInput:
		return "not interactive (--no-input)"
	case interactive:
		return "interactive"
	default:
		return "not interactive"
	}
}
