package confirm

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hnkNkm/flareadm/internal/errors"
)

func confirmWith(input string, interactive, yes, noInput bool) error {
	p := &Prompter{
		Stdin:       strings.NewReader(input),
		Stdout:      &bytes.Buffer{},
		Yes:         yes,
		NoInput:     noInput,
		Interactive: interactive,
	}
	return p.Confirm("Delete DNS record api.example.com?")
}

func TestYesFlagSkipsPrompt(t *testing.T) {
	if err := confirmWith("", true, true, false); err != nil {
		t.Fatalf("--yes should proceed: %v", err)
	}
	if err := confirmWith("", false, true, false); err != nil {
		t.Fatalf("--yes should proceed non-interactively: %v", err)
	}
}

func TestInteractiveAcceptances(t *testing.T) {
	for _, input := range []string{"y\n", "yes\n", "Y\n", "YES\n", "true\n", " y \n"} {
		if err := confirmWith(input, true, false, false); err != nil {
			t.Errorf("input %q should confirm: %v", input, err)
		}
	}
}

func TestInteractiveDeclines(t *testing.T) {
	for _, input := range []string{"n\n", "no\n", "\n", "false\n"} {
		err := confirmWith(input, true, false, false)
		if err == nil {
			t.Errorf("input %q should abort", input)
			continue
		}
		if errors.CodeOf(err) != errors.CodeUnclassified {
			t.Errorf("decline exit code = %d, want 1", errors.CodeOf(err))
		}
	}
}

func TestInvalidInputReprompts(t *testing.T) {
	// "maybe" is invalid, then "y" confirms.
	if err := confirmWith("maybe\ny\n", true, false, false); err != nil {
		t.Fatalf("reprompt should confirm: %v", err)
	}
}

func TestEOFWithoutAnswerAborts(t *testing.T) {
	err := confirmWith("", true, false, false) // interactive but empty stdin
	if err == nil {
		t.Fatal("EOF should abort")
	}
}

func TestNonInteractiveFailsWithExitTwo(t *testing.T) {
	err := confirmWith("", false, false, false)
	if err == nil {
		t.Fatal("non-interactive without --yes must fail")
	}
	if errors.CodeOf(err) != errors.CodeInvalid {
		t.Fatalf("exit code = %d, want 2", errors.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error should mention --yes: %v", err)
	}
}

func TestNoInputFailsWithoutYes(t *testing.T) {
	err := confirmWith("y\n", true, false, true)
	if err == nil {
		t.Fatal("--no-input without --yes must fail even on a TTY")
	}
	if errors.CodeOf(err) != errors.CodeInvalid {
		t.Fatalf("exit code = %d, want 2", errors.CodeOf(err))
	}
}

func TestPromptWrittenToStdout(t *testing.T) {
	var buf bytes.Buffer
	p := &Prompter{Stdin: strings.NewReader("y\n"), Stdout: &buf, Interactive: true}
	if err := p.Confirm("Delete DNS record api.example.com?"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "[y/N]") {
		t.Fatalf("prompt missing [y/N]: %q", buf.String())
	}
}
