package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestGenerateIsCompleteAndDeterministic checks the three properties the
// generated reference must have: it covers every leaf command, it names the
// representative commands of every group, and two runs are byte-identical.
func TestGenerateIsCompleteAndDeterministic(t *testing.T) {
	root := newRoot()
	want := len(leafCommands(root))
	first := generate(newRoot())
	second := generate(newRoot())
	if first != second {
		t.Fatalf("generator is not deterministic: %d vs %d bytes", len(first), len(second))
	}
	if first == "" {
		t.Fatal("generator produced no output")
	}
	if !strings.HasPrefix(first, "# FlareADM command reference\n") {
		t.Fatalf("unexpected preamble:\n%s", head(first, 5))
	}
	if strings.ContainsAny(first, "\x1b\r") {
		t.Fatal("output contains ANSI escapes or carriage returns")
	}
	if got := strings.Count(first, "\n## `"); got != want {
		t.Fatalf("sections = %d, want one per leaf command (%d)", got, want)
	}

	for _, section := range []string{
		"## `flareadm account list`",
		"## `flareadm zone list`",
		"## `flareadm dns record create`",
		"## `flareadm ssl setting update`",
		"## `flareadm certificate list`",
		"## `flareadm ruleset create`",
		"## `flareadm waf ruleset update`",
		"## `flareadm cache purge`",
		"## `flareadm redirect rule create`",
		"## `flareadm page-rule list`",
		"## `flareadm r2 bucket create`",
		"## `flareadm kv key list`",
		"## `flareadm d1 database query`",
		"## `flareadm queue consumer update`",
		"## `flareadm hyperdrive config create`",
		"## `flareadm vectorize vector insert`",
		"## `flareadm zero-trust tunnel list`",
		"## `flareadm zero-trust access app list`",
		"## `flareadm zero-trust gateway rule list`",
		"## `flareadm zero-trust device settings update`",
		"## `flareadm workers script settings update`",
		"## `flareadm workers route create`",
		"## `flareadm workers domain create`",
		"## `flareadm pages project deployment list`",
		"## `flareadm logpush job create`",
		"## `flareadm healthcheck preview create`",
		"## `flareadm load-balancer pool create`",
		"## `flareadm notifications policy create`",
		"## `flareadm audit-log list`",
		"## `flareadm analytics summary get`",
		"## `flareadm logs query`",
		"## `flareadm registrar domain list`",
		"## `flareadm completion`",
		"## `flareadm api request`",
	} {
		if !strings.Contains(first, section) {
			t.Fatalf("reference is missing %s", section)
		}
	}

	// Every section carries a usage block and the inherited flags.
	for _, want := range []string{"```text", "**Global flags:**", "`--endpoint-url string`", "`--zone string`", "`--json`"} {
		if !strings.Contains(first, want) {
			t.Fatalf("reference is missing %q", want)
		}
	}
	if !strings.Contains(first, "flareadm workers script settings update SCRIPT [flags]") {
		t.Fatalf("usage lines are missing:\n%s", head(first, 10))
	}
	// Local flags are rendered next to their command only.
	notifications := sectionOf(first, "## `flareadm notifications webhook create`")
	if !strings.Contains(notifications, "`--url string`") {
		t.Fatalf("local flags are missing from the section:\n%s", head(notifications, 20))
	}
	if strings.Contains(sectionOf(first, "## `flareadm zone list`"), "`--url string`") {
		t.Fatal("flags leaked between sections")
	}

	// The generator must not depend on the environment.
	t.Setenv("FLAREADM_API_TOKEN", "should-not-matter")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if after := generate(newRoot()); !bytes.Equal([]byte(after), []byte(first)) {
		t.Fatal("output depends on the environment")
	}
}

func head(s string, lines int) string {
	parts := strings.SplitN(s, "\n", lines+1)
	if len(parts) > lines {
		parts = parts[:lines]
	}
	return strings.Join(parts, "\n")
}

func sectionOf(doc, heading string) string {
	i := strings.Index(doc, heading)
	if i < 0 {
		return ""
	}
	rest := doc[i+len(heading):]
	if j := strings.Index(rest, "\n## `"); j >= 0 {
		return rest[:j]
	}
	return rest
}
