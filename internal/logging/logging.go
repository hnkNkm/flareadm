// Package logging provides the stderr diagnostics stream used for --verbose
// (informational) and --debug (request-level detail) output. All lines are
// scrubbed of the resolved API token and of Authorization header content, so
// credentials can never reach the log stream.
package logging

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hnkNkm/flareadm/internal/auth"
)

// Logger writes informational and debug diagnostics to an io.Writer
// (typically stderr). Machine output never passes through the Logger.
type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	token   string
	secrets []string
	verbose bool
	debug   bool
}

// New creates a Logger. token (may be empty) is scrubbed from every line.
func New(w io.Writer, token string, verbose, debug bool) *Logger {
	return &Logger{w: w, token: token, verbose: verbose, debug: debug}
}

// Enabled reports whether verbose output is enabled.
func (l *Logger) Enabled() bool { return l != nil && l.verbose }

// DebugEnabled reports whether debug output is enabled.
func (l *Logger) DebugEnabled() bool { return l != nil && l.debug }

// AddSecret registers additional sensitive material (for example an
// uploaded private key) to be scrubbed from every log line.
func (l *Logger) AddSecret(secret string) {
	if l == nil || secret == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.secrets {
		if existing == secret {
			return
		}
	}
	l.secrets = append(l.secrets, secret)
}

// SetToken updates the token scrubbed from log lines (the token is only
// known after credential resolution).
func (l *Logger) SetToken(token string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.token = token
}

// Infof logs an informational line (shown with --verbose).
func (l *Logger) Infof(format string, args ...any) {
	if l == nil || !l.verbose {
		return
	}
	l.write("info", format, args...)
}

// Debugf logs a debug line (shown with --debug).
func (l *Logger) Debugf(format string, args ...any) {
	if l == nil || !l.debug {
		return
	}
	l.write("debug", format, args...)
}

func (l *Logger) write(level, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	line = auth.Redact(line, l.token)
	for _, secret := range l.secrets {
		line = auth.Redact(line, secret)
	}
	line = auth.RedactPEMBlocks(line)
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	_, _ = fmt.Fprintf(l.w, "flareadm: %s %s: %s\n", ts, level, strings.TrimRight(line, "\n"))
}
