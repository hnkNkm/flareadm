// Package errors implements FlareADM's stable exit-code contract and the
// error types that carry exit codes from the deepest layers to the CLI
// boundary.
//
// The mapping below is the single source of truth for exit codes:
//
//	0  Success
//	1  Unclassified failure
//	2  Invalid CLI usage or input
//	3  Authentication failure
//	4  Permission denied
//	5  Resource not found
//	6  Conflict / invalid resource state
//	7  Rate-limit failure after retries
//	8  Network / timeout failure
//	9  Partial failure in a multi-resource operation
package errors

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Exit codes (stable public contract, see docs/cli.md).
const (
	CodeSuccess      = 0
	CodeUnclassified = 1
	CodeInvalid      = 2
	CodeAuth         = 3
	CodePermission   = 4
	CodeNotFound     = 5
	CodeConflict     = 6
	CodeRateLimit    = 7
	CodeNetwork      = 8
	CodePartial      = 9
)

// ExitError is an error carrying a stable FlareADM exit code.
type ExitError struct {
	Code int
	Msg  string
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *ExitError) Unwrap() error { return e.Err }

// New builds an ExitError with a formatted message.
func New(code int, format string, args ...any) *ExitError {
	return &ExitError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Wrap builds an ExitError around an underlying error.
func Wrap(code int, msg string, err error) *ExitError {
	return &ExitError{Code: code, Msg: msg, Err: err}
}

// CodeOf extracts the exit code carried by err. Unknown errors are treated as
// an unclassified failure (1) so the CLI never crashes with a raw stack.
func CodeOf(err error) int {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return CodeUnclassified
}

// Is reports whether err carries the given exit code.
func Is(err error, code int) bool {
	return CodeOf(err) == code
}

// Usage is shorthand for an invalid-usage/invalid-input error (exit 2).
func Usage(format string, args ...any) *ExitError {
	return New(CodeInvalid, format, args...)
}

// ---- Mapping of API and transport failures ------------------------------

// APIStatus maps an HTTP status code onto an exit code. Cloudflare error
// payloads may additionally carry an application error code (see
// FromAPIFailure) which takes precedence for ambiguous statuses such as 400.
func APIStatus(status int) int {
	switch status {
	case 401:
		return CodeAuth
	case 403:
		return CodePermission
	case 404:
		return CodeNotFound
	case 409:
		return CodeConflict
	case 429:
		return CodeRateLimit
	case 408:
		return CodeNetwork
	case 400:
		// 400 is ambiguous: Cloudflare reports invalid API tokens as
		// HTTP 400 with application error code 1000. Callers detect that
		// case (Code 1000) before falling back here.
		return CodeInvalid
	default:
		return CodeUnclassified
	}
}

// APIErrorCodeAuth is Cloudflare's "authentication error" application code.
// It is returned as HTTP 400 (and sometimes 401) when an API token is
// invalid or missing.
const APIErrorCodeAuth = 1000

// FromAPIFailure maps a Cloudflare API failure (HTTP status plus the first
// application error code/message reported in the body) to an ExitError.
func FromAPIFailure(status int, cfCode int64, message string, method, path string) *ExitError {
	code := APIStatus(status)
	if status == 400 && cfCode == APIErrorCodeAuth {
		code = CodeAuth
	}
	detail := message
	if cfCode != 0 && !strings.Contains(message, fmt.Sprintf("(%d)", cfCode)) {
		detail = fmt.Sprintf("%s (code %d)", message, cfCode)
	}
	verb := fmt.Sprintf("%s %s", method, path)
	switch {
	case detail == "":
		detail = fmt.Sprintf("HTTP %d %s", status, httpText(status))
	case status != 0:
		detail = fmt.Sprintf("HTTP %d %s: %s", status, httpText(status), detail)
	}
	msg := fmt.Sprintf("%s failed: %s", verb, detail)
	return &ExitError{Code: code, Msg: msg}
}

// FromTransport maps transport-level failures (connection errors, timeouts,
// DNS failures) to exit code 8. Context cancellation caused by an explicit
// deadline is reported as a network/timeout failure.
func FromTransport(err error) error {
	if err == nil {
		return nil
	}
	if isTimeout(err) {
		return Wrap(CodeNetwork, "request timed out", err)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		if isTimeout(ue.Err) {
			return Wrap(CodeNetwork, "request timed out", err)
		}
		if errors.Is(ue.Err, context.DeadlineExceeded) {
			return Wrap(CodeNetwork, "request timed out", err)
		}
		if _, ok := ue.Err.(net.Error); ok {
			return Wrap(CodeNetwork, "network error", err)
		}
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return Wrap(CodeNetwork, "network error", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Wrap(CodeNetwork, "operation timed out", err)
	}
	if errors.Is(err, context.Canceled) {
		return Wrap(CodeNetwork, "operation canceled", err)
	}
	return &ExitError{Code: CodeUnclassified, Msg: "request failed", Err: err}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func httpText(status int) string {
	switch status {
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 408:
		return "Request Timeout"
	case 409:
		return "Conflict"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	}
	return ""
}
