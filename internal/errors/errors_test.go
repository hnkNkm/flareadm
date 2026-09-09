package errors

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestExitCodesStable(t *testing.T) {
	codes := map[int]string{
		0: "Success",
		1: "Unclassified failure",
		2: "Invalid CLI usage or input",
		3: "Authentication failure",
		4: "Permission denied",
		5: "Resource not found",
		6: "Conflict / invalid resource state",
		7: "Rate-limit failure after retries",
		8: "Network / timeout failure",
		9: "Partial failure in a multi-resource operation",
	}
	if CodeSuccess != 0 || CodeInvalid != 2 || CodeAuth != 3 || CodePermission != 4 ||
		CodeNotFound != 5 || CodeConflict != 6 || CodeRateLimit != 7 || CodeNetwork != 8 ||
		CodePartial != 9 || CodeUnclassified != 1 {
		t.Fatal("exit code constants out of contract")
	}
	if len(codes) != 10 {
		t.Fatal("contract must map codes 0..9")
	}
}

func TestAPIFailureMapping(t *testing.T) {
	cases := []struct {
		status int
		code   int64
		want   int
	}{
		{400, 1000, CodeAuth}, // invalid API token
		{401, 1000, CodeAuth},
		{403, 0, CodePermission},
		{404, 0, CodeNotFound},
		{409, 0, CodeConflict},
		{429, 0, CodeRateLimit},
		{408, 0, CodeNetwork},
		{400, 1004, CodeInvalid},
		{500, 0, CodeUnclassified},
		{503, 0, CodeUnclassified},
		{405, 0, CodeUnclassified},
	}
	for _, tc := range cases {
		err := FromAPIFailure(tc.status, tc.code, "boom", "GET", "/zones")
		if got := CodeOf(err); got != tc.want {
			t.Errorf("status %d code %d: exit %d, want %d (%s)", tc.status, tc.code, got, tc.want, err.Error())
		}
	}
}

func TestFromAPIFailureMessage(t *testing.T) {
	err := FromAPIFailure(404, 7000, "Could not route to /zones/xyz", "GET", "/zones/xyz")
	msg := err.Error()
	if !strings.Contains(msg, "GET /zones/xyz") || !strings.Contains(msg, "404") || !strings.Contains(msg, "7000") {
		t.Fatalf("message lacks context: %q", msg)
	}
}

func TestFromTransportMapping(t *testing.T) {
	timeout := &net.DNSError{IsTimeout: true}
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"url timeout", &url.Error{Op: "Get", URL: "https://x", Err: timeout}, CodeNetwork},
		{"net timeout", timeout, CodeNetwork},
		{"deadline", context.DeadlineExceeded, CodeNetwork},
		{"refused", &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")}, CodeNetwork},
		{"other", fmt.Errorf("boom"), CodeUnclassified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CodeOf(FromTransport(tc.err)); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWrapUnwrapAndCodeOf(t *testing.T) {
	base := fmt.Errorf("root cause")
	err := Wrap(CodeNotFound, "zone missing", base)
	if !errors.Is(err, base) {
		t.Fatal("Wrap should preserve unwrapping")
	}
	if CodeOf(err) != CodeNotFound {
		t.Fatal("CodeOf should find the wrapped code")
	}
	// Non-ExitError wraps should surface the exit code through errors.As too.
	var ee *ExitError
	if !errors.As(Wrap(CodeNetwork, "x", fmt.Errorf("y")), &ee) {
		t.Fatal("errors.As must find ExitError")
	}
}

func TestUsage(t *testing.T) {
	if CodeOf(Usage("bad %s", "input")) != CodeInvalid {
		t.Fatal("Usage must map to exit 2")
	}
}
