//go:build linux

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// ioctl runs one ioctl call and reports the errno.
func ioctl(fd uintptr, request uintptr, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

// openPTY returns a connected pty pair, or skips the test when the kernel has no
// pty support available to this process.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("pty unavailable: %v", err)
	}
	var unlock int32
	if err := ioctl(master.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); err != nil {
		_ = master.Close()
		t.Skipf("pty unlock failed: %v", err)
	}
	var number uint32
	if err := ioctl(master.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number))); err != nil {
		_ = master.Close()
		t.Skipf("pty number lookup failed: %v", err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR, 0)
	if err != nil {
		_ = master.Close()
		t.Skipf("pty slave unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	return master, slave
}

// runCLIWithStdin is runCLI with an explicit stdin reader, so tests can drive
// the terminal detection with real descriptors. The isolated config directory is
// returned so callers can assert that nothing was persisted.
func runCLIWithStdin(t *testing.T, stdin io.Reader, args ...string) (cliResult, string) {
	t.Helper()
	home := newHome(t)
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, stdin, &stdout, &stderr)
	return cliResult{code: code, stdout: stdout.String(), stderr: stderr.String()}, home
}

// TestAuthLoginTerminalDetection is the regression harness for the login
// interactivity gate: only a real terminal may start the browser login, every
// other stdin must fail fast with exit 2, name both escape hatches, and never
// open a listener.
func TestAuthLoginTerminalDetection(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	t.Setenv("BROWSER", "definitely-not-a-real-browser-xyz")

	regular, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = regular.Close() }()
	if _, err := regular.WriteString("data\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := regular.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pipeRead.Close(); _ = pipeWrite.Close() }()
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	closed, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()

	cases := []struct {
		name  string
		stdin io.Reader
	}{
		{"dev-null", devNull},
		{"pipe", pipeRead},
		{"regular-file", regular},
		{"closed", closed},
		{"buffer", strings.NewReader("")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, home := runCLIWithStdin(t, tc.stdin, "auth", "login", "--client-id", "cli-client")
			if res.code != errors.CodeInvalid {
				t.Fatalf("code=%d, want 2 (stdout=%q stderr=%q)", res.code, res.stdout, res.stderr)
			}
			for _, want := range []string{"--no-browser", "FLAREADM_API_TOKEN"} {
				if !strings.Contains(res.stderr, want) {
					t.Fatalf("stderr must mention %s: %q", want, res.stderr)
				}
			}
			if strings.Contains(res.stdout, "http") {
				t.Fatalf("no authorize URL may be printed: %q", res.stdout)
			}
			stub.mu.Lock()
			forms := len(stub.forms)
			stub.mu.Unlock()
			if forms != 0 {
				t.Fatalf("no token request may happen, saw %d", forms)
			}
			if entries, err := os.ReadDir(home); err == nil {
				for _, entry := range entries {
					if strings.Contains(entry.Name(), "login") || strings.Contains(entry.Name(), "state") {
						t.Fatalf("the login never started, so it must not persist %q", entry.Name())
					}
				}
			}
		})
	}

	// A real terminal (pty) must pass the gate: the login then reaches the
	// browser handoff and times out waiting for the callback instead of
	// failing the interactivity check.
	t.Run("pty", func(t *testing.T) {
		_, slave := openPTY(t)
		res, _ := runCLIWithStdin(t, slave, "auth", "login",
			"--client-id", "cli-client", "--timeout", "500ms")
		if res.code != errors.CodeNetwork {
			t.Fatalf("code=%d, want 8 (stdout=%q stderr=%q)", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "could not open a browser automatically") {
			t.Fatalf("the pty run must reach the browser handoff: %q", res.stdout)
		}
		if lines := countURLLines(res.stdout); lines != 1 {
			t.Fatalf("the authorize URL must be printed exactly once, got %d: %q", lines, res.stdout)
		}
		if !strings.Contains(res.stderr, "timed out") {
			t.Fatalf("the pty run must wait for the callback: %q", res.stderr)
		}
	})
}

// TestAuthLoginTerminalDetectionIsQuick guards the reported defect directly: a
// cron job with stdin on /dev/null must not stall for the timeout.
func TestAuthLoginTerminalDetectionIsQuick(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()

	start := time.Now()
	res, _ := runCLIWithStdin(t, devNull, "auth", "login",
		"--client-id", "cli-client", "--timeout", "30s")
	elapsed := time.Since(start)
	if res.code != errors.CodeInvalid {
		t.Fatalf("code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the /dev/null login must fail fast, took %s", elapsed)
	}
}
