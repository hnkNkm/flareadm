//go:build linux

package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"
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

// TestIsTerminalDetection covers the four stdin shapes the login flow has to
// tell apart: a real terminal, a pipe, /dev/null and a regular file. The old
// os.ModeCharDevice check passed /dev/null, which made `auth login </dev/null`
// stall until the timeout.
func TestIsTerminalDetection(t *testing.T) {
	_, slave := openPTY(t)
	if !isTerminal(slave) {
		t.Fatal("a pty slave must be a terminal")
	}

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = read.Close(); _ = write.Close() }()
	if isTerminal(read) {
		t.Fatal("a pipe must not be a terminal")
	}

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	if isTerminal(devNull) {
		t.Fatal("/dev/null must not be a terminal")
	}

	file, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString("not a terminal\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if isTerminal(file) {
		t.Fatal("a regular file must not be a terminal")
	}

	// A closed descriptor fails the ioctl and is therefore not a terminal.
	closed, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	if isTerminal(closed) {
		t.Fatal("a closed file must not be a terminal")
	}

	// Non-file readers are never terminals, and the runtime contract exposes
	// the same answer.
	if readerIsTerminal(strings.NewReader("")) {
		t.Fatal("a non-file reader must not be a terminal")
	}
	if rt := NewRuntime(strings.NewReader(""), io.Discard, io.Discard); rt.StdinTTY() {
		t.Fatal("a runtime built on a buffer must not report an interactive stdin")
	}
	if rt := NewRuntime(slave, io.Discard, io.Discard); !rt.StdinTTY() {
		t.Fatal("a runtime built on a pty must report an interactive stdin")
	}
}
