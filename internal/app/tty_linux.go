//go:build linux

package app

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether f is a terminal.
//
// It performs the TCGETS ioctl on the file descriptor: only a real terminal
// answers it. os.ModeCharDevice cannot be used for this, because /dev/null and
// other character devices are not terminals (which made a cron job with stdin
// on /dev/null look interactive).
//
// The termios buffer is intentionally an opaque byte array: the ioctl only
// distinguishes success from failure, so the struct layout does not matter.
func isTerminal(f *os.File) bool {
	var termios [128]byte
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&termios)),
		0, 0, 0,
	)
	return errno == 0
}
