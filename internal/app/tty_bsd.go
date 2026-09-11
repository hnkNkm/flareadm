//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package app

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether f is a terminal, using the TIOCGETA ioctl the BSD
// family (including darwin) provides. See tty_linux.go for why
// os.ModeCharDevice is not sufficient.
func isTerminal(f *os.File) bool {
	var termios [128]byte
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCGETA),
		uintptr(unsafe.Pointer(&termios)),
		0, 0, 0,
	)
	return errno == 0
}
