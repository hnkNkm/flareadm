//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package app

import "os"

// isTerminal falls back to the character-device heuristic on platforms without
// a dedicated implementation. This is weaker than an ioctl (character devices
// such as /dev/null are not terminals), so it is deliberately limited to
// platforms this project does not support releases for; adding a platform means
// adding a real check here.
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
