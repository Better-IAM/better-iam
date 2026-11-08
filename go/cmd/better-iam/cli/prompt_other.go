//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package cli

import "errors"

// isTerminal: terminals are not detected on this platform, so the CLI runs non-interactively (no prompts).
func isTerminal(fd uintptr) bool { return false }

func withoutEcho(fd uintptr) (func(), error) {
	return nil, errors.New("hidden prompts are not supported on this platform")
}
