//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package cli

import "golang.org/x/sys/unix"

// isTerminal reports whether fd is a terminal.
func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), ioctlGetTermios)
	return err == nil
}

// withoutEcho turns the terminal's echo off (line editing stays on) and returns how to restore it.
func withoutEcho(fd uintptr) (func(), error) {
	state, err := unix.IoctlGetTermios(int(fd), ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	quiet := *state
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(int(fd), ioctlSetTermios, &quiet); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(int(fd), ioctlSetTermios, state) }, nil
}
