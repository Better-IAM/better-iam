//go:build windows

package cli

import "golang.org/x/sys/windows"

// isTerminal reports whether fd is a console.
func isTerminal(fd uintptr) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}

// withoutEcho turns the console's echo off (line input stays on) and returns how to restore it.
func withoutEcho(fd uintptr) (func(), error) {
	var mode uint32
	if err := windows.GetConsoleMode(windows.Handle(fd), &mode); err != nil {
		return nil, err
	}
	quiet := (mode &^ windows.ENABLE_ECHO_INPUT) | windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_LINE_INPUT
	if err := windows.SetConsoleMode(windows.Handle(fd), quiet); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(windows.Handle(fd), mode) }, nil
}
