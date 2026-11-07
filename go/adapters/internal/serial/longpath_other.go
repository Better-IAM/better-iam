//go:build !windows

package serial

func longPath(path string) string { return path }
