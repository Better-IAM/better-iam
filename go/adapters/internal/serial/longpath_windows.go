//go:build windows

package serial

import (
	"path/filepath"
	"syscall"
)

// longPath expands Windows 8.3 short names (as Node's realpathSync.native does).
func longPath(path string) string {
	expand := func(target string) (string, bool) {
		source, err := syscall.UTF16PtrFromString(target)
		if err != nil {
			return "", false
		}
		buffer := make([]uint16, 1024)
		n, err := syscall.GetLongPathName(source, &buffer[0], uint32(len(buffer)))
		if err != nil || n == 0 || int(n) > len(buffer) {
			return "", false
		}
		return syscall.UTF16ToString(buffer[:n]), true
	}
	if long, ok := expand(path); ok {
		return long
	}
	if dir, ok := expand(filepath.Dir(path)); ok {
		return filepath.Join(dir, filepath.Base(path))
	}
	return path
}
