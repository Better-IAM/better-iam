//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"syscall"
)

// trustworthy reports whether a found configuration may be loaded without being named: on POSIX systems, a file
// another user owns, or one in a directory anyone may write to (such as /tmp), could have been planted there.
func trustworthy(candidate string) bool {
	uid := uint32(os.Getuid())
	file, err := os.Stat(candidate)
	if err != nil {
		return false
	}
	directory, err := os.Stat(filepath.Dir(candidate))
	if err != nil {
		return false
	}
	stat, ok := file.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return (stat.Uid == uid || stat.Uid == 0) && directory.Mode().Perm()&0o002 == 0
}
