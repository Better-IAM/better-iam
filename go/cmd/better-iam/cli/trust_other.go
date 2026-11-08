//go:build !unix

package cli

// trustworthy: without POSIX ownership (Windows), every found configuration is usable, as in the TypeScript CLI
// (process.getuid is undefined there).
func trustworthy(candidate string) bool { return true }
