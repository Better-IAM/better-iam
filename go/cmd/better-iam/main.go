// Command better-iam is the better-iam command line: migrations, bootstrap, scheduled jobs, audit and storage
// operations, diagnostics, configuration as code, the API caller and saved sessions (port of @better-iam/cli).
//
//	better-iam help
//	better-iam migrate --config better-iam.json
//
// The commands live in package github.com/Better-IAM/better-iam/go/cmd/better-iam/cli.
package main

import "github.com/Better-IAM/better-iam/go/cmd/better-iam/cli"

func main() { cli.RunBinary(nil) }
