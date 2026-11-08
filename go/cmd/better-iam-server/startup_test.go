package main

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// A configuration with the better-iam CLI's "cli" member is refused with TypeScript's exact error line, and the
// server adds a hint line after it; other refusals stay one line.
func TestStartupErrorHintsAtTheCliMember(t *testing.T) {
	application := &app{clock: &clocks{}, state: &state{}}
	_, err := application.start([]byte(`{"secret":"startup-test-secret-with-at-least-32-characters","baseURL":"http://localhost:3000","cli":{"defaults":{}}}`), false)
	if err == nil {
		t.Fatal("the cli member must be refused")
	}
	lines := strings.Split(startupError(err), "\n")
	if len(lines) != 2 || lines[0] != `{"error":{"code":"INVALID_CONFIG","status":400,"message":"Invalid better-iam.json: unknown member \"cli\""}}` || lines[1] != cliMemberHint {
		t.Fatalf("startup error %q", lines)
	}
	_, err = application.start([]byte(`{"secret":"startup-test-secret-with-at-least-32-characters","baseURL":"http://localhost:3000","nope":1}`), false)
	if got := startupError(err); got != `{"error":{"code":"INVALID_CONFIG","status":400,"message":"Invalid better-iam.json: unknown member \"nope\""}}` {
		t.Fatalf("startup error %q", got)
	}
	if got := startupError(core.NewIamError("INVALID_CONFIG", "Invalid basePath")); strings.Contains(got, "\n") {
		t.Fatalf("startup error %q", got)
	}
}
