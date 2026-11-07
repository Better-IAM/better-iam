package server

// Port of packages/server/src/client-info.ts.

import (
	"net/http"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// headerGet is Headers#get: every value of the header joined with ", ", or "" when absent.
func headerGet(headers http.Header, name string) (string, bool) {
	values := headers.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ", "), true
}

// ClientFromRequest is the client details Better IAM records for a request: http.clientInfo(request) when the
// deployment supplies it (IP behind a trusted proxy, user agent, label), otherwise the User-Agent header only.
// Nothing here is trusted for authorization; the result feeds auth.WithClient.
func ClientFromRequest(options *BetterIamOptions, request *http.Request) *core.SessionClientInfo {
	if options != nil && options.HTTP != nil && options.HTTP.ClientInfo != nil {
		return options.HTTP.ClientInfo(request)
	}
	if userAgent, _ := headerGet(request.Header, "user-agent"); userAgent != "" {
		return &core.SessionClientInfo{UserAgent: userAgent}
	}
	return nil
}

// ClientFromHeaders is the same, for callers that only have the incoming request's headers (framework integrations
// passing { headers } as the credential). Returns nil when there are no headers to read or clientInfo fails.
func ClientFromHeaders(options *BetterIamOptions, headers http.Header, baseURL string) (client *core.SessionClientInfo) {
	if headers == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			client = nil
		}
	}()
	request, err := http.NewRequest(http.MethodGet, baseURL, nil)
	if err != nil {
		return nil
	}
	request.Header = headers.Clone()
	return ClientFromRequest(options, request)
}
