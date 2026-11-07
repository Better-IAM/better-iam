package server

// Port of packages/server/src/safe-fetch.ts: the SSRF guard for URLs that tenants control lives in go/auth (shared
// with the SCIM and OAuth packages); this file keeps the server's names.

import "github.com/Better-IAM/better-iam/go/auth"

type (
	// GuardedFetchOptions are the options of CreateGuardedFetch.
	GuardedFetchOptions = auth.GuardedFetchOptions
	// SafeFetchAddressOptions are the address rules of a guarded request.
	SafeFetchAddressOptions = auth.SafeFetchAddressOptions
	// SafeFetchFailureReason says which rule stopped a guarded fetch.
	SafeFetchFailureReason = auth.SafeFetchFailureReason
	// SafeFetchOptions are the limits of FetchJSONSafely.
	SafeFetchOptions = auth.SafeFetchOptions
	// SafeFetchError is a refused or failed guarded fetch.
	SafeFetchError = auth.SafeFetchError
)

var (
	// CheckFetchURL checks the URL rules of a guarded fetch.
	CheckFetchURL = auth.CheckFetchURL
	// CreateGuardedFetch returns a fetch under the SSRF rules.
	CreateGuardedFetch = auth.CreateGuardedFetch
	// FetchJSONSafely fetches a bounded JSON document under the SSRF rules.
	FetchJSONSafely = auth.FetchJSONSafely
	// IsPublicAddress is true for a globally routable unicast address.
	IsPublicAddress = auth.IsPublicAddress
)
