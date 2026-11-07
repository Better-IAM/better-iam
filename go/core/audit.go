package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Tamper-evident audit log: every tenant's audit events form a hash chain. Each event carries its position
// (`sequence`), the hash of the previous event (`previousHash`), and its own hash over the canonical JSON of the event
// body. The chain head per tenant lives in `auditChains`.

// AuditChainHead is a record of `auditChains` (id = tenantId).
type AuditChainHead struct {
	StoredRecord
	Sequence  float64 `json:"sequence"`
	Hash      string  `json:"hash"`
	UpdatedAt float64 `json:"updatedAt"`
}

// AuditChainFailure is sequence-gap, previous-hash-mismatch, hash-mismatch, head-mismatch, missing-prefix or
// unchained.
type AuditChainFailure = string

// AuditChainFailureInfo locates the first failure of a verification.
type AuditChainFailureInfo struct {
	Sequence float64           `json:"sequence"`
	ID       string            `json:"id"`
	Reason   AuditChainFailure `json:"reason"`
}

// AuditChainVerification is the result of VerifyAuditChain.
type AuditChainVerification struct {
	Valid bool `json:"valid"`
	// Checked counts the chained events that were checked.
	Checked int `json:"checked"`
	// Unchained counts events without chain fields.
	Unchained int                    `json:"unchained"`
	First     *float64               `json:"first,omitempty"`
	Last      *float64               `json:"last,omitempty"`
	LastHash  *string                `json:"lastHash,omitempty"`
	Failure   *AuditChainFailureInfo `json:"failure,omitempty"`
}

// AuditGenesis is the previousHash of the first event of every chain.
var AuditGenesis = strings.Repeat("0", 64)

// NowMillis is the current time in epoch milliseconds (Date.now()).
func NowMillis() int64 { return time.Now().UnixMilli() }

// CanonicalJSON is deterministic JSON (audit hashes, receipts): JSON.stringify with every plain object rebuilt with
// its keys sorted by `<` (UTF-16 code units) and Undefined members removed. Because it rebuilds JavaScript objects,
// integer-like keys still come first in ascending numeric order. Arrays keep their order. The second result is false
// when the value has no JSON form.
func CanonicalJSON(value any) string {
	text, _, _ := Stringify(canonicalValue(value))
	return text
}

func canonicalValue(value any) any {
	switch v := value.(type) {
	case *Object:
		if v == nil {
			return v
		}
		out := NewObject()
		for _, key := range sortedUTF16(v.keys) {
			item := v.values[key]
			if IsUndefined(item) {
				continue
			}
			out.SetRaw(key, canonicalValue(item))
		}
		return out
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = canonicalValue(item)
		}
		return out
	}
	return value
}

func sha256Hex(input string) string {
	digest := sha256.Sum256([]byte(input))
	return hex.EncodeToString(digest[:])
}

// AuditEventHash is SHA-256 (lowercase hex) over the canonical JSON of every field of the event except `hash`.
func AuditEventHash(event *Object) string {
	body := event.Spread()
	body.Delete("hash")
	return sha256Hex(CanonicalJSON(body))
}

// ChainAuditEvent assigns the next chain position to an event and advances the tenant's chain head. The caller
// stores the returned event; AppendAuditEvent does both. Must run inside the transaction that records the event.
func ChainAuditEvent(ctx context.Context, tx IamStore, event *Object) (*Object, error) {
	tenantID, _ := event.Get("tenantId").(string)
	head, err := tx.Get(ctx, "auditChains", tenantID)
	if err != nil {
		return nil, err
	}
	sequence := 1.0
	previousHash := AuditGenesis
	if head != nil {
		if headSequence, ok := head.Get("sequence").(float64); ok {
			sequence = headSequence + 1
		}
		if headHash, ok := head.Get("hash").(string); ok {
			previousHash = headHash
		}
	}
	chained := event.Spread(NewObject("sequence", sequence, "previousHash", previousHash))
	hash := AuditEventHash(chained)
	chained.Set("hash", hash)
	next := NewObject("id", tenantID, "tenantId", tenantID, "sequence", sequence, "hash", hash, "updatedAt", event.Get("timestamp"))
	if head != nil {
		_, err = tx.Put(ctx, "auditChains", next)
	} else {
		_, err = tx.Insert(ctx, "auditChains", next)
	}
	if err != nil {
		return nil, err
	}
	return chained, nil
}

// AppendAuditEvent records an audit event at the end of its tenant's chain. Every audit insert must go through here.
func AppendAuditEvent(ctx context.Context, tx IamStore, event *Object) (*Object, error) {
	chained, err := ChainAuditEvent(ctx, tx, event)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Insert(ctx, "audit", chained); err != nil {
		return nil, err
	}
	return chained, nil
}

// AuditChainHeadRef is the head a whole chain must end at.
type AuditChainHeadRef struct {
	Sequence float64
	Hash     string
}

// VerifyAuditChainOptions are VerifyAuditChain's options.
type VerifyAuditChainOptions struct {
	// PreviousHash is the previousHash of the first event of a run that starts mid-chain (nil: unset).
	PreviousHash *string
	// Head: the events are the tenant's whole stored chain.
	Head *AuditChainHeadRef
}

// VerifyAuditChain verifies a run of events from one tenant: contiguous sequences, each previousHash equal to the
// previous event's hash, and every hash recomputable. Events are sorted by sequence first. With Head, the events are
// the tenant's whole stored chain: it must end at the head, start at sequence 1 or right after an audit:prune
// checkpoint recorded inside it, and hold no unchained events.
func VerifyAuditChain(events []*Object, options VerifyAuditChainOptions) AuditChainVerification {
	var chained []*Object
	for _, event := range events {
		if _, ok := event.Get("sequence").(float64); ok {
			chained = append(chained, event)
		}
	}
	sequenceOf := func(event *Object) float64 {
		value, _ := event.Get("sequence").(float64)
		return value
	}
	sort.SliceStable(chained, func(i, j int) bool { return sequenceOf(chained[i]) < sequenceOf(chained[j]) })
	result := AuditChainVerification{Valid: true, Unchained: len(events) - len(chained)}
	var expectedPrevious any = Undefined
	if options.PreviousHash != nil {
		expectedPrevious = *options.PreviousHash
	}
	started := false
	var expectedSequence float64
	for _, event := range chained {
		sequence := sequenceOf(event)
		if !started {
			started = true
			expectedSequence = sequence
			if IsUndefined(expectedPrevious) || expectedPrevious == nil {
				if sequence == 1 {
					expectedPrevious = AuditGenesis
				} else {
					expectedPrevious = event.Get("previousHash")
				}
			}
			first := sequence
			result.First = &first
		}
		fail := func(reason AuditChainFailure) AuditChainVerification {
			result.Valid = false
			result.Failure = &AuditChainFailureInfo{Sequence: sequence, ID: recordID(event), Reason: reason}
			return result
		}
		if sequence != expectedSequence {
			return fail("sequence-gap")
		}
		if !strictEquals(event.Get("previousHash"), expectedPrevious) {
			return fail("previous-hash-mismatch")
		}
		hash := event.Get("hash")
		if !strictEquals(any(AuditEventHash(event)), hash) {
			return fail("hash-mismatch")
		}
		result.Checked++
		last := sequence
		result.Last = &last
		lastHash, _ := hash.(string)
		result.LastHash = &lastHash
		expectedPrevious = hash
		expectedSequence = sequence + 1
	}
	head := options.Head
	if head == nil {
		return result
	}
	fail := func(sequence float64, id string, reason AuditChainFailure) AuditChainVerification {
		result.Valid = false
		result.Failure = &AuditChainFailureInfo{Sequence: sequence, ID: id, Reason: reason}
		return result
	}
	if result.Last == nil || head.Sequence != *result.Last || head.Hash != *result.LastHash {
		sequence := head.Sequence
		if result.Last != nil {
			sequence = *result.Last
		}
		id := ""
		if len(chained) > 0 {
			id = recordID(chained[len(chained)-1])
		}
		return fail(sequence, id, "head-mismatch")
	}
	start := chained[0]
	startSequence := sequenceOf(start)
	if startSequence > 1 {
		covered := false
		for _, event := range chained {
			if action, _ := event.Get("action").(string); action != "audit:prune" {
				continue
			}
			metadata, ok := event.Get("metadata").(*Object)
			if !ok || metadata == nil {
				continue
			}
			if strictEquals(metadata.Get("prunedThroughSequence"), startSequence-1) && strictEquals(metadata.Get("prunedThroughHash"), start.Get("previousHash")) {
				covered = true
				break
			}
		}
		if !covered {
			return fail(startSequence, recordID(start), "missing-prefix")
		}
	}
	for _, event := range events {
		if _, ok := event.Get("sequence").(float64); !ok {
			return fail(0, recordID(event), "unchained")
		}
	}
	return result
}
