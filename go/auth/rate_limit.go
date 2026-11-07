package auth

// Port of packages/auth/src/rate-limit.ts.

import (
	"container/list"
	"context"
	"math"
	"strconv"
	"sync"

	"github.com/Better-IAM/better-iam/go/core"
)

// ResolvedRateLimits are the limits in force.
type ResolvedRateLimits struct {
	Attempts          int64
	SensitiveAttempts int64
	WindowMs          int64
	// IPAttempts per client IP per window across flows; 0 disables the check.
	IPAttempts int64
	Limiter    RateLimiter
}

// MemoryRateLimiterOptions configures CreateMemoryRateLimiter.
type MemoryRateLimiterOptions struct {
	// MaxKeys is the number of counters kept at most (default 100,000). Expired counters are dropped first; at the cap
	// with none expired, the oldest window is dropped (its counter starts over).
	MaxKeys *int64
}

type memoryCounter struct {
	key     string
	count   float64
	resetAt int64
}

type memoryRateLimiter struct {
	mu       sync.Mutex
	maxKeys  int64
	order    *list.List // oldest window first (Map insertion order)
	counters map[string]*list.Element
}

// CreateMemoryRateLimiter is an in-process limiter for single-instance deployments and tests. Counters are not
// shared between processes, and the map is bounded by MaxKeys.
func CreateMemoryRateLimiter(options MemoryRateLimiterOptions) (RateLimiter, error) {
	maxKeys := int64(100_000)
	if options.MaxKeys != nil {
		maxKeys = *options.MaxKeys
	}
	if maxKeys < 1 || maxKeys > 9007199254740991 {
		return nil, core.NewIamError("INVALID_CONFIG", "maxKeys must be a positive integer")
	}
	return &memoryRateLimiter{maxKeys: maxKeys, order: list.New(), counters: map[string]*list.Element{}}, nil
}

func (m *memoryRateLimiter) Consume(_ context.Context, input RateLimitInput) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Keys are attacker-chosen. A counter is (re)inserted whenever its window starts, so with one window length the
	// list runs oldest window first: pruning walks from the front and stops at the first live counter.
	for front := m.order.Front(); front != nil; front = m.order.Front() {
		entry := front.Value.(*memoryCounter)
		if entry.resetAt > input.Now {
			break
		}
		m.order.Remove(front)
		delete(m.counters, entry.key)
	}
	element, ok := m.counters[input.Key]
	var entry *memoryCounter
	if ok {
		entry = element.Value.(*memoryCounter)
	}
	if !ok || entry.resetAt <= input.Now {
		if ok {
			m.order.Remove(element)
			delete(m.counters, input.Key)
		}
		for int64(len(m.counters)) >= m.maxKeys {
			front := m.order.Front()
			m.order.Remove(front)
			delete(m.counters, front.Value.(*memoryCounter).key)
		}
		entry = &memoryCounter{key: input.Key, resetAt: input.Now + input.WindowMs}
		m.counters[input.Key] = m.order.PushBack(entry)
	}
	if entry.count >= input.Limit {
		return false, nil
	}
	entry.count++
	return true, nil
}

func (m *memoryRateLimiter) Reset(_ context.Context, key, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if element, ok := m.counters[key]; ok {
		m.order.Remove(element)
		delete(m.counters, key)
	}
	return nil
}

// A store limiter sweeps expired counters at most this often, in transactions of at most sweepBatch deletions.
const (
	sweepIntervalMs = 60_000
	sweepBatch      = 200
)

type storeRateLimiter struct {
	store     core.IamStore
	mu        sync.Mutex
	nextSweep float64
	sweeping  bool
	// wg tracks running sweeps (tests wait for them before closing the store).
	wg sync.WaitGroup
}

// CreateStoreRateLimiter is the default limiter: durable counters in the IAM database (authRateLimits), committed
// independently so rejected credentials cannot roll back their attempt.
func CreateStoreRateLimiter(store core.IamStore) RateLimiter {
	return &storeRateLimiter{store: store, nextSweep: math.Inf(-1)}
}

func (s *storeRateLimiter) sweep(now int64) {
	ctx := context.Background()
	records, err := s.store.Find(ctx, "authRateLimits", nil, nil)
	if err != nil {
		return
	}
	var expired []*core.Object
	for _, record := range records {
		if resetAt, ok := num(record, "resetAt"); ok && resetAt <= float64(now) {
			expired = append(expired, record)
		}
	}
	for start := 0; start < len(expired); start += sweepBatch {
		batch := expired[start:min(len(expired), start+sweepBatch)]
		err := s.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			for _, stale := range batch {
				id := str(stale, "id")
				current, err := tx.Get(ctx, "authRateLimits", id)
				if err != nil {
					return err
				}
				if current != nil {
					if resetAt, ok := num(current, "resetAt"); ok && resetAt <= float64(now) {
						if err := tx.Delete(ctx, "authRateLimits", id); err != nil {
							return err
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			// Housekeeping only: the next sweep (or the purge worker) retries.
			return
		}
	}
}

func (s *storeRateLimiter) Consume(ctx context.Context, input RateLimitInput) (bool, error) {
	permitted, err := core.Transact(ctx, s.store, func(ctx context.Context, tx core.IamStore) (bool, error) {
		existing, err := tx.Get(ctx, "authRateLimits", input.Key)
		if err != nil {
			return false, err
		}
		record := existing
		if existing == nil || !(numOr(existing, "resetAt", math.NaN()) > float64(input.Now)) {
			record = core.NewObject("id", input.Key, "tenantId", input.TenantID, "count", 0.0, "resetAt", float64(input.Now+input.WindowMs))
		}
		count := numOr(record, "count", math.NaN())
		if count >= input.Limit {
			return false, nil
		}
		record.Set("count", count+1)
		if existing != nil {
			_, err = tx.Put(ctx, "authRateLimits", record)
		} else {
			_, err = tx.Insert(ctx, "authRateLimits", record)
		}
		return err == nil, err
	})
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	if !s.sweeping && float64(input.Now) >= s.nextSweep {
		s.sweeping = true
		s.nextSweep = float64(input.Now + sweepIntervalMs)
		s.wg.Add(1)
		go func(now int64) {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				s.sweeping = false
				s.mu.Unlock()
			}()
			s.sweep(now)
		}(input.Now)
	}
	s.mu.Unlock()
	return permitted, nil
}

func (s *storeRateLimiter) Reset(ctx context.Context, key, _ string) error {
	return s.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		existing, err := tx.Get(ctx, "authRateLimits", key)
		if err != nil || existing == nil {
			return err
		}
		return tx.Delete(ctx, "authRateLimits", key)
	})
}

// settle waits for running sweeps.
func (s *storeRateLimiter) settle() { s.wg.Wait() }

// ResolveRateLimits applies the defaults and bounds.
func ResolveRateLimits(options *RateLimitOptions, store core.IamStore) (ResolvedRateLimits, error) {
	limits := RateLimitOptions{}
	if options != nil {
		limits = *options
	}
	value := func(v *int64, fallback int64) int64 {
		if v == nil {
			return fallback
		}
		return *v
	}
	resolved := ResolvedRateLimits{
		Attempts:          value(limits.Attempts, 10),
		SensitiveAttempts: value(limits.SensitiveAttempts, 5),
		WindowMs:          value(limits.WindowMs, 15*60_000),
		IPAttempts:        value(limits.IPAttempts, 0),
		Limiter:           limits.Limiter,
	}
	if resolved.Limiter == nil {
		resolved.Limiter = CreateStoreRateLimiter(store)
	}
	bounds := []struct {
		name          string
		value         int64
		lower, higher int64
	}{
		{"attempts", resolved.Attempts, 1, 100_000},
		{"sensitiveAttempts", resolved.SensitiveAttempts, 1, 100_000},
		{"windowMs", resolved.WindowMs, 1_000, 24 * 60 * 60_000},
		{"ipAttempts", resolved.IPAttempts, 0, 1_000_000},
	}
	for _, bound := range bounds {
		if bound.value < bound.lower || bound.value > bound.higher {
			return ResolvedRateLimits{}, core.NewIamError("INVALID_CONFIG", "rateLimits."+bound.name+" must be an integer between "+
				strconv.FormatInt(bound.lower, 10)+" and "+strconv.FormatInt(bound.higher, 10))
		}
	}
	return resolved, nil
}
