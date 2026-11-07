package server

// Port of packages/server/src/usage.ts: access usage tracking. Allowed authorize/authorizeMany checks and allowed
// provisioning operations are counted in memory and written in batches, so the hot path never touches storage.

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// UsageRecorder is usage.ts UsageRecorder.
type UsageRecorder interface {
	Enabled() bool
	// Record counts one allowed use; a no-op when tracking is off.
	Record(tenantID, identityID, action string)
	// Flush writes everything buffered; concurrent calls share one write at a time.
	Flush(ctx context.Context) (written int, err error)
	// Stop stops the periodic writer (buffered usage stays until the next Flush).
	Stop()
}

// UsageRecordID is the ID of an accessUsage record: `{tenantId}:{identityId}:{action}`.
func UsageRecordID(tenantID, identityID, action string) string {
	return tenantID + ":" + identityID + ":" + action
}

type pendingUsage struct {
	tenantID, identityID, action string
	first, last                  int64
	count                        float64
}

// usageBuffer is a Map keyed by the JSON array of (tenant, identity, action), in insertion order.
type usageBuffer struct {
	keys    []string
	entries map[string]*pendingUsage
}

func newUsageBuffer() *usageBuffer { return &usageBuffer{entries: map[string]*pendingUsage{}} }

func (b *usageBuffer) size() int { return len(b.keys) }

func (b *usageBuffer) set(key string, entry *pendingUsage) {
	if _, ok := b.entries[key]; !ok {
		b.keys = append(b.keys, key)
	}
	b.entries[key] = entry
}

type usageRecorder struct {
	server      *ServerContext
	enabled     bool
	interval    int64
	maxBuffered int

	mu          sync.Mutex
	buffer      *usageBuffer
	writing     chan struct{}
	scheduled   bool
	lastFailure int64
	stop        chan struct{}
	stopOnce    sync.Once
}

// CreateUsageRecorder builds the recorder from options.accessUsage (createUsageRecorder).
func CreateUsageRecorder(server *ServerContext) UsageRecorder {
	setting := server.Options.AccessUsage
	enabled := setting.IsOn()
	var options AccessUsageOptions
	if setting != nil && setting.Options != nil {
		options = *setting.Options
	}
	interval := 60_000.0
	if options.FlushIntervalMs != nil {
		interval = *options.FlushIntervalMs
	}
	maxBuffered := 10_000.0
	if options.MaxBuffered != nil {
		maxBuffered = *options.MaxBuffered
	}
	recorder := &usageRecorder{
		server: server, enabled: enabled, interval: int64(math.Max(1000, interval)),
		maxBuffered: int(math.Max(1, maxBuffered)), buffer: newUsageBuffer(), stop: make(chan struct{}),
	}
	if enabled {
		go recorder.periodic()
	}
	return recorder
}

func (r *usageRecorder) Enabled() bool { return r.enabled }

func (r *usageRecorder) periodic() {
	ticker := time.NewTicker(time.Duration(r.interval) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.mu.Lock()
			pending := r.buffer.size() > 0
			r.mu.Unlock()
			if pending {
				if _, err := r.Flush(context.Background()); err != nil {
					r.mu.Lock()
					r.lastFailure = r.server.Wall()
					r.mu.Unlock()
				}
			}
		}
	}
}

func (r *usageRecorder) Record(tenantID, identityID, action string) {
	if !r.enabled {
		return
	}
	now := r.server.Now()
	keyBytes, _ := json.Marshal([]string{tenantID, identityID, action})
	key := string(keyBytes)
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.buffer.entries[key]; ok {
		if now > entry.last {
			entry.last = now
		}
		entry.count++
	} else {
		r.buffer.set(key, &pendingUsage{tenantID: tenantID, identityID: identityID, action: action, first: now, last: now, count: 1})
	}
	// One early write at a time, and none while storage keeps failing (the interval retries).
	if r.buffer.size() >= r.maxBuffered && !r.scheduled && r.writing == nil && r.server.Wall()-r.lastFailure >= r.interval {
		r.scheduled = true
		// A detached context: the write never joins the transaction of the call that recorded.
		go func() {
			r.mu.Lock()
			r.scheduled = false
			r.mu.Unlock()
			if _, err := r.Flush(context.Background()); err != nil {
				r.mu.Lock()
				r.lastFailure = r.server.Wall()
				r.mu.Unlock()
			}
		}()
	}
}

func (r *usageRecorder) Flush(ctx context.Context) (int, error) {
	// One write at a time; a caller arriving mid-write waits and then writes what arrived since.
	r.mu.Lock()
	for r.writing != nil {
		wait := r.writing
		r.mu.Unlock()
		<-wait
		r.mu.Lock()
	}
	batch := r.buffer
	r.buffer = newUsageBuffer()
	done := make(chan struct{})
	r.writing = done
	r.mu.Unlock()
	written, err := r.write(ctx, batch)
	r.mu.Lock()
	if err != nil {
		// Keep the batch for the next attempt, merged with anything recorded meanwhile.
		for _, key := range batch.keys {
			entry := batch.entries[key]
			current, ok := r.buffer.entries[key]
			if !ok {
				r.buffer.set(key, entry)
				continue
			}
			current.first = min(current.first, entry.first)
			current.last = max(current.last, entry.last)
			current.count += entry.count
		}
	}
	r.writing = nil
	r.mu.Unlock()
	close(done)
	return written, err
}

func (r *usageRecorder) write(ctx context.Context, batch *usageBuffer) (int, error) {
	if batch.size() == 0 {
		return 0, nil
	}
	err := r.server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		var tenantOrder []string
		tenants := map[string]int64{}
		for _, key := range batch.keys {
			entry := batch.entries[key]
			if started, ok := tenants[entry.tenantID]; !ok {
				tenantOrder = append(tenantOrder, entry.tenantID)
				tenants[entry.tenantID] = entry.first
			} else if entry.first < started {
				tenants[entry.tenantID] = entry.first
			}
			id := UsageRecordID(entry.tenantID, entry.identityID, entry.action)
			existing, err := tx.Get(ctx, "accessUsage", id)
			if err != nil {
				return err
			}
			if existing != nil {
				_, err = tx.Put(ctx, "accessUsage", existing.Spread(core.NewObject(
					"firstUsedAt", math.Min(jsNumber(existing.Get("firstUsedAt")), float64(entry.first)),
					"lastUsedAt", math.Max(jsNumber(existing.Get("lastUsedAt")), float64(entry.last)),
					"count", jsNumber(existing.Get("count"))+entry.count,
				)))
			} else {
				_, err = tx.Insert(ctx, "accessUsage", core.NewObject(
					"id", id, "tenantId", entry.tenantID, "identityId", entry.identityID, "action", entry.action,
					"firstUsedAt", float64(entry.first), "lastUsedAt", float64(entry.last), "count", entry.count,
				))
			}
			if err != nil {
				return err
			}
		}
		for _, tenantID := range tenantOrder {
			tracked, err := tx.Get(ctx, "accessUsageTracking", tenantID)
			if err != nil {
				return err
			}
			if tracked == nil {
				if _, err := tx.Insert(ctx, "accessUsageTracking", core.NewObject("id", tenantID, "tenantId", tenantID, "startedAt", float64(tenants[tenantID]))); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return batch.size(), nil
}

func (r *usageRecorder) Stop() {
	r.stopOnce.Do(func() { close(r.stop) })
}
