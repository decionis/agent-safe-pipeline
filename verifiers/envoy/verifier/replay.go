package verifier

import (
	"sync"
	"time"
)

// MemoryReplayStore is a replay store for one process: enough for a single
// instance, and for the vectors. A provider with more than one instance that
// can effect shares one instead, keyed the same way. Expired grants are
// forgotten on the next record, which is why the store needs no life beyond
// the lease.
type MemoryReplayStore struct {
	mutex sync.Mutex
	seen  map[string]time.Time
	now   func() time.Time
}

// NewMemoryReplayStore makes a store reading the clock given, or the wall
// clock when nil.
func NewMemoryReplayStore(now func() time.Time) *MemoryReplayStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayStore{seen: map[string]time.Time{}, now: now}
}

// Record implements ReplayStore.
func (store *MemoryReplayStore) Record(grantID string, expiresAt time.Time) bool {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	now := store.now()
	for grant, expiry := range store.seen {
		if !expiry.After(now) {
			delete(store.seen, grant)
		}
	}
	if _, present := store.seen[grantID]; present {
		return false
	}
	store.seen[grantID] = expiresAt
	return true
}
