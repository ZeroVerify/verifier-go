package cache

import (
	"sync"
	"time"
)

type Entry[V any] struct {
	value     V
	fetchedAt time.Time
}

type Cache[K comparable, V any] struct {
	mu      sync.RWMutex
	entries map[K]Entry[V]
	ttl     time.Duration
}

func New[K comparable, V any](ttl time.Duration) *Cache[K, V] {
	return &Cache[K, V]{
		entries: make(map[K]Entry[V]),
		ttl:     ttl,
	}
}

func (c *Cache[K, V]) Get(key K, fetch func() (V, error)) (V, error) {
	c.mu.RLock()
	if e, ok := c.entries[key]; ok && c.valid(e) {
		val := e.value
		c.mu.RUnlock()
		return val, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[key]; ok && c.valid(e) {
		return e.value, nil
	}

	val, err := fetch()
	if err != nil {
		var zero V
		return zero, err
	}
	c.entries[key] = Entry[V]{value: val, fetchedAt: time.Now()}
	return val, nil
}

func (c *Cache[K, V]) valid(e Entry[V]) bool {
	return c.ttl == 0 || time.Since(e.fetchedAt) < c.ttl
}
