package bitstring

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/zeroverify/verifier-go/internal/cache"
)

const cacheTTL = 5 * time.Minute

type Cache struct {
	c   *cache.Cache[struct{}, []byte]
	url string
}

func NewCacheWithURL(url string) *Cache {
	return &Cache{
		c:   cache.New[struct{}, []byte](cacheTTL),
		url: url,
	}
}

func (c *Cache) Get(ctx context.Context) ([]byte, error) {
	return c.c.Get(struct{}{}, func() ([]byte, error) {
		return fetch(ctx, c.url)
	})
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching bitstring: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching bitstring: HTTP %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gz.Close()

	data, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("decompressing bitstring: %w", err)
	}
	return data, nil
}
