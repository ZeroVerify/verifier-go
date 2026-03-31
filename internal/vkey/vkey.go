package vkey

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/zeroverify/verifier-go/internal/cache"
)

type Cache struct {
	c           *cache.Cache[string, []byte]
	urlTemplate string
}

func NewCacheWithURL(urlTemplate string) *Cache {
	return &Cache{
		c:           cache.New[string, []byte](0),
		urlTemplate: urlTemplate,
	}
}

func (c *Cache) Get(ctx context.Context, proofType string) ([]byte, error) {
	return c.c.Get(proofType, func() ([]byte, error) {
		return fetch(ctx, fmt.Sprintf(c.urlTemplate, proofType))
	})
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching verification key %q: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching verification key %q: HTTP %d", url, resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading verification key %q: %w", url, err)
	}
	return b, nil
}
