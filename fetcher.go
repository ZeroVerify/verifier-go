package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/zeroverify/verifier-go/internal/bitstring"
	"github.com/zeroverify/verifier-go/internal/vkey"
)

const (
	DefaultBaseURL      = "https://artifacts.api.zeroverify.net"
	DefaultVKeyURL      = DefaultBaseURL + "/circuit/%s/verification_key.json"
	DefaultBitstringURL = DefaultBaseURL + "/bitstring/v1/bitstring.gz"
	DefaultPublicKeyURL = DefaultBaseURL + "/issuer/public-key.json"
)

type Fetcher struct {
	vkeys        *vkey.Cache
	bitstrings   *bitstring.Cache
	publicKeyURL string
}

type FetcherBuilder struct {
	vkeyURL      string
	bitstringURL string
	publicKeyURL string
}

func NewFetcher() *FetcherBuilder {
	return &FetcherBuilder{
		vkeyURL:      DefaultVKeyURL,
		bitstringURL: DefaultBitstringURL,
		publicKeyURL: DefaultPublicKeyURL,
	}
}

func (b *FetcherBuilder) WithVKeyURL(urlTemplate string) *FetcherBuilder {
	b.vkeyURL = urlTemplate
	return b
}

func (b *FetcherBuilder) WithBitstringURL(url string) *FetcherBuilder {
	b.bitstringURL = url
	return b
}

func (b *FetcherBuilder) WithPublicKeyURL(url string) *FetcherBuilder {
	b.publicKeyURL = url
	return b
}

func (b *FetcherBuilder) Build() *Fetcher {
	return &Fetcher{
		vkeys:        vkey.NewCacheWithURL(b.vkeyURL),
		bitstrings:   bitstring.NewCacheWithURL(b.bitstringURL),
		publicKeyURL: b.publicKeyURL,
	}
}

func (f *Fetcher) VerificationKey(ctx context.Context, proofType string) ([]byte, error) {
	return f.vkeys.Get(ctx, proofType)
}

func (f *Fetcher) Bitstring(ctx context.Context) ([]byte, error) {
	return f.bitstrings.Get(ctx)
}

func (f *Fetcher) BabyJubJubPublicKey(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.publicKeyURL, nil)
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching public key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching public key: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading public key response: %w", err)
	}

	var payload struct {
		PublicKeyHex string `json:"publicKeyHex"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parsing public key response: %w", err)
	}
	if payload.PublicKeyHex == "" {
		return "", fmt.Errorf("publicKeyHex missing from response")
	}

	return payload.PublicKeyHex, nil
}
