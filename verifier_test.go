package verifier_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	verifier "github.com/zeroverify/verifier-go"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()
	return buf.Bytes()
}

var stubProofJSON = []byte(`{
	"pi_a": ["0", "0", "1"],
	"pi_b": [["0", "0"], ["0", "0"], ["1", "0"]],
	"pi_c": ["0", "0", "1"],
	"protocol": "groth16",
	"curve": "bn128"
}`)

func inputs(challenge string, expiresAt int64, revocationIndex int) verifier.CircuitInputs {
	return verifier.CircuitInputs{
		Challenge:       challenge,
		ExpiresAt:       expiresAt,
		RevocationIndex: revocationIndex,
	}
}

func mockServers(t *testing.T, bitstringData []byte) (vkURL, bsURL, pkURL string) {
	t.Helper()

	vkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"protocol": "groth16", "curve": "bn128", "nPublic": 3,
			"vk_alpha_1": []string{"0", "0", "1"},
			"vk_beta_2":  [][]string{{"0", "0"}, {"0", "0"}, {"1", "0"}},
			"vk_gamma_2": [][]string{{"0", "0"}, {"0", "0"}, {"1", "0"}},
			"vk_delta_2": [][]string{{"0", "0"}, {"0", "0"}, {"1", "0"}},
			"IC":         [][]string{{"0", "0", "1"}, {"0", "0", "1"}, {"0", "0", "1"}, {"0", "0", "1"}},
		})
	}))

	bsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(gzipBytes(t, bitstringData))
	}))

	pkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"publicKeyHex": ""})
	}))

	t.Cleanup(func() { vkSrv.Close(); bsSrv.Close(); pkSrv.Close() })
	return vkSrv.URL, bsSrv.URL, pkSrv.URL
}

func newTestClient(t *testing.T, bs []byte) *verifier.Client {
	t.Helper()
	vkURL, bsURL, pkURL := mockServers(t, bs)
	fetcher := verifier.NewFetcher().
		WithVKeyURL(vkURL + "/circuit/%s/verification_key.json").
		WithBitstringURL(bsURL).
		WithPublicKeyURL(pkURL).
		Build()
	return verifier.NewClient(fetcher)
}

func TestFetcherVKeyCacheHitMakesNoRequest(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]string{"protocol": "groth16"})
	}))
	defer srv.Close()

	fetcher := verifier.NewFetcher().WithVKeyURL(srv.URL + "/circuit/%s/verification_key.json").Build()
	ctx := context.Background()

	fetcher.VerificationKey(ctx, "student_status")
	fetcher.VerificationKey(ctx, "student_status")

	if calls != 1 {
		t.Fatalf("expected 1 HTTP call, got %d", calls)
	}
}

func TestFetcherBitstringCacheRespectsTTL(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write(gzipBytes(t, make([]byte, 16)))
	}))
	defer srv.Close()

	fetcher := verifier.NewFetcher().WithBitstringURL(srv.URL).Build()
	ctx := context.Background()

	fetcher.Bitstring(ctx)
	fetcher.Bitstring(ctx)

	if calls != 1 {
		t.Fatalf("expected 1 HTTP call within TTL, got %d", calls)
	}
}

func TestVerifyTimestampExpired(t *testing.T) {
	expired := time.Now().Add(-24 * time.Hour).Unix()
	result, err := verifier.Verify(verifier.VerifyRequest{
		ProofJSON:         stubProofJSON,
		Inputs:            inputs("nonce", expired, 0),
		ExpectedChallenge: "nonce",
		VerificationKey:   []byte(`{}`),
		Bitstring:         make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.Reason != verifier.ReasonTimestampExpired {
		t.Fatalf("expected timestamp_expired, got valid=%v reason=%q", result.Valid, result.Reason)
	}
}

func TestVerifyCredentialRevoked(t *testing.T) {
	bs := make([]byte, 16)
	bs[0] = 0b10000000 // bit index 0 is revoked

	future := time.Now().Add(30 * 24 * time.Hour).Unix()
	result, err := verifier.Verify(verifier.VerifyRequest{
		ProofJSON:         stubProofJSON,
		Inputs:            inputs("nonce", future, 0),
		ExpectedChallenge: "nonce",
		VerificationKey:   []byte(`{}`),
		Bitstring:         bs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.Reason != verifier.ReasonCredentialRevoked {
		t.Fatalf("expected credential_revoked, got valid=%v reason=%q", result.Valid, result.Reason)
	}
}

func TestVerifyChallengeMismatch(t *testing.T) {
	future := time.Now().Add(30 * 24 * time.Hour).Unix()
	result, err := verifier.Verify(verifier.VerifyRequest{
		ProofJSON:         stubProofJSON,
		Inputs:            inputs("actual", future, 0),
		ExpectedChallenge: "expected",
		VerificationKey:   []byte(`{}`),
		Bitstring:         make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.Reason != verifier.ReasonProofInvalid {
		t.Fatalf("expected proof_invalid, got valid=%v reason=%q", result.Valid, result.Reason)
	}
}
