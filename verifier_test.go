package verifier_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/babyjub"
	verifier "github.com/zeroverify/verifier-go"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(base64.StdEncoding.EncodeToString(data))) // same encoding as bitstring-updater-lambda
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

// testKey derives a deterministic Baby Jubjub key pair: compressed hex plus decimal Ax and Ay, as the issuer publishes it.
func testKey(seed byte) (pubHex, ax, ay string) {
	var sk babyjub.PrivateKey
	copy(sk[:], bytes.Repeat([]byte{seed}, 32))
	pub := sk.Public()
	comp := pub.Compress()
	return hex.EncodeToString(comp[:]), pub.X.String(), pub.Y.String()
}

var issuerHex, issuerAx, issuerAy = testKey(7)

// newStudentSignals builds [out_nonce, pseudonym_hash, revocation_index, Ax, Ay, challenge_nonce, now] for the trusted issuer.
func newStudentSignals(challenge string, index int, now int64) []string {
	return []string{challenge, "12345", strconv.Itoa(index), issuerAx, issuerAy, challenge, strconv.FormatInt(now, 10)}
}

func verifySignals(signals []string, bits []byte) verifier.VerifyResult {
	res, _ := verifier.Verify(verifier.VerifyRequest{
		ProofJSON: stubProofJSON, PublicSignals: signals, ExpectedChallenge: "nonce",
		VerificationKey: []byte(`{}`), Bitstring: bits, BabyJubJubPubKey: issuerHex,
	})
	return res
}

// A proof made against any other key (for example one the prover generated and used to sign their own credential)
// must be rejected before the proof is even checked.
func TestSelfSignedCredentialRejected(t *testing.T) {
	_, ax, ay := testKey(9) // an attacker's own key
	sig := newStudentSignals("nonce", 0, time.Now().Unix())
	sig[3], sig[4] = ax, ay
	if res := verifySignals(sig, make([]byte, 16)); res.Valid || res.Reason != verifier.ReasonUntrustedIssuer {
		t.Fatalf("expected untrusted_issuer, got %+v", res)
	}
	sig = newStudentSignals("nonce", 0, time.Now().Unix())
	sig[4] = "1" // only one coordinate matches
	if res := verifySignals(sig, make([]byte, 16)); res.Valid || res.Reason != verifier.ReasonUntrustedIssuer {
		t.Fatalf("expected untrusted_issuer for a half-matching key, got %+v", res)
	}
}

func TestStudentProofWithoutIssuerKeyIsAnError(t *testing.T) {
	_, err := verifier.Verify(verifier.VerifyRequest{
		ProofJSON: stubProofJSON, PublicSignals: newStudentSignals("nonce", 0, time.Now().Unix()), ExpectedChallenge: "nonce",
		VerificationKey: []byte(`{}`), Bitstring: make([]byte, 16),
	})
	if err == nil {
		t.Fatal("verifying without the issuer public key must fail loudly, not skip the check")
	}
}

func TestPublicSignalsNowFarFromClockRejected(t *testing.T) {
	res := verifySignals(newStudentSignals("nonce", 0, time.Now().Add(-time.Hour).Unix()), make([]byte, 16))
	if res.Valid || res.Reason != verifier.ReasonTimestampExpired {
		t.Fatalf("expected timestamp_expired for back-dated now, got %+v", res)
	}
}

func TestPublicSignalsRevocationIndexIsRead(t *testing.T) {
	bs := make([]byte, 16)
	bs[1] = 0b01000000 // bit 9
	res := verifySignals(newStudentSignals("nonce", 9, time.Now().Unix()), bs)
	if res.Valid || res.Reason != verifier.ReasonCredentialRevoked {
		t.Fatalf("expected credential_revoked, got %+v", res)
	}
}

func TestPublicSignalsMalformedRejected(t *testing.T) {
	for name, sig := range map[string][]string{
		"too few":        {"nonce", "0", "nonce", "1"},
		"nonce mismatch": {"other", "1", "0", issuerAx, issuerAy, "nonce", strconv.FormatInt(time.Now().Unix(), 10)},
		"bad index":      {"nonce", "1", "x", issuerAx, issuerAy, "nonce", strconv.FormatInt(time.Now().Unix(), 10)},
		"negative index": {"nonce", "1", "-1", issuerAx, issuerAy, "nonce", strconv.FormatInt(time.Now().Unix(), 10)},
	} {
		if res := verifySignals(sig, make([]byte, 16)); res.Valid || res.Reason != verifier.ReasonProofInvalid {
			t.Errorf("%s: expected proof_invalid, got %+v", name, res)
		}
	}
}

func TestPublicSignalsWrongChallengeRejected(t *testing.T) {
	res, _ := verifier.Verify(verifier.VerifyRequest{
		ProofJSON: stubProofJSON, PublicSignals: newStudentSignals("nonce", 0, time.Now().Unix()), ExpectedChallenge: "different",
		VerificationKey: []byte(`{}`), Bitstring: make([]byte, 16), BabyJubJubPubKey: issuerHex,
	})
	if res.Valid || res.Reason != verifier.ReasonProofInvalid {
		t.Fatalf("expected proof_invalid, got %+v", res)
	}
}
