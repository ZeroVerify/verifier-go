# verifier-go

Verifies ZeroVerify zk-SNARK credentials in Go. Handles Groth16 proof verification, revocation checks against the W3C Bitstring Status List, expiry validation, and BabyJubJub field signature verification.

## Install

```bash
go get github.com/zeroverify/verifier-go@v0.1.0
```

## Usage

The typical path is to build a `Fetcher`, wrap it in a `Client`, and call `Verify`:

```go
fetcher := verifier.NewFetcher().Build()
client  := verifier.NewClient(fetcher)

result, err := client.Verify(ctx, proof, "student_status", expectedChallenge)
if err != nil {
    // something went wrong fetching from S3 or the data was malformed
    log.Fatal(err)
}
if !result.Valid {
    log.Println(result.Reason)
}
```

`proof` is a `types.ZKProof` from `github.com/iden3/go-rapidsnark/types` — the same struct snarkjs produces.

## Public Signals

The library expects public signals in this order by default:

| Index | Value             | Format                |
|-------|-------------------|-----------------------|
| 0     | challenge         | decimal field element |
| 1     | expires_at        | Unix timestamp        |
| 2     | revocation_index  | bit position          |

If your circuit outputs signals in a different order, use `VerifyWithLayout`:

```go
layout := verifier.SignalLayout{
    ChallengeIndex:     2,
    ExpiresAtIndex:     0,
    RevocationIndexIdx: 1,
}

result, err := client.VerifyWithLayout(ctx, proof, "student_status", challenge, layout)
```

## Custom Endpoints

By default the fetcher points at ZeroVerify's S3 buckets. You can override any of them:

```go
fetcher := verifier.NewFetcher().
    WithVKeyURL("https://my-mirror.example.com/circuit/%s/verification_key.json").
    WithBitstringURL("https://my-mirror.example.com/bitstring/v1/bitstring.gz").
    WithPublicKeyURL("https://my-mirror.example.com/issuer/public-key.json").
    Build()
```

The defaults are exported if you need to reference them:

```go
verifier.DefaultVKeyURL      // "https://artifacts.api.zeroverify.net/circuit/%s/verification_key.json"
verifier.DefaultBitstringURL // "https://artifacts.api.zeroverify.net/bitstring/v1/bitstring.gz"
verifier.DefaultPublicKeyURL // "https://artifacts.api.zeroverify.net/issuer/public-key.json"
```

Verification keys are cached for the lifetime of the process. The revocation bitstring is cached for 5 minutes.

## Field Signature Verification

Each credential carries a BabyJubJub signature per field proving the issuer signed that exact value. To verify them, supply the plain field values alongside the signatures from the credential:

```go
result, err := verifier.Verify(verifier.VerifyRequest{
    Proof:             proof,
    ExpectedChallenge: challenge,
    VerificationKey:   vkJSON,
    Bitstring:         bitstringBytes,
    BabyJubJubPubKey:  pubKeyHex,
    FieldSignatures: map[string]string{
        "email":             "base64encodedSig...",
        "enrollment_status": "base64encodedSig...",
        "given_name":        "base64encodedSig...",
        "family_name":       "base64encodedSig...",
    },
    CredentialFields: map[string]string{
        "email":             "testuser@oakland.edu",
        "enrollment_status": "student",
        "given_name":        "Test",
        "family_name":       "User",
    },
    Layout: verifier.DefaultLayout,
})
```

Leave `BabyJubJubPubKey` empty to skip field signature verification.

## Fetching Data Manually

If you need the raw data for something else, the `Fetcher` methods are public:

```go
vkJSON, err  := fetcher.VerificationKey(ctx, "student_status")
bs, err      := fetcher.Bitstring(ctx)
pubKeyHex, err := fetcher.BabyJubJubPublicKey(ctx)
```

## Calling Verify Without a Client

If you already have all the data and don't want the fetcher involved, call `Verify` directly:

```go
result, err := verifier.Verify(verifier.VerifyRequest{
    Proof:             proof,
    ExpectedChallenge: challenge,
    VerificationKey:   vkJSON,
    Bitstring:         bitstringBytes,
    Layout:            verifier.DefaultLayout,
})
```

No HTTP calls, no caching — just the verification logic.

## Verification Order

Checks run in this order and stop at the first failure:

1. Signal count validation
2. Challenge match
3. Expiry (`expires_at` vs current time)
4. Revocation (bit at `revocation_index` in bitstring)
5. Groth16 proof
6. BabyJubJub field signatures (only if `BabyJubJubPubKey` is set)

## Failure Reasons

| `result.Reason`        | When                                                  |
|------------------------|-------------------------------------------------------|
| `proof_invalid`        | Groth16 failed, challenge mismatch, or bad signals    |
| `timestamp_expired`    | `expires_at` is in the past                           |
| `credential_revoked`   | Revocation bit is set                                 |

## Testing

In tests, point the fetcher at `httptest.Server` instances instead of S3:

```go
fetcher := verifier.NewFetcher().
    WithVKeyBaseURL(mockVKServer.URL).
    WithBitstringURL(mockBitstringServer.URL).
    WithPublicKeyURL(mockPubKeyServer.URL).
    Build()
```

Or skip the fetcher entirely and pass raw bytes straight into `verifier.Verify`.
