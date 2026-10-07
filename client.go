package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type Client struct {
	fetcher   *Fetcher
	clock     func() time.Time
	clockSkew time.Duration
}

// WithClock overrides the clock used for the `now` check (intended for tests) and the allowed skew (0 = DefaultClockSkew).
func (c *Client) WithClock(clock func() time.Time, skew time.Duration) *Client {
	cp := *c
	cp.clock, cp.clockSkew = clock, skew
	return &cp
}

func NewClient(fetcher *Fetcher) *Client {
	return &Client{fetcher: fetcher}
}

func (c *Client) Verify(ctx context.Context, proofJSON []byte, inputs CircuitInputs, proofType, expectedChallenge string) (VerifyResult, error) {
	return c.VerifyWithCircuit(ctx, proofJSON, inputs, proofType, expectedChallenge, StudentStatusCircuit)
}

// Submission is the JSON body the ZeroVerify wallet POSTs to a verifier's callback URL.
type Submission struct {
	Proof         json.RawMessage `json:"proof"`
	PublicSignals []string        `json:"publicSignals"`
}

// VerifySubmission verifies the wallet's callback body: Groth16 proof, nonce, `now` against the local clock,
// and the revocation bit. This is the recommended entry point.
func (c *Client) VerifySubmission(ctx context.Context, body []byte, proofType, expectedChallenge string) (VerifyResult, error) {
	var sub Submission
	if err := json.Unmarshal(body, &sub); err != nil || len(sub.Proof) == 0 || sub.PublicSignals == nil {
		return VerifyResult{Valid: false, Reason: ReasonProofInvalid}, fmt.Errorf("malformed submission: %v", err)
	}
	return c.verify(ctx, sub.Proof, CircuitInputs{}, sub.PublicSignals, proofType, expectedChallenge, StudentStatusCircuit)
}

func (c *Client) VerifyWithCircuit(ctx context.Context, proofJSON []byte, inputs CircuitInputs, proofType, expectedChallenge string, circuit *Circuit) (VerifyResult, error) {
	return c.verify(ctx, proofJSON, inputs, nil, proofType, expectedChallenge, circuit)
}

func (c *Client) verify(ctx context.Context, proofJSON []byte, inputs CircuitInputs, publicSignals []string, proofType, expectedChallenge string, circuit *Circuit) (VerifyResult, error) {
	vkJSON, err := c.fetcher.VerificationKey(ctx, proofType)
	if err != nil {
		return VerifyResult{}, err
	}

	bs, err := c.fetcher.Bitstring(ctx)
	if err != nil {
		return VerifyResult{}, err
	}

	pubKey, err := c.fetcher.BabyJubJubPublicKey(ctx)
	if err != nil {
		return VerifyResult{}, err
	}

	return Verify(VerifyRequest{
		ProofJSON:         proofJSON,
		Inputs:            inputs,
		PublicSignals:     publicSignals,
		Clock:             c.clock,
		ClockSkew:         c.clockSkew,
		ExpectedChallenge: expectedChallenge,
		Circuit:           circuit,
		VerificationKey:   vkJSON,
		Bitstring:         bs,
		BabyJubJubPubKey:  pubKey,
	})
}
