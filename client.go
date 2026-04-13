package verifier

import (
	"context"
)

type Client struct {
	fetcher *Fetcher
}

func NewClient(fetcher *Fetcher) *Client {
	return &Client{fetcher: fetcher}
}

func (c *Client) Verify(ctx context.Context, proofJSON []byte, inputs CircuitInputs, proofType, expectedChallenge string) (VerifyResult, error) {
	return c.VerifyWithCircuit(ctx, proofJSON, inputs, proofType, expectedChallenge, StudentStatusCircuit)
}

func (c *Client) VerifyWithCircuit(ctx context.Context, proofJSON []byte, inputs CircuitInputs, proofType, expectedChallenge string, circuit *Circuit) (VerifyResult, error) {
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
		ExpectedChallenge: expectedChallenge,
		Circuit:           circuit,
		VerificationKey:   vkJSON,
		Bitstring:         bs,
		BabyJubJubPubKey:  pubKey,
	})
}
