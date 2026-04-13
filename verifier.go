package verifier

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/zeroverify/verifier-go/internal/groth16"
)

const (
	ReasonProofInvalid      = "proof_invalid"
	ReasonTimestampExpired  = "timestamp_expired"
	ReasonCredentialRevoked = "credential_revoked"
)

type VerifyResult struct {
	Valid  bool
	Reason string
}

// Circuit maps credential inputs to the public signals required by a specific circuit.
// Different circuits encode different fields or orderings into their public signals.
type Circuit func(inputs CircuitInputs) ([]string, error)

// CircuitInputs holds the raw credential data. The Circuit function derives the
// public signals from these; the Verify function validates them directly.
type CircuitInputs struct {
	Fields          map[string]string
	Signatures      map[string]string
	Challenge       string
	ExpiresAt       int64
	RevocationIndex int
}

// DefaultCircuit produces public signals in ZeroVerify's standard order:
// [challenge, expires_at, revocation_index]
var DefaultCircuit Circuit = func(inputs CircuitInputs) ([]string, error) {
	return []string{
		inputs.Challenge,
		strconv.FormatInt(inputs.ExpiresAt, 10),
		strconv.Itoa(inputs.RevocationIndex),
	}, nil
}

type VerifyRequest struct {
	ProofJSON         []byte
	Inputs            CircuitInputs
	ExpectedChallenge string
	Circuit           Circuit
	VerificationKey   []byte
	Bitstring         []byte
	BabyJubJubPubKey  string
}

func Verify(req VerifyRequest) (VerifyResult, error) {
	if req.Inputs.Challenge != req.ExpectedChallenge {
		return VerifyResult{Valid: false, Reason: ReasonProofInvalid}, nil
	}

	if time.Now().Unix() > req.Inputs.ExpiresAt {
		return VerifyResult{Valid: false, Reason: ReasonTimestampExpired}, nil
	}

	revoked, err := isRevoked(req.Bitstring, req.Inputs.RevocationIndex)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("checking revocation: %w", err)
	}
	if revoked {
		return VerifyResult{Valid: false, Reason: ReasonCredentialRevoked}, nil
	}

	var proofData types.ProofData
	if err := json.Unmarshal(req.ProofJSON, &proofData); err != nil {
		return VerifyResult{}, fmt.Errorf("parsing proof JSON: %w", err)
	}

	circuit := req.Circuit
	if circuit == nil {
		circuit = DefaultCircuit
	}
	signals, err := circuit(req.Inputs)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("computing public signals: %w", err)
	}

	proof := types.ZKProof{Proof: &proofData, PubSignals: signals}
	if err := groth16.Verify(proof, req.VerificationKey); err != nil {
		return VerifyResult{Valid: false, Reason: ReasonProofInvalid}, nil
	}

	if req.BabyJubJubPubKey != "" {
		if err := verifyFieldSignatures(req.BabyJubJubPubKey, req.Inputs.Fields, req.Inputs.Signatures); err != nil {
			return VerifyResult{Valid: false, Reason: ReasonProofInvalid}, nil
		}
	}

	return VerifyResult{Valid: true}, nil
}

func VerifyProof(proofJSON []byte, verificationKey []byte, publicSignals []string) (VerifyResult, error) {
	var proofData types.ProofData
	if err := json.Unmarshal(proofJSON, &proofData); err != nil {
		return VerifyResult{}, fmt.Errorf("parsing proof JSON: %w", err)
	}

	proof := types.ZKProof{Proof: &proofData, PubSignals: publicSignals}
	if err := groth16.Verify(proof, verificationKey); err != nil {
		return VerifyResult{Valid: false, Reason: ReasonProofInvalid}, nil
	}

	return VerifyResult{Valid: true}, nil
}

func FieldElement(value string) *big.Int {
	return fieldElement(value)
}

func DecompressBabyJubJubKey(pubKeyHex string) (x, y string, err error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("decoding public key hex: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", "", fmt.Errorf("public key must be 32 bytes, got %d", len(pubKeyBytes))
	}

	var comp babyjub.PublicKeyComp
	copy(comp[:], pubKeyBytes)
	pubKey, err := comp.Decompress()
	if err != nil {
		return "", "", fmt.Errorf("decompressing public key: %w", err)
	}

	return pubKey.X.String(), pubKey.Y.String(), nil
}

func isRevoked(bitstring []byte, revocationIndex int) (bool, error) {
	byteIndex := revocationIndex / 8
	bitIndex := 7 - (revocationIndex % 8)

	if byteIndex >= len(bitstring) {
		return false, fmt.Errorf("revocation_index %d out of range (bitstring %d bytes)", revocationIndex, len(bitstring))
	}

	return (bitstring[byteIndex]>>bitIndex)&1 == 1, nil
}

func verifyFieldSignatures(pubKeyHex string, fields, signatures map[string]string) error {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("decoding public key hex: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return fmt.Errorf("public key must be 32 bytes, got %d", len(pubKeyBytes))
	}

	var comp babyjub.PublicKeyComp
	copy(comp[:], pubKeyBytes)
	pubKey, err := comp.Decompress()
	if err != nil {
		return fmt.Errorf("decompressing public key: %w", err)
	}

	for field, sigB64 := range signatures {
		value, ok := fields[field]
		if !ok {
			return fmt.Errorf("field %q missing from credential", field)
		}

		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return fmt.Errorf("decoding signature for field %q: %w", field, err)
		}
		if len(sigBytes) != 64 {
			return fmt.Errorf("invalid signature length for field %q: %d", field, len(sigBytes))
		}

		var sigComp babyjub.SignatureComp
		copy(sigComp[:], sigBytes)
		sig, err := sigComp.Decompress()
		if err != nil {
			return fmt.Errorf("decompressing signature for field %q: %w", field, err)
		}

		if !pubKey.VerifyPoseidon(fieldElement(value), sig) {
			return fmt.Errorf("invalid signature for field %q", field)
		}
	}
	return nil
}

func fieldElement(value string) *big.Int {
	h := sha256.Sum256([]byte(value))
	n := new(big.Int).SetBytes(h[:])
	n.Mod(n, babyjub.SubOrder)
	return n
}

