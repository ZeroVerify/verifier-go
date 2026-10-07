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

	// DefaultClockSkew is how far the prover-supplied `now` public signal may differ from the verifier's clock.
	DefaultClockSkew = 5 * time.Minute
)

type VerifyResult struct {
	Valid  bool
	Reason string
}

type Circuit struct {
	PreVerify  func(req VerifyRequest) (*VerifyResult, error)
	Signals    func(req VerifyRequest) ([]string, error)
	PostVerify func(req VerifyRequest) (*VerifyResult, error)
}

type CircuitInputs struct {
	Fields     map[string]string
	Signatures map[string]string
	Challenge  string
	// ExpiresAt is optional. Credential expiry is enforced inside the circuit (issued_at <= now < expires_at,
	// all signed by the issuer), so a verifier only needs to check that `now` matches its own clock.
	ExpiresAt       int64
	Now             int64 // the `now` public signal the prover used (taken from PublicSignals when present)
	RevocationIndex int
	CredentialID    string
}

// Public signal layout of the student_status circuit:
// [out_nonce, revocation_index, challenge_nonce, now]
const (
	studentSignalOutNonce        = 0
	studentSignalRevocationIndex = 1
	studentSignalChallenge       = 2
	studentSignalNow             = 3
	studentSignalCount           = 4
)

func applyStudentSignals(req *VerifyRequest) *VerifyResult {
	sig := req.PublicSignals
	invalid := &VerifyResult{Valid: false, Reason: ReasonProofInvalid}
	if len(sig) != studentSignalCount || sig[studentSignalOutNonce] != sig[studentSignalChallenge] {
		return invalid
	}
	idx, err := strconv.Atoi(sig[studentSignalRevocationIndex])
	if err != nil || idx < 0 {
		return invalid
	}
	now, err := strconv.ParseInt(sig[studentSignalNow], 10, 64)
	if err != nil {
		return invalid
	}
	req.Inputs.Challenge = sig[studentSignalChallenge]
	req.Inputs.RevocationIndex = idx
	req.Inputs.Now = now
	return nil
}

var StudentStatusCircuit = &Circuit{
	PreVerify: func(req VerifyRequest) (*VerifyResult, error) {
		if req.Inputs.Challenge != req.ExpectedChallenge {
			return &VerifyResult{Valid: false, Reason: ReasonProofInvalid}, nil
		}
		clock := req.Clock
		if clock == nil {
			clock = time.Now
		}
		if req.Inputs.ExpiresAt != 0 && clock().Unix() > req.Inputs.ExpiresAt {
			return &VerifyResult{Valid: false, Reason: ReasonTimestampExpired}, nil
		}
		// The circuit only proves the credential was valid at the prover-chosen `now`.
		// Without this check a prover could present an expired credential with a back-dated `now`.
		if req.PublicSignals != nil {
			skew := req.ClockSkew
			if skew == 0 {
				skew = DefaultClockSkew
			}
			diff := clock().Unix() - req.Inputs.Now
			if diff < 0 {
				diff = -diff
			}
			if time.Duration(diff)*time.Second > skew {
				return &VerifyResult{Valid: false, Reason: ReasonTimestampExpired}, nil
			}
		}
		revoked, err := isRevoked(req.Bitstring, req.Inputs.RevocationIndex)
		if err != nil {
			return nil, fmt.Errorf("checking revocation: %w", err)
		}
		if revoked {
			return &VerifyResult{Valid: false, Reason: ReasonCredentialRevoked}, nil
		}
		return nil, nil
	},
	Signals: func(req VerifyRequest) ([]string, error) {
		if req.PublicSignals != nil {
			return req.PublicSignals, nil
		}
		return []string{
			req.Inputs.Challenge,
			strconv.Itoa(req.Inputs.RevocationIndex),
			req.Inputs.Challenge,
			strconv.FormatInt(req.Inputs.Now, 10),
		}, nil
	},
	PostVerify: func(req VerifyRequest) (*VerifyResult, error) {
		if req.BabyJubJubPubKey == "" {
			return nil, nil
		}
		if err := verifyFieldSignatures(req.BabyJubJubPubKey, req.Inputs.Fields, req.Inputs.Signatures); err != nil {
			return &VerifyResult{Valid: false, Reason: ReasonProofInvalid}, nil
		}
		return nil, nil
	},
}

var RevocationCircuit = &Circuit{
	Signals: func(req VerifyRequest) ([]string, error) {
		ax, ay, err := DecompressBabyJubJubKey(req.BabyJubJubPubKey)
		if err != nil {
			return nil, fmt.Errorf("decompressing issuer public key: %w", err)
		}
		credIDFE := FieldElement(req.Inputs.CredentialID).String()
		return []string{credIDFE, ax, ay}, nil
	},
}

type VerifyRequest struct {
	ProofJSON         []byte
	Inputs            CircuitInputs
	ExpectedChallenge string
	Circuit           *Circuit
	VerificationKey   []byte
	Bitstring         []byte
	BabyJubJubPubKey  string

	// PublicSignals are the public signals submitted with the proof. Preferred over Inputs: the signals the
	// proof is checked against are exactly the ones the checks (nonce, now, revocation index) are made on.
	PublicSignals []string
	ClockSkew     time.Duration    // 0 means DefaultClockSkew
	Clock         func() time.Time // nil means time.Now (for tests)
}

func Verify(req VerifyRequest) (VerifyResult, error) {
	circuit := req.Circuit
	if circuit == nil {
		circuit = StudentStatusCircuit
	}

	if circuit == StudentStatusCircuit && req.PublicSignals != nil {
		if bad := applyStudentSignals(&req); bad != nil {
			return *bad, nil
		}
	}

	if circuit.Signals == nil {
		return VerifyResult{}, fmt.Errorf("circuit Signals hook is required")
	}

	if circuit.PreVerify != nil {
		result, err := circuit.PreVerify(req)
		if err != nil {
			return VerifyResult{}, err
		}
		if result != nil {
			return *result, nil
		}
	}

	var proofData types.ProofData
	if err := json.Unmarshal(req.ProofJSON, &proofData); err != nil {
		return VerifyResult{}, fmt.Errorf("parsing proof JSON: %w", err)
	}

	signals, err := circuit.Signals(req)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("computing public signals: %w", err)
	}

	proof := types.ZKProof{Proof: &proofData, PubSignals: signals}
	if err := groth16.Verify(proof, req.VerificationKey); err != nil {
		return VerifyResult{Valid: false, Reason: ReasonProofInvalid}, nil
	}

	if circuit.PostVerify != nil {
		result, err := circuit.PostVerify(req)
		if err != nil {
			return VerifyResult{}, err
		}
		if result != nil {
			return *result, nil
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
