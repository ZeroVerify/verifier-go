package groth16

import (
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
)

func Verify(proof types.ZKProof, verificationKeyJSON []byte) error {
	return verifier.VerifyGroth16(proof, verificationKeyJSON)
}
