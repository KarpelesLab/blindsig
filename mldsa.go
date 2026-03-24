package blindsig

import (
	"crypto/rand"
	"crypto/sha3"
	"errors"

	"github.com/KarpelesLab/mldsa"
)

// ML-DSA blind signature constants.
const (
	// mldsaTokenSize is the size of the random blinding token in bytes.
	mldsaTokenSize = 32

	// mldsaHashSize is the size of the blinded message hash in bytes.
	mldsaHashSize = 64

	// mldsaContext is the ML-DSA context string used for domain separation.
	// This ensures blind signatures cannot be confused with regular ML-DSA signatures.
	mldsaContext = "blindsig/mldsa65/v1"

	// MLDSASignatureSize is the total size of an ML-DSA blind signature
	// (blinding token + ML-DSA-65 signature).
	MLDSASignatureSize = mldsaTokenSize + mldsa.SignatureSize65
)

// GenerateMLDSAKey generates an ML-DSA-65 key pair suitable for blind signing.
func GenerateMLDSAKey() (*mldsa.Key65, error) {
	return mldsa.GenerateKey65(rand.Reader)
}

// BlindMessageMLDSA blinds a message using a random token so it can be sent
// to a signer without revealing its content.
//
// It returns the blinded message (a SHAKE256 hash commitment) and the blinding
// factor (random token) needed to later construct the final signature.
//
// The blinded message is computed as SHAKE256(domain || token || message),
// which is computationally hiding: the signer learns nothing about the
// original message from the blinded value.
func BlindMessageMLDSA(message []byte, pubKey *mldsa.PublicKey65) (blindedMsg []byte, blindingFactor []byte, err error) {
	token := make([]byte, mldsaTokenSize)
	if _, err := rand.Read(token); err != nil {
		return nil, nil, err
	}

	blindedMsg = mldsaCommit(token, message)
	return blindedMsg, token, nil
}

// SignBlindedMLDSA signs a blinded message using ML-DSA-65. The signer never
// sees the original message — only the hash commitment.
func SignBlindedMLDSA(blindedMsg []byte, privKey *mldsa.PrivateKey65) ([]byte, error) {
	if len(blindedMsg) != mldsaHashSize {
		return nil, errors.New("blindsig: invalid blinded message size")
	}
	return privKey.SignWithContext(rand.Reader, blindedMsg, []byte(mldsaContext))
}

// UnblindSignatureMLDSA assembles the final blind signature from the signer's
// ML-DSA signature and the client's blinding factor.
//
// The resulting signature is token || mldsaSig and can be verified by anyone
// using VerifySignatureMLDSA.
func UnblindSignatureMLDSA(blindSig []byte, blindingFactor []byte, pubKey *mldsa.PublicKey65) ([]byte, error) {
	if len(blindSig) != mldsa.SignatureSize65 {
		return nil, errors.New("blindsig: invalid ML-DSA signature size")
	}
	if len(blindingFactor) != mldsaTokenSize {
		return nil, errors.New("blindsig: invalid blinding factor size")
	}

	sig := make([]byte, MLDSASignatureSize)
	copy(sig[:mldsaTokenSize], blindingFactor)
	copy(sig[mldsaTokenSize:], blindSig)
	return sig, nil
}

// VerifySignatureMLDSA verifies an ML-DSA blind signature on the given message.
//
// It recomputes the hash commitment from the embedded blinding token and the
// message, then verifies the ML-DSA-65 signature on that commitment.
func VerifySignatureMLDSA(message []byte, signature []byte, pubKey *mldsa.PublicKey65) bool {
	if len(signature) != MLDSASignatureSize {
		return false
	}

	token := signature[:mldsaTokenSize]
	mldsaSig := signature[mldsaTokenSize:]

	blindedMsg := mldsaCommit(token, message)
	return pubKey.Verify(mldsaSig, blindedMsg, []byte(mldsaContext))
}

// mldsaCommit computes the hash commitment: SHAKE256(domain || token || message).
func mldsaCommit(token, message []byte) []byte {
	h := sha3.NewSHAKE256()
	h.Write([]byte("blindsig.mldsa65.commit\x00"))
	h.Write(token)
	h.Write(message)
	out := make([]byte, mldsaHashSize)
	h.Read(out)
	return out
}
