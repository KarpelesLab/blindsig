package blindsig

import (
	"crypto/rand"
	"errors"

	"github.com/KarpelesLab/mldsa"
)

// ML-DSA blind signature sizes.
const (
	// MLDSASignatureSize is the size of an ML-DSA-65 blind signature.
	MLDSASignatureSize = mldsa.BlindSignatureSize65

	// MLDSACommitmentSize is the size of the signer's commitment.
	MLDSACommitmentSize = mldsa.BlindCommitmentSize65

	// MLDSAChallengeSize is the size of the blinded challenge.
	MLDSAChallengeSize = mldsa.BlindChallengeSize65

	// MLDSAResponseSize is the size of the signer's response.
	MLDSAResponseSize = mldsa.BlindResponseSize65
)

// ErrMLDSARetry indicates the signer's rejection sampling failed and the
// protocol should restart from the commitment phase.
var ErrMLDSARetry = mldsa.ErrBlindRetry

// GenerateMLDSAKey generates an ML-DSA-65 key pair suitable for blind signing.
func GenerateMLDSAKey() (*mldsa.Key65, error) {
	return mldsa.GenerateKey65(rand.Reader)
}

// MLDSABlindPublicKey derives the blind signing public key from a private key.
// The blind public key uses t = A·s1 (without the s2 error term from standard
// ML-DSA), enabling algebraic blinding that provides true unlinkability.
func MLDSABlindPublicKey(sk *mldsa.PrivateKey65) *mldsa.BlindPublicKey65 {
	return sk.BlindPublicKey()
}

// MLDSASignerCommit starts a blind signing session. The signer generates a
// commitment (w = A·y) to send to the client.
//
// Returns the signer session state and the commitment bytes.
// The session must not be reused after [MLDSASignerRespond].
func MLDSASignerCommit(sk *mldsa.PrivateKey65) (*mldsa.BlindSignerState65, []byte, error) {
	return sk.NewBlindSession(rand.Reader)
}

// MLDSAClientChallenge creates a blinded challenge from the signer's commitment.
// The client picks a random blinding vector α, computes w' = w + A·α, and
// hashes to get the challenge.
//
// Returns the client state (for unblinding) and the challenge to send to the signer.
func MLDSAClientChallenge(message, commitment []byte, bpk *mldsa.BlindPublicKey65) (*mldsa.BlindClientState65, []byte, error) {
	return bpk.NewBlindChallenge(rand.Reader, message, commitment, nil)
}

// MLDSASignerRespond computes the signer's response to the client's challenge.
//
// Returns [ErrMLDSARetry] if rejection sampling fails — the caller should
// create a new session with [MLDSASignerCommit] and restart the protocol.
func MLDSASignerRespond(session *mldsa.BlindSignerState65, challenge []byte) ([]byte, error) {
	return session.Respond(challenge)
}

// MLDSAClientUnblind removes the blinding from the signer's response, producing
// a valid blind signature that anyone can verify.
func MLDSAClientUnblind(state *mldsa.BlindClientState65, response []byte, bpk *mldsa.BlindPublicKey65) ([]byte, error) {
	return bpk.Unblind(state, response)
}

// VerifySignatureMLDSA verifies an ML-DSA-65 blind signature on the given message.
func VerifySignatureMLDSA(message []byte, signature []byte, bpk *mldsa.BlindPublicKey65) bool {
	return bpk.BlindVerify(signature, message, nil)
}

// MLDSABlindSign runs the full blind signing protocol, handling retries
// automatically. This is a convenience function for when both parties are
// local (e.g., testing). For real protocols, use the individual steps.
//
// Returns the blind signature or an error if signing fails after maxRetries.
func MLDSABlindSign(message []byte, sk *mldsa.PrivateKey65, bpk *mldsa.BlindPublicKey65, maxRetries int) ([]byte, error) {
	if maxRetries <= 0 {
		maxRetries = 100
	}
	for i := 0; i < maxRetries; i++ {
		session, commitment, err := sk.NewBlindSession(rand.Reader)
		if err != nil {
			return nil, err
		}
		state, challenge, err := bpk.NewBlindChallenge(rand.Reader, message, commitment, nil)
		if err != nil {
			return nil, err
		}
		response, err := session.Respond(challenge)
		if errors.Is(err, mldsa.ErrBlindRetry) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return bpk.Unblind(state, response)
	}
	return nil, errors.New("blindsig: ML-DSA blind signing failed after max retries")
}
