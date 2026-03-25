package blindsig

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"

	ed "github.com/KarpelesLab/edwards25519"
)

var (
	curve    = ed.Edwards()
	curveL   = curve.N                    // group order
	curveGx  = curve.Gx                  // base point x
	curveGy  = curve.Gy                  // base point y
	bigZero  = big.NewInt(0)
)

// SchnorrPublicKey is a public key for blind Schnorr signatures over Ed25519.
type SchnorrPublicKey struct {
	x, y *big.Int // affine coordinates on the Edwards curve
}

// SchnorrPrivateKey is a private key for blind Schnorr signatures.
type SchnorrPrivateKey struct {
	a  *big.Int         // secret scalar
	pk *SchnorrPublicKey // corresponding public key A = aB
}

// SchnorrSignerState holds the signer's ephemeral state for one signing session.
// Must not be reused.
type SchnorrSignerState struct {
	k  *big.Int // nonce scalar (secret)
	rx, ry *big.Int // R = kB (commitment point)
}

// SchnorrClientState holds the client's state between protocol rounds.
type SchnorrClientState struct {
	alpha  *big.Int // blinding scalar for response
	beta   *big.Int // blinding scalar for challenge
	rpx, rpy *big.Int // R' = R + αB + βA (blinded commitment)
	ePrime *big.Int // e' = H(R' || A || msg)
}

// SchnorrSignature is a blind Schnorr signature (64 bytes: R' || s').
type SchnorrSignature struct {
	Rx, Ry *big.Int // R' point (blinded commitment)
	S      *big.Int // s' scalar (unblinded response)
}

// GenerateSchnorrKey generates a key pair for blind Schnorr signatures.
func GenerateSchnorrKey() (*SchnorrPrivateKey, *SchnorrPublicKey, error) {
	// Sample random scalar a ∈ [1, L-1]
	a, err := rand.Int(rand.Reader, new(big.Int).Sub(curveL, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}
	a.Add(a, big.NewInt(1)) // a ∈ [1, L-1]

	// A = aB
	ax, ay := curve.ScalarBaseMult(a.Bytes())

	pk := &SchnorrPublicKey{x: ax, y: ay}
	sk := &SchnorrPrivateKey{a: a, pk: pk}
	return sk, pk, nil
}

// PublicKey returns the public key for this private key.
func (sk *SchnorrPrivateKey) PublicKey() *SchnorrPublicKey {
	return sk.pk
}

// Bytes returns the 32-byte compressed encoding of the public key.
func (pk *SchnorrPublicKey) Bytes() []byte {
	p := ed.NewPublicKey(pk.x, pk.y)
	return p.Serialize()
}

// ParseSchnorrPublicKey parses a 32-byte compressed public key.
func ParseSchnorrPublicKey(data []byte) (*SchnorrPublicKey, error) {
	p, err := ed.ParsePubKey(data)
	if err != nil {
		return nil, err
	}
	return &SchnorrPublicKey{x: p.X, y: p.Y}, nil
}

// SchnorrSignerCommit starts a blind signing session (Round 1).
// The signer picks a random nonce k and sends the commitment R = kB to the client.
// Returns the signer state and the 32-byte compressed commitment point.
func SchnorrSignerCommit() (*SchnorrSignerState, []byte, error) {
	// Random nonce k ∈ [1, L-1]
	k, err := rand.Int(rand.Reader, new(big.Int).Sub(curveL, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}
	k.Add(k, big.NewInt(1))

	rx, ry := curve.ScalarBaseMult(k.Bytes())

	state := &SchnorrSignerState{k: k, rx: rx, ry: ry}
	commitment := ed.NewPublicKey(rx, ry).Serialize()
	return state, commitment, nil
}

// SchnorrClientChallenge creates a blinded challenge from the signer's commitment (Round 2).
// The client picks random blinding factors α, β, computes the blinded commitment
// R' = R + αB + βA, derives the challenge e' = H(R' || A || msg), and sends
// the blinded challenge e = e' + β to the signer.
//
// Returns the client state and the blinded challenge scalar (32 bytes).
func SchnorrClientChallenge(message, commitment []byte, pk *SchnorrPublicKey) (*SchnorrClientState, []byte, error) {
	// Parse commitment R
	rPub, err := ed.ParsePubKey(commitment)
	if err != nil {
		return nil, nil, errors.New("blindsig: invalid Schnorr commitment")
	}
	rx, ry := rPub.X, rPub.Y

	// Random blinding scalars α, β ∈ [0, L)
	alpha, err := rand.Int(rand.Reader, curveL)
	if err != nil {
		return nil, nil, err
	}
	beta, err := rand.Int(rand.Reader, curveL)
	if err != nil {
		return nil, nil, err
	}

	// R' = R + αB + βA
	aGx, aGy := curve.ScalarBaseMult(alpha.Bytes()) // αB
	bAx, bAy := curve.ScalarMult(pk.x, pk.y, beta.Bytes()) // βA
	tmpx, tmpy := curve.Add(rx, ry, aGx, aGy) // R + αB
	rpx, rpy := curve.Add(tmpx, tmpy, bAx, bAy) // R + αB + βA

	// e' = H(R' || A || msg) mod L
	ePrime := schnorrHashChallenge(rpx, rpy, pk, message)

	// e = e' + β mod L
	e := new(big.Int).Add(ePrime, beta)
	e.Mod(e, curveL)

	state := &SchnorrClientState{
		alpha: alpha, beta: beta,
		rpx: rpx, rpy: rpy,
		ePrime: ePrime,
	}

	// Encode e as 32-byte scalar
	eBytes := make([]byte, 32)
	eB := e.Bytes()
	copy(eBytes[32-len(eB):], eB) // big-endian, left-padded

	return state, eBytes, nil
}

// SchnorrSignerRespond computes the signer's response to the blinded challenge (Round 3).
// s = k + e·a mod L.
// Returns the 32-byte scalar response.
func SchnorrSignerRespond(state *SchnorrSignerState, challenge []byte, sk *SchnorrPrivateKey) ([]byte, error) {
	if len(challenge) != 32 {
		return nil, errors.New("blindsig: invalid challenge size")
	}

	e := new(big.Int).SetBytes(challenge)
	if e.Cmp(curveL) >= 0 {
		return nil, errors.New("blindsig: challenge out of range")
	}

	// s = k + e·a mod L
	s := new(big.Int).Mul(e, sk.a)
	s.Add(s, state.k)
	s.Mod(s, curveL)

	sBytes := make([]byte, 32)
	sB := s.Bytes()
	copy(sBytes[32-len(sB):], sB)

	return sBytes, nil
}

// SchnorrClientUnblind removes the blinding from the signer's response to produce
// the final blind signature.
// s' = s + α mod L. Signature = (R', s').
func SchnorrClientUnblind(state *SchnorrClientState, response []byte, pk *SchnorrPublicKey) (*SchnorrSignature, error) {
	if len(response) != 32 {
		return nil, errors.New("blindsig: invalid response size")
	}

	s := new(big.Int).SetBytes(response)

	// s' = s + α mod L
	sPrime := new(big.Int).Add(s, state.alpha)
	sPrime.Mod(sPrime, curveL)

	sig := &SchnorrSignature{
		Rx: state.rpx, Ry: state.rpy,
		S: sPrime,
	}

	// Verify before returning
	if !schnorrVerifyInternal(sig, pk, state.ePrime) {
		return nil, errors.New("blindsig: signature verification failed after unblinding")
	}

	return sig, nil
}

// SchnorrVerify verifies a blind Schnorr signature on the given message.
func SchnorrVerify(message []byte, sig *SchnorrSignature, pk *SchnorrPublicKey) bool {
	if sig == nil || sig.S == nil || sig.Rx == nil || sig.Ry == nil {
		return false
	}
	if sig.S.Cmp(bigZero) <= 0 || sig.S.Cmp(curveL) >= 0 {
		return false
	}
	if !curve.IsOnCurve(sig.Rx, sig.Ry) {
		return false
	}

	ePrime := schnorrHashChallenge(sig.Rx, sig.Ry, pk, message)
	return schnorrVerifyInternal(sig, pk, ePrime)
}

// schnorrVerifyInternal checks s'·B == R' + e'·A.
func schnorrVerifyInternal(sig *SchnorrSignature, pk *SchnorrPublicKey, ePrime *big.Int) bool {
	// LHS: s'·B
	lhsx, lhsy := curve.ScalarBaseMult(sig.S.Bytes())

	// RHS: R' + e'·A
	eAx, eAy := curve.ScalarMult(pk.x, pk.y, ePrime.Bytes())
	rhsx, rhsy := curve.Add(sig.Rx, sig.Ry, eAx, eAy)

	return lhsx.Cmp(rhsx) == 0 && lhsy.Cmp(rhsy) == 0
}

// SchnorrBlindSign runs the full blind Schnorr protocol locally (convenience).
func SchnorrBlindSign(message []byte, sk *SchnorrPrivateKey) (*SchnorrSignature, error) {
	pk := sk.PublicKey()

	state, commitment, err := SchnorrSignerCommit()
	if err != nil {
		return nil, err
	}

	clientState, challenge, err := SchnorrClientChallenge(message, commitment, pk)
	if err != nil {
		return nil, err
	}

	response, err := SchnorrSignerRespond(state, challenge, sk)
	if err != nil {
		return nil, err
	}

	return SchnorrClientUnblind(clientState, response, pk)
}

// Bytes returns the 64-byte encoding of the signature: R' (32 bytes) || s' (32 bytes).
func (sig *SchnorrSignature) Bytes() []byte {
	out := make([]byte, 64)
	rBytes := ed.NewPublicKey(sig.Rx, sig.Ry).Serialize()
	copy(out[:32], rBytes)
	sB := sig.S.Bytes()
	copy(out[64-len(sB):], sB)
	return out
}

// ParseSchnorrSignature parses a 64-byte signature.
func ParseSchnorrSignature(data []byte) (*SchnorrSignature, error) {
	if len(data) != 64 {
		return nil, errors.New("blindsig: invalid Schnorr signature size")
	}

	rPub, err := ed.ParsePubKey(data[:32])
	if err != nil {
		return nil, errors.New("blindsig: invalid R' point in signature")
	}

	s := new(big.Int).SetBytes(data[32:])
	if s.Cmp(curveL) >= 0 {
		return nil, errors.New("blindsig: s' out of range")
	}

	return &SchnorrSignature{Rx: rPub.X, Ry: rPub.Y, S: s}, nil
}

// schnorrHashChallenge computes e' = SHA-512(R' || A || msg) mod L.
func schnorrHashChallenge(rx, ry *big.Int, pk *SchnorrPublicKey, message []byte) *big.Int {
	h := sha512.New()
	h.Write(ed.NewPublicKey(rx, ry).Serialize())
	h.Write(ed.NewPublicKey(pk.x, pk.y).Serialize())
	h.Write(message)
	digest := h.Sum(nil) // 64 bytes

	e := new(big.Int).SetBytes(digest)
	e.Mod(e, curveL)
	return e
}
