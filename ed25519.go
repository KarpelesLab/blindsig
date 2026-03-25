package blindsig

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"

	ed "github.com/KarpelesLab/edwards25519"
)

var (
	ed25519Curve = ed.Edwards()
	ed25519L     = ed25519Curve.N  // group order
	ed25519Gx    = ed25519Curve.Gx // base point x
	ed25519Gy    = ed25519Curve.Gy // base point y
)

// Ed25519PublicKey is a public key for blind signatures over Ed25519.
type Ed25519PublicKey struct {
	x, y *big.Int
}

// Ed25519PrivateKey is a private key for blind signatures over Ed25519.
type Ed25519PrivateKey struct {
	a  *big.Int
	pk *Ed25519PublicKey
}

// Ed25519SignerState holds the signer's ephemeral state for one signing session.
type Ed25519SignerState struct {
	k      *big.Int
	rx, ry *big.Int
}

// Ed25519ClientState holds the client's state between protocol rounds.
type Ed25519ClientState struct {
	alpha    *big.Int
	beta     *big.Int
	rpx, rpy *big.Int
	ePrime   *big.Int
}

// Ed25519Signature is a blind signature (64 bytes: R' || s').
type Ed25519Signature struct {
	Rx, Ry *big.Int
	S      *big.Int
}

// GenerateEd25519Key generates a key pair for blind signatures over Ed25519.
func GenerateEd25519Key() (*Ed25519PrivateKey, *Ed25519PublicKey, error) {
	a, err := rand.Int(rand.Reader, new(big.Int).Sub(ed25519L, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}
	a.Add(a, big.NewInt(1))

	ax, ay := ed25519Curve.ScalarBaseMult(a.Bytes())

	pk := &Ed25519PublicKey{x: ax, y: ay}
	sk := &Ed25519PrivateKey{a: a, pk: pk}
	return sk, pk, nil
}

// PublicKey returns the public key for this private key.
func (sk *Ed25519PrivateKey) PublicKey() *Ed25519PublicKey {
	return sk.pk
}

// Bytes returns the 32-byte compressed encoding of the public key.
func (pk *Ed25519PublicKey) Bytes() []byte {
	return ed.NewPublicKey(pk.x, pk.y).Serialize()
}

// ParseEd25519PublicKey parses a 32-byte compressed public key.
func ParseEd25519PublicKey(data []byte) (*Ed25519PublicKey, error) {
	p, err := ed.ParsePubKey(data)
	if err != nil {
		return nil, err
	}
	return &Ed25519PublicKey{x: p.X, y: p.Y}, nil
}

// Ed25519SignerCommit starts a blind signing session (Round 1).
// The signer picks a random nonce k and returns the commitment R = kB (32 bytes).
func Ed25519SignerCommit() (*Ed25519SignerState, []byte, error) {
	k, err := rand.Int(rand.Reader, new(big.Int).Sub(ed25519L, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}
	k.Add(k, big.NewInt(1))

	rx, ry := ed25519Curve.ScalarBaseMult(k.Bytes())

	state := &Ed25519SignerState{k: k, rx: rx, ry: ry}
	commitment := ed.NewPublicKey(rx, ry).Serialize()
	return state, commitment, nil
}

// Ed25519ClientChallenge creates a blinded challenge from the signer's commitment (Round 2).
// Computes R' = R + αB + βA, e' = H(R' || A || msg), sends e = e' + β.
func Ed25519ClientChallenge(message, commitment []byte, pk *Ed25519PublicKey) (*Ed25519ClientState, []byte, error) {
	rPub, err := ed.ParsePubKey(commitment)
	if err != nil {
		return nil, nil, errors.New("blindsig: invalid Ed25519 commitment")
	}
	rx, ry := rPub.X, rPub.Y

	alpha, err := rand.Int(rand.Reader, ed25519L)
	if err != nil {
		return nil, nil, err
	}
	beta, err := rand.Int(rand.Reader, ed25519L)
	if err != nil {
		return nil, nil, err
	}

	// R' = R + αB + βA
	aGx, aGy := ed25519Curve.ScalarBaseMult(alpha.Bytes())
	bAx, bAy := ed25519Curve.ScalarMult(pk.x, pk.y, beta.Bytes())
	tmpx, tmpy := ed25519Curve.Add(rx, ry, aGx, aGy)
	rpx, rpy := ed25519Curve.Add(tmpx, tmpy, bAx, bAy)

	ePrime := ed25519HashChallenge(rpx, rpy, pk, message)

	e := new(big.Int).Add(ePrime, beta)
	e.Mod(e, ed25519L)

	state := &Ed25519ClientState{
		alpha: alpha, beta: beta,
		rpx: rpx, rpy: rpy,
		ePrime: ePrime,
	}

	eBytes := make([]byte, 32)
	eB := e.Bytes()
	copy(eBytes[32-len(eB):], eB)
	return state, eBytes, nil
}

// Ed25519SignerRespond computes the signer's response (Round 3).
// s = k + e·a mod L.
func Ed25519SignerRespond(state *Ed25519SignerState, challenge []byte, sk *Ed25519PrivateKey) ([]byte, error) {
	if len(challenge) != 32 {
		return nil, errors.New("blindsig: invalid challenge size")
	}

	e := new(big.Int).SetBytes(challenge)
	if e.Cmp(ed25519L) >= 0 {
		return nil, errors.New("blindsig: challenge out of range")
	}

	s := new(big.Int).Mul(e, sk.a)
	s.Add(s, state.k)
	s.Mod(s, ed25519L)

	sBytes := make([]byte, 32)
	sB := s.Bytes()
	copy(sBytes[32-len(sB):], sB)
	return sBytes, nil
}

// Ed25519ClientUnblind removes the blinding to produce the final signature.
// s' = s + α mod L. Signature = (R', s').
func Ed25519ClientUnblind(state *Ed25519ClientState, response []byte, pk *Ed25519PublicKey) (*Ed25519Signature, error) {
	if len(response) != 32 {
		return nil, errors.New("blindsig: invalid response size")
	}

	s := new(big.Int).SetBytes(response)

	sPrime := new(big.Int).Add(s, state.alpha)
	sPrime.Mod(sPrime, ed25519L)

	sig := &Ed25519Signature{Rx: state.rpx, Ry: state.rpy, S: sPrime}

	if !ed25519VerifyInternal(sig, pk, state.ePrime) {
		return nil, errors.New("blindsig: signature verification failed after unblinding")
	}

	return sig, nil
}

// Ed25519Verify verifies a blind signature on the given message.
func Ed25519Verify(message []byte, sig *Ed25519Signature, pk *Ed25519PublicKey) bool {
	if sig == nil || sig.S == nil || sig.Rx == nil || sig.Ry == nil {
		return false
	}
	if sig.S.Sign() <= 0 || sig.S.Cmp(ed25519L) >= 0 {
		return false
	}
	if !ed25519Curve.IsOnCurve(sig.Rx, sig.Ry) {
		return false
	}

	ePrime := ed25519HashChallenge(sig.Rx, sig.Ry, pk, message)
	return ed25519VerifyInternal(sig, pk, ePrime)
}

// ed25519VerifyInternal checks s'·B == R' + e'·A.
func ed25519VerifyInternal(sig *Ed25519Signature, pk *Ed25519PublicKey, ePrime *big.Int) bool {
	lhsx, lhsy := ed25519Curve.ScalarBaseMult(sig.S.Bytes())
	eAx, eAy := ed25519Curve.ScalarMult(pk.x, pk.y, ePrime.Bytes())
	rhsx, rhsy := ed25519Curve.Add(sig.Rx, sig.Ry, eAx, eAy)
	return lhsx.Cmp(rhsx) == 0 && lhsy.Cmp(rhsy) == 0
}

// Ed25519BlindSign runs the full blind protocol locally (convenience).
func Ed25519BlindSign(message []byte, sk *Ed25519PrivateKey) (*Ed25519Signature, error) {
	pk := sk.PublicKey()

	state, commitment, err := Ed25519SignerCommit()
	if err != nil {
		return nil, err
	}
	clientState, challenge, err := Ed25519ClientChallenge(message, commitment, pk)
	if err != nil {
		return nil, err
	}
	response, err := Ed25519SignerRespond(state, challenge, sk)
	if err != nil {
		return nil, err
	}
	return Ed25519ClientUnblind(clientState, response, pk)
}

// Bytes returns the 64-byte encoding: R' (32 bytes) || s' (32 bytes).
func (sig *Ed25519Signature) Bytes() []byte {
	out := make([]byte, 64)
	copy(out[:32], ed.NewPublicKey(sig.Rx, sig.Ry).Serialize())
	sB := sig.S.Bytes()
	copy(out[64-len(sB):], sB)
	return out
}

// ParseEd25519Signature parses a 64-byte signature.
func ParseEd25519Signature(data []byte) (*Ed25519Signature, error) {
	if len(data) != 64 {
		return nil, errors.New("blindsig: invalid Ed25519 signature size")
	}
	rPub, err := ed.ParsePubKey(data[:32])
	if err != nil {
		return nil, errors.New("blindsig: invalid R' point in signature")
	}
	s := new(big.Int).SetBytes(data[32:])
	if s.Cmp(ed25519L) >= 0 {
		return nil, errors.New("blindsig: s' out of range")
	}
	return &Ed25519Signature{Rx: rPub.X, Ry: rPub.Y, S: s}, nil
}

// ed25519HashChallenge computes e' = SHA-512(R' || A || msg) mod L.
func ed25519HashChallenge(rx, ry *big.Int, pk *Ed25519PublicKey, message []byte) *big.Int {
	h := sha512.New()
	h.Write(ed.NewPublicKey(rx, ry).Serialize())
	h.Write(ed.NewPublicKey(pk.x, pk.y).Serialize())
	h.Write(message)
	digest := h.Sum(nil)
	e := new(big.Int).SetBytes(digest)
	e.Mod(e, ed25519L)
	return e
}
