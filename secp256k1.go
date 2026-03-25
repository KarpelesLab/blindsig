package blindsig

import (
	"crypto/rand"
	"errors"

	"github.com/KarpelesLab/blake256"
	"github.com/KarpelesLab/secp256k1"
)

// Secp256k1PublicKey is a public key for blind signatures over secp256k1.
type Secp256k1PublicKey struct {
	key *secp256k1.PublicKey
}

// Secp256k1PrivateKey is a private key for blind signatures over secp256k1.
type Secp256k1PrivateKey struct {
	key *secp256k1.PrivateKey
	pk  *Secp256k1PublicKey
}

// Secp256k1SignerState holds the signer's ephemeral state for one signing session.
type Secp256k1SignerState struct {
	k secp256k1.ModNScalar    // nonce
	R secp256k1.JacobianPoint // commitment R = kG
}

// Secp256k1ClientState holds the client's state between protocol rounds.
type Secp256k1ClientState struct {
	alpha  secp256k1.ModNScalar    // blinding scalar for response
	beta   secp256k1.ModNScalar    // blinding scalar for challenge
	rPrime secp256k1.JacobianPoint // R' (blinded commitment)
	ePrime secp256k1.ModNScalar    // e' = H(R'.x || msg)
}

// Secp256k1Signature is a blind signature (64 bytes: R'.x || s').
type Secp256k1Signature struct {
	R secp256k1.FieldVal   // R'.x (x-coordinate only)
	S secp256k1.ModNScalar // s'
}

// GenerateSecp256k1Key generates a key pair for blind signatures over secp256k1.
func GenerateSecp256k1Key() (*Secp256k1PrivateKey, *Secp256k1PublicKey, error) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	pub := key.PubKey()
	pk := &Secp256k1PublicKey{key: pub}
	sk := &Secp256k1PrivateKey{key: key, pk: pk}
	return sk, pk, nil
}

// PublicKey returns the public key for this private key.
func (sk *Secp256k1PrivateKey) PublicKey() *Secp256k1PublicKey {
	return sk.pk
}

// Bytes returns the 33-byte compressed encoding of the public key.
func (pk *Secp256k1PublicKey) Bytes() []byte {
	return pk.key.SerializeCompressed()
}

// ParseSecp256k1PublicKey parses a 33-byte compressed public key.
func ParseSecp256k1PublicKey(data []byte) (*Secp256k1PublicKey, error) {
	pub, err := secp256k1.ParsePubKey(data)
	if err != nil {
		return nil, err
	}
	return &Secp256k1PublicKey{key: pub}, nil
}

// Secp256k1SignerCommit starts a blind signing session (Round 1).
// The signer picks a random nonce k and returns the commitment R = kG (33 bytes compressed).
func Secp256k1SignerCommit() (*Secp256k1SignerState, []byte, error) {
	// Random nonce k
	var kBytes [32]byte
	if _, err := rand.Read(kBytes[:]); err != nil {
		return nil, nil, err
	}
	var k secp256k1.ModNScalar
	k.SetBytes(&kBytes)
	if k.IsZero() {
		return nil, nil, errors.New("blindsig: generated zero nonce")
	}

	// R = kG, negate k if R.y is odd (BIP-340 convention)
	var R secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&k, &R)
	R.ToAffine()
	if R.Y.IsOdd() {
		k.Negate()
		secp256k1.ScalarBaseMultNonConst(&k, &R)
		R.ToAffine()
	}

	state := &Secp256k1SignerState{k: k, R: R}

	// Serialize R as compressed point
	pub := secp256k1.NewPublicKey(&R.X, &R.Y)
	return state, pub.SerializeCompressed(), nil
}

// Secp256k1ClientChallenge creates a blinded challenge from the signer's commitment (Round 2).
//
// BIP-340 convention: s = k - e·x, verification R = s·G + e·P.
// Blinding: R' = R - αG - βP, e' = H(R'.x || msg), e = e' + β, s' = s - α.
// The client retries blinding if R'.y is odd (BIP-340 requires even y).
func Secp256k1ClientChallenge(hash, commitment []byte, pk *Secp256k1PublicKey) (*Secp256k1ClientState, []byte, error) {
	if len(hash) != 32 {
		return nil, nil, errors.New("blindsig: hash must be 32 bytes")
	}

	// Parse commitment R
	rPub, err := secp256k1.ParsePubKey(commitment)
	if err != nil {
		return nil, nil, errors.New("blindsig: invalid secp256k1 commitment")
	}
	var R secp256k1.JacobianPoint
	rPub.AsJacobian(&R)

	var Q secp256k1.JacobianPoint
	pk.key.AsJacobian(&Q)

	// Try random α, β until R'.y is even
	for attempts := 0; attempts < 1000; attempts++ {
		var alphaBytes, betaBytes [32]byte
		rand.Read(alphaBytes[:])
		rand.Read(betaBytes[:])

		var alpha, beta secp256k1.ModNScalar
		alpha.SetBytes(&alphaBytes)
		beta.SetBytes(&betaBytes)

		// R' = R - αG - βP
		var aG, bP, tmp, rPrime secp256k1.JacobianPoint
		var negAlpha, negBeta secp256k1.ModNScalar
		negAlpha.NegateVal(&alpha)
		negBeta.NegateVal(&beta)
		secp256k1.ScalarBaseMultNonConst(&negAlpha, &aG) // -αG
		secp256k1.ScalarMultNonConst(&negBeta, &Q, &bP)  // -βP
		secp256k1.AddNonConst(&R, &aG, &tmp)             // R - αG
		secp256k1.AddNonConst(&tmp, &bP, &rPrime)        // R - αG - βP
		rPrime.ToAffine()

		// BIP-340: R'.y must be even
		if rPrime.Y.IsOdd() {
			continue
		}

		// e' = BLAKE-256(R'.x || hash)
		var ePrime secp256k1.ModNScalar
		var commitInput [64]byte
		rPrime.X.PutBytesUnchecked(commitInput[:32])
		copy(commitInput[32:], hash)
		eHash := blake256.Sum256(commitInput[:])
		if overflow := ePrime.SetBytes(&eHash); overflow != 0 {
			continue
		}

		// e = e' + β
		var e secp256k1.ModNScalar
		e.Add2(&ePrime, &beta)

		state := &Secp256k1ClientState{
			alpha:  alpha,
			beta:   beta,
			rPrime: rPrime,
			ePrime: ePrime,
		}

		eBytes := e.Bytes()
		return state, eBytes[:], nil
	}

	return nil, nil, errors.New("blindsig: failed to find blinding with even R'.y")
}

// Secp256k1SignerRespond computes the signer's response (Round 3).
// BIP-340 convention: s = k - e·x (negating k if R.y is odd).
func Secp256k1SignerRespond(state *Secp256k1SignerState, challenge []byte, sk *Secp256k1PrivateKey) ([]byte, error) {
	if len(challenge) != 32 {
		return nil, errors.New("blindsig: invalid challenge size")
	}

	var e secp256k1.ModNScalar
	var eBytes [32]byte
	copy(eBytes[:], challenge)
	e.SetBytes(&eBytes)

	// k was already adjusted at commit time so R.y is even
	k := state.k

	// s = k - e·x
	var s secp256k1.ModNScalar
	s.Mul2(&e, &sk.key.Key).Negate().Add(&k)

	sBytes := s.Bytes()
	return sBytes[:], nil
}

// Secp256k1ClientUnblind removes the blinding to produce the final signature.
// s' = s - α. Signature = (R'.x, s').
func Secp256k1ClientUnblind(state *Secp256k1ClientState, response []byte, pk *Secp256k1PublicKey) (*Secp256k1Signature, error) {
	if len(response) != 32 {
		return nil, errors.New("blindsig: invalid response size")
	}

	var s secp256k1.ModNScalar
	var sBytes [32]byte
	copy(sBytes[:], response)
	s.SetBytes(&sBytes)

	// s' = s - α
	var negAlpha secp256k1.ModNScalar
	negAlpha.NegateVal(&state.alpha)
	var sPrime secp256k1.ModNScalar
	sPrime.Add2(&s, &negAlpha)

	sig := &Secp256k1Signature{S: sPrime}
	sig.R.Set(&state.rPrime.X)

	// Verify before returning
	if !secp256k1VerifyInternal(sig, pk, &state.ePrime) {
		return nil, errors.New("blindsig: signature verification failed after unblinding")
	}

	return sig, nil
}

// Secp256k1Verify verifies a blind secp256k1 signature.
// BIP-340 verification: R = s·G + e·P, check R.x == sig.R and R.y is even.
func Secp256k1Verify(hash []byte, sig *Secp256k1Signature, pk *Secp256k1PublicKey) bool {
	if sig == nil || len(hash) != 32 {
		return false
	}

	// e = BLAKE-256(R.x || hash)
	var e secp256k1.ModNScalar
	var commitInput [64]byte
	sig.R.PutBytesUnchecked(commitInput[:32])
	copy(commitInput[32:], hash)
	eHash := blake256.Sum256(commitInput[:])
	if overflow := e.SetBytes(&eHash); overflow != 0 {
		return false
	}

	return secp256k1VerifyInternal(sig, pk, &e)
}

// secp256k1VerifyInternal checks s·G + e·P == R (with even y).
func secp256k1VerifyInternal(sig *Secp256k1Signature, pk *Secp256k1PublicKey, e *secp256k1.ModNScalar) bool {
	// R = s·G + e·P
	var Q, sG, eQ, R secp256k1.JacobianPoint
	pk.key.AsJacobian(&Q)
	secp256k1.ScalarBaseMultNonConst(&sig.S, &sG)
	secp256k1.ScalarMultNonConst(e, &Q, &eQ)
	secp256k1.AddNonConst(&sG, &eQ, &R)

	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		return false
	}

	R.ToAffine()

	if R.Y.IsOdd() {
		return false
	}

	return sig.R.Equals(&R.X)
}

// Secp256k1BlindSign runs the full blind protocol locally (convenience).
// hash must be 32 bytes (pre-hashed message).
func Secp256k1BlindSign(hash []byte, sk *Secp256k1PrivateKey) (*Secp256k1Signature, error) {
	pk := sk.PublicKey()

	state, commitment, err := Secp256k1SignerCommit()
	if err != nil {
		return nil, err
	}
	clientState, challenge, err := Secp256k1ClientChallenge(hash, commitment, pk)
	if err != nil {
		return nil, err
	}
	response, err := Secp256k1SignerRespond(state, challenge, sk)
	if err != nil {
		return nil, err
	}
	return Secp256k1ClientUnblind(clientState, response, pk)
}

// Bytes returns the 64-byte encoding: R'.x (32 bytes) || s' (32 bytes).
func (sig *Secp256k1Signature) Bytes() []byte {
	var out [64]byte
	sig.R.PutBytesUnchecked(out[:32])
	sig.S.PutBytesUnchecked(out[32:])
	return out[:]
}

// ParseSecp256k1Signature parses a 64-byte signature.
func ParseSecp256k1Signature(data []byte) (*Secp256k1Signature, error) {
	if len(data) != 64 {
		return nil, errors.New("blindsig: invalid secp256k1 signature size")
	}
	var sig Secp256k1Signature
	sig.R.SetByteSlice(data[:32])
	sig.R.Normalize()
	var sBytes [32]byte
	copy(sBytes[:], data[32:])
	sig.S.SetBytes(&sBytes)
	return &sig, nil
}
