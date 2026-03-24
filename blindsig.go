// Package blindsig implements RSA blind signatures using full-domain hashing.
//
// Blind signatures allow a signer to sign a message without learning its
// content, providing unlinkability between the signing request and the
// resulting signature.
package blindsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
)

// ErrInvalidSignature is returned when a blind signature fails verification.
var ErrInvalidSignature = errors.New("invalid blind signature")

// minKeyBits is the minimum RSA key size per NIST SP 800-57.
const minKeyBits = 3072

// GenerateBlindSigningKey generates an RSA private key suitable for blind
// signing. bits must be at least 3072.
func GenerateBlindSigningKey(bits int) (*rsa.PrivateKey, error) {
	if bits < minKeyBits {
		return nil, errors.New("blindsig: key size must be at least 3072 bits")
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// BlindMessage blinds a message so it can be sent to a signer without
// revealing its content. It returns the blinded value and the blinding factor
// needed to later unblind the signature.
func BlindMessage(message []byte, pubKey *rsa.PublicKey) (blinded *big.Int, blindingFactor *big.Int, err error) {
	n := pubKey.N
	e := big.NewInt(int64(pubKey.E))

	// Full-domain hash of the message
	m := fdh(message, n)

	// Pick a random blinding factor r ∈ [1, n) coprime to n
	r, err := randomCoprime(rand.Reader, n)
	if err != nil {
		return nil, nil, err
	}

	// blinded = m · r^e mod n
	re := new(big.Int).Exp(r, e, n) // r^e mod n
	blinded = new(big.Int).Mul(m, re)
	blinded.Mod(blinded, n)

	return blinded, r, nil
}

// SignBlinded signs a blinded message using the signer's private key.
// The signer never sees the original message.
//
// Internally this uses CRT exponentiation with random timing blinding and
// Shamir fault detection.
func SignBlinded(blinded *big.Int, privKey *rsa.PrivateKey) (*big.Int, error) {
	n := privKey.PublicKey.N
	e := big.NewInt(int64(privKey.PublicKey.E))
	d := privKey.D

	if blinded.Sign() <= 0 || blinded.Cmp(n) >= 0 {
		return nil, errors.New("blindsig: blinded value out of range")
	}

	// Timing blinding: pick random t coprime to n, compute t^e and t^d,
	// then compute signature on (blinded · t^e) and remove t^d afterward.
	t, err := randomCoprime(rand.Reader, n)
	if err != nil {
		return nil, err
	}
	te := new(big.Int).Exp(t, e, n)
	masked := new(big.Int).Mul(blinded, te)
	masked.Mod(masked, n)

	// CRT exponentiation on the masked input
	sig := crtExp(masked, privKey)

	// Remove timing blinding: sig = sig · t^{-1} mod n
	// Since t^d = (t^e)^d / t^{ed} = t mod n ... no, we need t^{-1}.
	// We have sig = masked^d = (blinded · t^e)^d = blinded^d · t^{ed} = blinded^d · t mod n
	// So: blinded^d = sig · t^{-1} mod n
	tInv := new(big.Int).ModInverse(t, n)
	if tInv == nil {
		return nil, errors.New("blindsig: failed to invert timing blinding factor")
	}
	sig.Mul(sig, tInv)
	sig.Mod(sig, n)

	// Use d to re-derive for Shamir check only if CRT wasn't used.
	// Shamir fault detection: verify sig^e == blinded mod n
	check := new(big.Int).Exp(sig, e, n)
	if check.Cmp(blinded) != 0 {
		// Fault detected — fall back to non-CRT exponentiation
		sig = new(big.Int).Exp(blinded, d, n)
		check = new(big.Int).Exp(sig, e, n)
		if check.Cmp(blinded) != 0 {
			return nil, errors.New("blindsig: signature verification failed after fault recovery")
		}
	}

	return sig, nil
}

// UnblindSignature removes the blinding factor from a blind signature,
// yielding a valid signature on the original message.
func UnblindSignature(blindSig *big.Int, blindingFactor *big.Int, pubKey *rsa.PublicKey) (*big.Int, error) {
	n := pubKey.N

	// r^{-1} mod n
	rInv := new(big.Int).ModInverse(blindingFactor, n)
	if rInv == nil {
		return nil, errors.New("blindsig: blinding factor is not invertible")
	}

	// sig = blindSig · r^{-1} mod n
	sig := new(big.Int).Mul(blindSig, rInv)
	sig.Mod(sig, n)

	return sig, nil
}

// VerifySignature verifies that signature is a valid signature on message
// under the given public key.
func VerifySignature(message []byte, signature *big.Int, pubKey *rsa.PublicKey) bool {
	n := pubKey.N
	e := big.NewInt(int64(pubKey.E))

	// Full-domain hash of the message (same as used during blinding)
	m := fdh(message, n)

	// sig^e mod n should equal m
	v := new(big.Int).Exp(signature, e, n)
	return v.Cmp(m) == 0
}

// fdh computes a full-domain hash of data, producing a value in [0, n).
// It uses MGF1 with SHA-256 to expand the hash to the byte length of n,
// then reduces mod n.
func fdh(data []byte, n *big.Int) *big.Int {
	nLen := (n.BitLen() + 7) / 8

	// Hash the input first with SHA-256 to get a fixed-size seed
	seed := sha256.Sum256(data)

	// MGF1-SHA256 expansion to nLen bytes
	expanded := mgf1SHA256(seed[:], nLen)

	// Interpret as big-endian integer and reduce mod n
	m := new(big.Int).SetBytes(expanded)
	m.Mod(m, n)
	return m
}

// mgf1SHA256 implements MGF1 with SHA-256 as defined in PKCS#1 v2.1 / RFC 8017.
func mgf1SHA256(seed []byte, length int) []byte {
	var out []byte
	var counter [4]byte
	for i := 0; len(out) < length; i++ {
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)

		h := sha256.New()
		h.Write(seed)
		h.Write(counter[:])
		out = append(out, h.Sum(nil)...)
	}
	return out[:length]
}

// randomCoprime returns a random integer in [1, n) that is coprime to n.
func randomCoprime(random io.Reader, n *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	// n-2 so we can add 1 to get range [1, n-1]
	nMinus1 := new(big.Int).Sub(n, one)
	for {
		r, err := rand.Int(random, nMinus1)
		if err != nil {
			return nil, err
		}
		r.Add(r, one) // r ∈ [1, n-1]
		if new(big.Int).GCD(nil, nil, r, n).Cmp(one) == 0 {
			return r, nil
		}
	}
}

// crtExp computes blinded^d mod n using CRT with the precomputed values
// in the RSA private key.
func crtExp(input *big.Int, privKey *rsa.PrivateKey) *big.Int {
	privKey.Precompute()

	p := privKey.Primes[0]
	q := privKey.Primes[1]

	// dp = d mod (p-1), dq = d mod (q-1)
	dp := new(big.Int).Mod(privKey.D, new(big.Int).Sub(p, big.NewInt(1)))
	dq := new(big.Int).Mod(privKey.D, new(big.Int).Sub(q, big.NewInt(1)))

	// mp = input^dp mod p
	mp := new(big.Int).Exp(new(big.Int).Mod(input, p), dp, p)
	// mq = input^dq mod q
	mq := new(big.Int).Exp(new(big.Int).Mod(input, q), dq, q)

	// CRT recombination: h = (mp - mq) · qInv mod p
	qInv := privKey.Precomputed.Qinv
	h := new(big.Int).Sub(mp, mq)
	if h.Sign() < 0 {
		h.Add(h, p)
	}
	h.Mul(h, qInv)
	h.Mod(h, p)

	// result = mq + h·q
	result := new(big.Int).Mul(h, q)
	result.Add(result, mq)

	return result
}
