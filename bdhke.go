package blindsig

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	ed "github.com/KarpelesLab/edwards25519"
)

// BDHKEMintPublicKey is the mint's public key K = kG.
type BDHKEMintPublicKey struct {
	x, y *big.Int
}

// BDHKEMintPrivateKey is the mint's secret key k.
type BDHKEMintPrivateKey struct {
	k  *big.Int
	pk *BDHKEMintPublicKey
}

// BDHKEBlindedMessage is a blinded token B' = Y + rG sent to the mint.
type BDHKEBlindedMessage struct {
	x, y *big.Int
}

// BDHKEBlindSignature is the mint's blind signature C' = k·B'.
type BDHKEBlindSignature struct {
	x, y *big.Int
}

// BDHKEToken is an unblinded token (x, C) where C = k·hash_to_curve(x).
type BDHKEToken struct {
	Secret []byte   // x — the user's secret
	Cx, Cy *big.Int // C = k·Y where Y = hash_to_curve(x)
}

// BDHKEBlindingState holds the client's blinding factor for unblinding.
type BDHKEBlindingState struct {
	r *big.Int // blinding factor
}

// GenerateBDHKEMintKey generates a mint key pair for BDHKE.
func GenerateBDHKEMintKey() (*BDHKEMintPrivateKey, *BDHKEMintPublicKey, error) {
	k, err := rand.Int(rand.Reader, new(big.Int).Sub(ed25519L, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}
	k.Add(k, big.NewInt(1))

	kx, ky := ed25519Curve.ScalarBaseMult(k.Bytes())

	pk := &BDHKEMintPublicKey{x: kx, y: ky}
	sk := &BDHKEMintPrivateKey{k: k, pk: pk}
	return sk, pk, nil
}

// PublicKey returns the mint's public key.
func (sk *BDHKEMintPrivateKey) PublicKey() *BDHKEMintPublicKey {
	return sk.pk
}

// Bytes returns the 32-byte compressed public key.
func (pk *BDHKEMintPublicKey) Bytes() []byte {
	return ed.NewPublicKey(pk.x, pk.y).Serialize()
}

// ParseBDHKEMintPublicKey parses a 32-byte compressed public key.
func ParseBDHKEMintPublicKey(data []byte) (*BDHKEMintPublicKey, error) {
	p, err := ed.ParsePubKey(data)
	if err != nil {
		return nil, err
	}
	return &BDHKEMintPublicKey{x: p.X, y: p.Y}, nil
}

// BDHKEBlind blinds a secret for sending to the mint.
// Computes Y = hash_to_curve(secret), B' = Y + rG.
// Returns the blinded message and the blinding state needed for unblinding.
func BDHKEBlind(secret []byte) (*BDHKEBlindingState, *BDHKEBlindedMessage, error) {
	// Y = hash_to_curve(secret)
	yx, yy := bdhkeHashToCurve(secret)

	// Random blinding factor r
	r, err := rand.Int(rand.Reader, ed25519L)
	if err != nil {
		return nil, nil, err
	}

	// B' = Y + rG
	rgx, rgy := ed25519Curve.ScalarBaseMult(r.Bytes())
	bx, by := ed25519Curve.Add(yx, yy, rgx, rgy)

	state := &BDHKEBlindingState{r: r}
	blinded := &BDHKEBlindedMessage{x: bx, y: by}
	return state, blinded, nil
}

// BDHKESign creates a blind signature on a blinded message.
// The mint computes C' = k·B' without learning the secret.
func BDHKESign(blinded *BDHKEBlindedMessage, sk *BDHKEMintPrivateKey) (*BDHKEBlindSignature, error) {
	if blinded == nil {
		return nil, errors.New("blindsig: nil blinded message")
	}
	if !ed25519Curve.IsOnCurve(blinded.x, blinded.y) {
		return nil, errors.New("blindsig: blinded message not on curve")
	}

	// C' = k·B'
	cx, cy := ed25519Curve.ScalarMult(blinded.x, blinded.y, sk.k.Bytes())

	return &BDHKEBlindSignature{x: cx, y: cy}, nil
}

// BDHKEUnblind removes the blinding to produce a valid token.
// C = C' - r·K where K is the mint's public key.
func BDHKEUnblind(secret []byte, blindSig *BDHKEBlindSignature, state *BDHKEBlindingState, mintPub *BDHKEMintPublicKey) (*BDHKEToken, error) {
	if blindSig == nil || state == nil || mintPub == nil {
		return nil, errors.New("blindsig: nil argument")
	}

	// r·K
	rkx, rky := ed25519Curve.ScalarMult(mintPub.x, mintPub.y, state.r.Bytes())

	// C = C' - r·K (subtract = add negation; negate y-coordinate on Edwards curve)
	// On twisted Edwards, -P = (-x, y) ... wait, actually on Edwards curve -P = (x, -y)? No...
	// For twisted Edwards ax² + y² = 1 + dx²y², negation is (-x, y).
	negRkx := new(big.Int).Neg(rkx)
	negRkx.Mod(negRkx, ed25519Curve.P)
	cx, cy := ed25519Curve.Add(blindSig.x, blindSig.y, negRkx, rky)

	return &BDHKEToken{
		Secret: append([]byte{}, secret...),
		Cx:     cx,
		Cy:     cy,
	}, nil
}

// BDHKEVerify verifies a token against the mint's secret key.
// Checks that C == k·hash_to_curve(secret).
// This is keyed verification — only the mint (with secret key k) can verify.
func BDHKEVerify(token *BDHKEToken, sk *BDHKEMintPrivateKey) bool {
	if token == nil || token.Cx == nil || token.Cy == nil {
		return false
	}

	// Y = hash_to_curve(secret)
	yx, yy := bdhkeHashToCurve(token.Secret)

	// Expected C = k·Y
	ex, ey := ed25519Curve.ScalarMult(yx, yy, sk.k.Bytes())

	return token.Cx.Cmp(ex) == 0 && token.Cy.Cmp(ey) == 0
}

// Bytes serializes a blinded message to 32 bytes (compressed point).
func (b *BDHKEBlindedMessage) Bytes() []byte {
	return ed.NewPublicKey(b.x, b.y).Serialize()
}

// ParseBDHKEBlindedMessage parses a 32-byte compressed blinded message.
func ParseBDHKEBlindedMessage(data []byte) (*BDHKEBlindedMessage, error) {
	p, err := ed.ParsePubKey(data)
	if err != nil {
		return nil, err
	}
	return &BDHKEBlindedMessage{x: p.X, y: p.Y}, nil
}

// Bytes serializes a blind signature to 32 bytes (compressed point).
func (s *BDHKEBlindSignature) Bytes() []byte {
	return ed.NewPublicKey(s.x, s.y).Serialize()
}

// ParseBDHKEBlindSignature parses a 32-byte compressed blind signature.
func ParseBDHKEBlindSignature(data []byte) (*BDHKEBlindSignature, error) {
	p, err := ed.ParsePubKey(data)
	if err != nil {
		return nil, err
	}
	return &BDHKEBlindSignature{x: p.X, y: p.Y}, nil
}

// Bytes serializes a token: 32-byte C point || secret.
func (t *BDHKEToken) Bytes() []byte {
	cBytes := ed.NewPublicKey(t.Cx, t.Cy).Serialize()
	out := make([]byte, 32+len(t.Secret))
	copy(out[:32], cBytes)
	copy(out[32:], t.Secret)
	return out
}

// bdhkeHashToCurve maps arbitrary bytes to a point on Ed25519 in the
// prime-order subgroup. Uses try-and-increment: hash with incrementing
// counter, try to decode as a compressed Ed25519 point, multiply by
// cofactor 8 to project into the prime-order subgroup.
func bdhkeHashToCurve(data []byte) (x, y *big.Int) {
	var buf [32]byte
	for counter := uint32(0); ; counter++ {
		h := sha256.New()
		h.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		h.Write([]byte("HashToCurve"))
		h.Write(data)
		copy(buf[:], h.Sum(nil))

		// Clear the sign bit for valid Ed25519 encoding
		buf[31] &= 0x7F

		// Try to decode as a compressed point
		p, err := ed.ParsePubKey(buf[:])
		if err != nil {
			continue
		}

		// Cofactor clearing: multiply by 8 to ensure prime-order subgroup
		px, py := ed25519Curve.ScalarMult(p.X, p.Y, big.NewInt(8).Bytes())

		// Skip if result is the identity point (0, 1)
		if px.Sign() == 0 && py.Cmp(big.NewInt(1)) == 0 {
			continue
		}

		return px, py
	}
}
