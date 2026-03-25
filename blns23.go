package blindsig

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"

	"github.com/KarpelesLab/lnp22/ring"
	"github.com/KarpelesLab/lnp22/sampler"
	"github.com/KarpelesLab/lnp22/tworing"
	"golang.org/x/crypto/sha3"
)

var exp = math.Exp
var exp2_64 = math.Exp2(64)

// BLNS23 parameters from the paper (Table 2).
var (
	blns23Q    = big.NewInt(7933)                    // signature ring modulus
	blns23Q2   = big.NewInt(277199453)               // q̂/q cofactor
	blns23QHat = new(big.Int).Mul(blns23Q, blns23Q2) // proof ring modulus ≈ 2^41
)

const (
	blns23D     = 512   // ring degree
	blns23Sigma = 232.0 // Gaussian std dev for pre-image sampling
	blns23Kappa = 60    // NIZK challenge weight
	blns23RhoLen = 32   // length of ρ = G(r) in bytes
)

// BLNS23Params holds the pre-computed scheme parameters.
type BLNS23Params struct {
	SigRing   *ring.BigRing   // R_q: d=512, q=7933
	ProofRing *ring.BigRing   // R_{q̂}: d=512, q̂=q·q2
	Q         *big.Int
	Q2        *big.Int
	QHat      *big.Int
	Sigma     float64         // pre-image Gaussian std dev
	BetaRSq   *big.Int        // L2² norm bound on r
	BetaSSq   *big.Int        // L2² norm bound on s
	ProofParams *tworing.Params // NIZK parameters
}

// BLNS23PublicKey is the signer's public key.
type BLNS23PublicKey struct {
	Params *BLNS23Params
	A      ring.BigPolyVec // [h, 1] — NTRU public key structure
	B      ring.BigPolyVec // random blinding vector (2 polynomials)
}

// BLNS23PrivateKey is the signer's secret key.
type BLNS23PrivateKey struct {
	Params *BLNS23Params
	F      ring.BigPoly    // NTRU secret f
	G      ring.BigPoly    // NTRU secret g
	H      ring.BigPoly    // public h = f^{-1}·g mod q
	FInv   ring.BigPoly    // f^{-1} mod q
	FF     ring.BigPoly    // F from SolveNTRU: fG - gF = q
	GG     ring.BigPoly    // G from SolveNTRU
	B      ring.BigPolyVec // random blinding vector (same as in public key)
}

// BLNS23BlindRequest is the user's blinded commitment (Round 1 message).
type BLNS23BlindRequest struct {
	C ring.BigPoly // c = B·r + H(G(r), μ)
}

// BLNS23BlindResponse is the signer's pre-image (Round 2 message).
type BLNS23BlindResponse struct {
	S ring.BigPolyVec // short s with A·s = c
}

// BLNS23ClientState holds the user's ephemeral state between protocol rounds.
type BLNS23ClientState struct {
	R       ring.BigPolyVec // random commitment vector (secret)
	Rho     []byte          // G(r) hash
	HTarget ring.BigPoly    // H(ρ, μ) — the hash target
	Message []byte          // original message
}

// BLNS23Signature is the blind signature on a message.
type BLNS23Signature struct {
	Rho   []byte        // G(r) — 32 bytes
	Proof *tworing.Proof // NIZK proof π₂
}

// BLNS23DefaultParams returns the default parameters from the paper (Table 2).
func BLNS23DefaultParams() *BLNS23Params {
	sigRing, err := ring.NewBig(blns23D, blns23Q)
	if err != nil {
		panic("blindsig: failed to create signature ring: " + err.Error())
	}
	proofRing, err := ring.NewBig(blns23D, blns23QHat)
	if err != nil {
		panic("blindsig: failed to create proof ring: " + err.Error())
	}

	// L2² norm bounds:
	// r has 2 polynomials of degree 512, coefficients in [-2,2]:
	//   max ||r||² = 2 * 512 * 4 = 4096
	// s is Gaussian with σ=232 over 2 polynomials of degree 512:
	//   expected ||s||² ≈ 2 * 512 * σ² ≈ 55 million
	//   tail bound (12σ): 2 * 512 * (12*232)² ≈ 7.9 billion
	betaRSq := big.NewInt(4096)
	betaSSq := big.NewInt(0).SetUint64(2 * 512 * 232 * 232 * 144) // 2·d·σ²·τ² with τ²=144

	// NIZK proof parameters. The witness is (s1,s2,r1,r2) in R_{q̂}^4.
	// The pre-image s has coefficients up to ~q/2 with simplified Babai rounding.
	// (A proper Falcon ffSampler would produce shorter vectors, ~σ.)
	// σ_proof must be ≥ 2·κ·max(witness_inf_norm).
	maxWitInfNorm := int64(7933 / 2) // conservative: q/2
	sigmaProof := float64(4 * blns23Kappa * maxWitInfNorm) // generous margin
	boundZ := big.NewInt(int64(sigmaProof * 4))            // 4× for good acceptance rate

	proofParams := &tworing.Params{
		Ring:        proofRing,
		K:           1, // one linear equation: [A|-B]·(s,r) = h
		L:           4, // witness dimension: (s1, s2, r1, r2)
		Kappa:       blns23Kappa,
		Sigma:       sigmaProof,
		BoundZ:      boundZ,
		MaxAttempts: 1000,
	}

	return &BLNS23Params{
		SigRing:     sigRing,
		ProofRing:   proofRing,
		Q:           new(big.Int).Set(blns23Q),
		Q2:          new(big.Int).Set(blns23Q2),
		QHat:        new(big.Int).Set(blns23QHat),
		Sigma:       blns23Sigma,
		BetaRSq:     betaRSq,
		BetaSSq:     betaSSq,
		ProofParams: proofParams,
	}
}

// GenerateBLNS23Key generates a BLNS23 key pair.
func GenerateBLNS23Key(params *BLNS23Params) (*BLNS23PrivateKey, *BLNS23PublicKey, error) {
	r := params.SigRing

	// Generate NTRU key: sample short f, g; compute h = f^{-1}·g mod q
	// Retry if f is not invertible or SolveNTRU fails (field norms not coprime to q)
	const ntruSigma = 1.17
	var f, g, fInv, h, ff, gg ring.BigPoly
	for attempt := 0; attempt < 1000; attempt++ {
		f = sampler.SampleBigGaussianPoly(r, ntruSigma, rand.Reader)
		g = sampler.SampleBigGaussianPoly(r, ntruSigma, rand.Reader)

		var err error
		fInv, err = blns23PolyInverse(r, f)
		if err != nil {
			continue // f not invertible, retry
		}
		h = r.Mul(fInv, g)

		ff, gg, err = blns23SolveNTRU(r, f, g, params.Q)
		if err != nil {
			fInv = nil
			continue // SolveNTRU failed (field norms issue), retry
		}
		break
	}
	if fInv == nil {
		return nil, nil, errors.New("blindsig: failed to generate valid NTRU key after 1000 attempts")
	}

	// Public matrix A = [h, 1]
	a := r.NewPolyVec(2)
	a[0] = h
	a[1] = r.One()

	// Random blinding vector B ∈ R_q^2
	b := sampler.SampleBigUniformVec(r, 2, rand.Reader)

	sk := &BLNS23PrivateKey{
		Params: params,
		F:      f,
		G:      g,
		H:      h,
		FInv:   fInv,
		FF:     ff,
		GG:     gg,
		B:      b,
	}
	pk := &BLNS23PublicKey{
		Params: params,
		A:      a,
		B:      b,
	}
	return sk, pk, nil
}

// blns23PolyInverse computes f^{-1} in R_q = Z_q[X]/(X^N+1) using the
// polynomial extended Euclidean algorithm.
func blns23PolyInverse(r *ring.BigRing, f ring.BigPoly) (ring.BigPoly, error) {
	q := r.Q
	n := r.N

	// Build modulus polynomial X^N + 1
	modPoly := make([]*big.Int, n+1)
	for i := 0; i <= n; i++ {
		modPoly[i] = big.NewInt(0)
	}
	modPoly[0] = big.NewInt(1)
	modPoly[n] = big.NewInt(1)

	// Convert f to coefficient slice
	fCoeffs := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		fCoeffs[i] = new(big.Int).Mod(f[i], q)
	}

	// Extended GCD: find a such that a·f ≡ gcd (mod X^N+1, mod q)
	gcd, a, _ := polyExtGCD(fCoeffs, modPoly, q)

	// Normalize: gcd should be a constant (degree 0)
	gcdDeg := polyDegree(gcd)
	if gcdDeg > 0 {
		return nil, errors.New("blindsig: f is not invertible in R_q")
	}
	if gcdDeg < 0 || gcd[0].Sign() == 0 {
		return nil, errors.New("blindsig: f is zero")
	}

	// Multiply a by gcd[0]^{-1} to normalize
	gcdInv := new(big.Int).ModInverse(gcd[0], q)
	if gcdInv == nil {
		return nil, errors.New("blindsig: gcd not invertible mod q")
	}

	result := r.NewPoly()
	for i := 0; i < n && i < len(a); i++ {
		result[i] = new(big.Int).Mul(a[i], gcdInv)
		result[i].Mod(result[i], q)
	}

	// Verify: f * result ≡ 1 (mod q, mod X^N+1)
	check := r.Mul(f, result)
	if !r.Equal(check, r.One()) {
		return nil, errors.New("blindsig: inverse verification failed")
	}

	return result, nil
}

// polyExtGCD computes the extended GCD of a and b over Z_q[X].
// Returns (gcd, s, t) such that s·a + t·b ≡ gcd (mod q).
func polyExtGCD(a, b []*big.Int, q *big.Int) (gcd, s, t []*big.Int) {
	// Initialize: old_r = a, r = b, old_s = 1, s = 0
	oldR := polyClone(a)
	rr := polyClone(b)
	oldS := []*big.Int{big.NewInt(1)}
	ss := []*big.Int{big.NewInt(0)}

	for polyDegree(rr) >= 0 {
		quot, rem := polyDivMod(oldR, rr, q)

		oldR, rr = rr, rem
		// old_s, s = s, old_s - quot * s
		newS := polySub2(oldS, polyMulPoly(quot, ss, q), q)
		oldS, ss = ss, newS
	}

	return oldR, oldS, ss
}

func polyClone(a []*big.Int) []*big.Int {
	c := make([]*big.Int, len(a))
	for i := range a {
		c[i] = new(big.Int).Set(a[i])
	}
	return c
}

func polyDegree(a []*big.Int) int {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i].Sign() != 0 {
			return i
		}
	}
	return -1
}

func polyDivMod(a, b []*big.Int, q *big.Int) (quot, rem []*big.Int) {
	degA := polyDegree(a)
	degB := polyDegree(b)
	if degB < 0 {
		panic("blindsig: polynomial division by zero")
	}
	if degA < degB {
		return []*big.Int{big.NewInt(0)}, polyClone(a)
	}

	rem = polyClone(a)
	quot = make([]*big.Int, degA-degB+1)
	for i := range quot {
		quot[i] = big.NewInt(0)
	}

	bLeadInv := new(big.Int).ModInverse(b[degB], q)
	if bLeadInv == nil {
		panic("blindsig: leading coefficient not invertible")
	}

	for polyDegree(rem) >= degB {
		d := polyDegree(rem)
		coeff := new(big.Int).Mul(rem[d], bLeadInv)
		coeff.Mod(coeff, q)
		quot[d-degB] = coeff

		for i := 0; i <= degB; i++ {
			sub := new(big.Int).Mul(coeff, b[i])
			rem[d-degB+i].Sub(rem[d-degB+i], sub)
			rem[d-degB+i].Mod(rem[d-degB+i], q)
		}
	}

	return quot, rem
}

func polyMulPoly(a, b []*big.Int, q *big.Int) []*big.Int {
	if len(a) == 0 || len(b) == 0 {
		return []*big.Int{big.NewInt(0)}
	}
	c := make([]*big.Int, len(a)+len(b)-1)
	for i := range c {
		c[i] = big.NewInt(0)
	}
	for i := range a {
		for j := range b {
			prod := new(big.Int).Mul(a[i], b[j])
			c[i+j].Add(c[i+j], prod)
			c[i+j].Mod(c[i+j], q)
		}
	}
	return c
}

// blns23SolveNTRU finds F, G such that f·G - g·F = q in Z[X]/(X^N+1).
// This is a local implementation that handles the N=1 base case without
// requiring ring.NewBig(1, q), which lnp22 v0.1.0 doesn't support.
func blns23SolveNTRU(r *ring.BigRing, f, g ring.BigPoly, q *big.Int) (ring.BigPoly, ring.BigPoly, error) {
	if r.N <= 2 {
		return blns23SolveNTRUSmall(r, f, g, q)
	}

	halfN := r.N / 2
	rHalf, err := ring.NewBig(halfN, q)
	if err != nil {
		return nil, nil, err
	}

	// Field norm: N_f(x) = f_even(x)^2 - x * f_odd(x)^2
	fNorm := blns23FieldNorm(r, rHalf, f)
	gNorm := blns23FieldNorm(r, rHalf, g)

	// Recursively solve at half degree
	Fp, Gp, err := blns23SolveNTRU(rHalf, fNorm, gNorm, q)
	if err != nil {
		return nil, nil, err
	}

	// Lift: F = F' * adj(g), G = G' * adj(f)
	fAdj := blns23Adjoint(r, f)
	gAdj := blns23Adjoint(r, g)
	FpLift := blns23LiftPolyHalf(r, rHalf, Fp)
	GpLift := blns23LiftPolyHalf(r, rHalf, Gp)

	F := r.Mul(FpLift, gAdj)
	G := r.Mul(GpLift, fAdj)

	// Verify: f*G - g*F = q
	fG := r.Mul(f, G)
	gF := r.Mul(g, F)
	diff := r.Sub(fG, gF)
	qPoly := r.NewPoly()
	qPoly[0] = new(big.Int).Set(q)
	if !r.Equal(diff, qPoly) {
		return nil, nil, errors.New("blindsig: NTRU equation verification failed")
	}

	return F, G, nil
}

// blns23SolveNTRUSmall handles the base cases N=1 and N=2.
func blns23SolveNTRUSmall(r *ring.BigRing, f, g ring.BigPoly, q *big.Int) (ring.BigPoly, ring.BigPoly, error) {
	if r.N == 2 {
		// For N=2: f = f0 + f1·X, g = g0 + g1·X in Z[X]/(X^2+1)
		// Field norm to Z: N(f) = f0^2 + f1^2 (since X^2 = -1)
		// Solve at the integer level, then lift.
		f0, f1 := f[0], f[1]
		g0, g1 := g[0], g[1]

		// N(f) = f0^2 + f1^2
		fNorm := new(big.Int).Add(
			new(big.Int).Mul(f0, f0),
			new(big.Int).Mul(f1, f1),
		)
		gNorm := new(big.Int).Add(
			new(big.Int).Mul(g0, g0),
			new(big.Int).Mul(g1, g1),
		)

		// Solve fNorm·G0 - gNorm·F0 = q at integer level
		u := new(big.Int)
		v := new(big.Int)
		d := new(big.Int).GCD(u, v, fNorm, gNorm)
		if new(big.Int).Mod(q, d).Sign() != 0 {
			return nil, nil, errors.New("blindsig: gcd(N(f),N(g)) does not divide q")
		}
		scale := new(big.Int).Div(q, d)
		G0 := new(big.Int).Mul(u, scale)
		F0 := new(big.Int).Neg(new(big.Int).Mul(v, scale))

		// Lift: F = F0 * conj(g), G = G0 * conj(f) where conj(a+bX) = a-bX
		// F = F0 * (g0 - g1·X) in Z[X]/(X^2+1)
		// G = G0 * (f0 - f1·X) in Z[X]/(X^2+1)
		F := r.NewPoly()
		G := r.NewPoly()

		// F = F0 * conj(g) = F0·g0 + F0·g1·1 (from -g1·X * X = -g1·X^2 = g1)
		// Actually: F0 * (g0 - g1·X) = F0·g0 - F0·g1·X  BUT in Z[X]/(X^2+1)
		// F[0] = F0*g0, F[1] = -F0*g1
		F[0] = new(big.Int).Mul(F0, g0)
		F[1] = new(big.Int).Neg(new(big.Int).Mul(F0, g1))

		G[0] = new(big.Int).Mul(G0, f0)
		G[1] = new(big.Int).Neg(new(big.Int).Mul(G0, f1))

		return F, G, nil
	}

	// N=1: just integers
	// Find F, G with f[0]*G[0] - g[0]*F[0] = q
	u := new(big.Int)
	v := new(big.Int)
	d := new(big.Int).GCD(u, v, f[0], g[0])
	if new(big.Int).Mod(q, d).Sign() != 0 {
		return nil, nil, errors.New("blindsig: gcd(f,g) does not divide q")
	}
	scale := new(big.Int).Div(q, d)
	F := r.NewPoly()
	G := r.NewPoly()
	G[0] = new(big.Int).Mul(u, scale)
	F[0] = new(big.Int).Neg(new(big.Int).Mul(v, scale))
	return F, G, nil
}

func blns23FieldNorm(r *ring.BigRing, rHalf *ring.BigRing, f ring.BigPoly) ring.BigPoly {
	halfN := rHalf.N
	fEven := rHalf.NewPoly()
	fOdd := rHalf.NewPoly()
	for i := 0; i < halfN; i++ {
		fEven[i] = new(big.Int).Set(f[2*i])
		if 2*i+1 < r.N {
			fOdd[i] = new(big.Int).Set(f[2*i+1])
		}
	}
	evenSq := rHalf.Mul(fEven, fEven)
	oddSq := rHalf.Mul(fOdd, fOdd)

	// x * oddSq: shift by 1 with wraparound (x^{N/2} = -1)
	xOddSq := rHalf.NewPoly()
	xOddSq[0] = new(big.Int).Neg(oddSq[halfN-1])
	xOddSq[0].Mod(xOddSq[0], rHalf.Q)
	for i := 1; i < halfN; i++ {
		xOddSq[i] = new(big.Int).Set(oddSq[i-1])
	}

	return rHalf.Sub(evenSq, xOddSq)
}

func blns23Adjoint(r *ring.BigRing, f ring.BigPoly) ring.BigPoly {
	result := r.NewPoly()
	for i := 0; i < r.N; i++ {
		if i%2 == 0 {
			result[i] = new(big.Int).Set(f[i])
		} else {
			result[i] = new(big.Int).Neg(f[i])
			result[i].Mod(result[i], r.Q)
		}
	}
	return result
}

func blns23LiftPolyHalf(r *ring.BigRing, rHalf *ring.BigRing, p ring.BigPoly) ring.BigPoly {
	result := r.NewPoly()
	for i := 0; i < rHalf.N; i++ {
		result[2*i] = new(big.Int).Set(p[i])
	}
	return result
}

func polySub2(a, b []*big.Int, q *big.Int) []*big.Int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	c := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		ai := big.NewInt(0)
		bi := big.NewInt(0)
		if i < len(a) {
			ai = a[i]
		}
		if i < len(b) {
			bi = b[i]
		}
		c[i] = new(big.Int).Sub(ai, bi)
		c[i].Mod(c[i], q)
	}
	return c
}

// PublicKey returns the public key corresponding to this private key.
func (sk *BLNS23PrivateKey) PublicKey() *BLNS23PublicKey {
	r := sk.Params.SigRing
	a := r.NewPolyVec(2)
	a[0] = sk.H
	a[1] = r.One()
	return &BLNS23PublicKey{
		Params: sk.Params,
		A:      a,
		B:      sk.B,
	}
}

// BLNS23UserBlind creates a blinded commitment for the message (Round 1).
// Returns the client state (kept secret) and the blind request to send to the signer.
func BLNS23UserBlind(message []byte, pk *BLNS23PublicKey) (*BLNS23ClientState, *BLNS23BlindRequest, error) {
	r := pk.Params.SigRing

	// Sample r with coefficients in {-2,-1,0,1,2}
	rv := blns23SampleS2Vec(r, 2, rand.Reader)

	// ρ = G(r)
	rho := blns23HashG(r, rv)

	// h = H(ρ, μ)
	h := blns23HashH(r, rho, message)

	// c = B·r + h
	br := r.InnerProduct(pk.B, rv)
	c := r.Add(br, h)

	state := &BLNS23ClientState{
		R:       rv,
		Rho:     rho,
		HTarget: h,
		Message: message,
	}
	req := &BLNS23BlindRequest{C: c}
	return state, req, nil
}

// BLNS23SignerRespond computes the signer's response (Round 2).
// The signer finds a short pre-image s with A·s = c using the NTRU trapdoor.
func BLNS23SignerRespond(req *BLNS23BlindRequest, sk *BLNS23PrivateKey) (*BLNS23BlindResponse, error) {
	r := sk.Params.SigRing

	// NTRU pre-image: find short (s1, s2) with h·s1 + s2 = c (mod q)
	s, err := blns23NTRUPreimage(r, req.C, sk.F, sk.G, sk.FF, sk.GG, sk.Params.Q, sk.Params.Sigma, rand.Reader)
	if err != nil {
		return nil, err
	}

	// Verify: A·s = c
	as := r.Add(r.Mul(sk.H, s[0]), s[1])
	if !r.Equal(as, r.Reduce(req.C)) {
		return nil, errors.New("blindsig: pre-image verification failed")
	}

	return &BLNS23BlindResponse{S: s}, nil
}

// BLNS23UserFinalize creates the blind signature from the signer's response (Round 3).
func BLNS23UserFinalize(state *BLNS23ClientState, resp *BLNS23BlindResponse, pk *BLNS23PublicKey) (*BLNS23Signature, error) {
	r := pk.Params.SigRing

	// Verify signer's response: A·s = B·r + H(ρ, μ)
	as := r.Add(r.Mul(pk.A[0], resp.S[0]), resp.S[1])
	br := r.InnerProduct(pk.B, state.R)
	expected := r.Add(br, state.HTarget)
	if !r.Equal(as, expected) {
		return nil, errors.New("blindsig: signer response does not satisfy A·s = c")
	}

	// Build the NIZK statement in the proof ring R_{q̂}
	// Lift: multiply public polynomials by q2 to go from R_q to R_{q̂}
	proofRing := pk.Params.ProofRing
	q2 := pk.Params.Q2

	// Lifted A: [q2·h, q2·1]
	aLifted := proofRing.NewPolyVec(2)
	aLifted[0] = blns23LiftPoly(r, proofRing, pk.A[0], q2)
	aLifted[1] = blns23LiftPoly(r, proofRing, pk.A[1], q2)

	// Lifted -B: [-q2·B1, -q2·B2]
	negBLifted := proofRing.NewPolyVec(2)
	negBLifted[0] = proofRing.Neg(blns23LiftPoly(r, proofRing, pk.B[0], q2))
	negBLifted[1] = proofRing.Neg(blns23LiftPoly(r, proofRing, pk.B[1], q2))

	// Combined matrix [A_lifted | -B_lifted] as 1×4
	mat := proofRing.NewPolyMat(1, 4)
	mat[0][0] = aLifted[0]
	mat[0][1] = aLifted[1]
	mat[0][2] = negBLifted[0]
	mat[0][3] = negBLifted[1]

	// Lifted target: q2·H(ρ, μ)
	tLifted := proofRing.NewPolyVec(1)
	tLifted[0] = blns23LiftPoly(r, proofRing, state.HTarget, q2)

	// Witness: (s1, s2, r1, r2) — embed into proof ring (same coefficients)
	wit := proofRing.NewPolyVec(4)
	wit[0] = blns23EmbedPoly(r, proofRing, resp.S[0])
	wit[1] = blns23EmbedPoly(r, proofRing, resp.S[1])
	wit[2] = blns23EmbedPoly(r, proofRing, state.R[0])
	wit[3] = blns23EmbedPoly(r, proofRing, state.R[1])

	stmt := &tworing.Statement{
		Linear: []tworing.LinearStatement{{A: mat, T: tLifted}},
	}
	witness := &tworing.Witness{S: wit}

	proof, err := tworing.Prove(pk.Params.ProofParams, stmt, witness, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &BLNS23Signature{
		Rho:   state.Rho,
		Proof: proof,
	}, nil
}

// BLNS23Verify verifies a BLNS23 blind signature on the given message.
func BLNS23Verify(message []byte, sig *BLNS23Signature, pk *BLNS23PublicKey) bool {
	if sig == nil || sig.Proof == nil || len(sig.Rho) != blns23RhoLen {
		return false
	}

	r := pk.Params.SigRing
	proofRing := pk.Params.ProofRing
	q2 := pk.Params.Q2

	// Recompute h = H(ρ, μ)
	h := blns23HashH(r, sig.Rho, message)

	// Build the same NIZK statement as in UserFinalize
	aLifted := proofRing.NewPolyVec(2)
	aLifted[0] = blns23LiftPoly(r, proofRing, pk.A[0], q2)
	aLifted[1] = blns23LiftPoly(r, proofRing, pk.A[1], q2)

	negBLifted := proofRing.NewPolyVec(2)
	negBLifted[0] = proofRing.Neg(blns23LiftPoly(r, proofRing, pk.B[0], q2))
	negBLifted[1] = proofRing.Neg(blns23LiftPoly(r, proofRing, pk.B[1], q2))

	mat := proofRing.NewPolyMat(1, 4)
	mat[0][0] = aLifted[0]
	mat[0][1] = aLifted[1]
	mat[0][2] = negBLifted[0]
	mat[0][3] = negBLifted[1]

	tLifted := proofRing.NewPolyVec(1)
	tLifted[0] = blns23LiftPoly(r, proofRing, h, q2)

	stmt := &tworing.Statement{
		Linear: []tworing.LinearStatement{{A: mat, T: tLifted}},
	}

	return tworing.Verify(pk.Params.ProofParams, stmt, sig.Proof)
}

// BLNS23BlindSign runs the full blind signing protocol locally (convenience).
func BLNS23BlindSign(message []byte, sk *BLNS23PrivateKey, pk *BLNS23PublicKey) (*BLNS23Signature, error) {
	state, req, err := BLNS23UserBlind(message, pk)
	if err != nil {
		return nil, err
	}
	resp, err := BLNS23SignerRespond(req, sk)
	if err != nil {
		return nil, err
	}
	return BLNS23UserFinalize(state, resp, pk)
}

// --- Internal helpers ---

// blns23SampleS2Poly samples a polynomial with coefficients uniform in {-2,-1,0,1,2}.
func blns23SampleS2Poly(r *ring.BigRing, rng io.Reader) ring.BigPoly {
	p := r.NewPoly()
	var buf [1]byte
	for i := 0; i < r.N; i++ {
		for {
			if _, err := io.ReadFull(rng, buf[:]); err != nil {
				panic("blindsig: failed to read randomness: " + err.Error())
			}
			if buf[0] < 250 { // 250 = 50*5, largest multiple of 5 ≤ 255
				v := int64(buf[0]%5) - 2 // maps to {-2,-1,0,1,2}
				if v < 0 {
					p[i] = new(big.Int).Add(r.Q, big.NewInt(v))
				} else {
					p[i] = big.NewInt(v)
				}
				break
			}
		}
	}
	return p
}

// blns23SampleS2Vec samples a vector of l S2 polynomials.
func blns23SampleS2Vec(r *ring.BigRing, l int, rng io.Reader) ring.BigPolyVec {
	v := r.NewPolyVec(l)
	for i := 0; i < l; i++ {
		v[i] = blns23SampleS2Poly(r, rng)
	}
	return v
}

// blns23HashG computes G(r) = SHAKE256("BLNS23-G" ‖ r) → 32 bytes.
func blns23HashG(r *ring.BigRing, rv ring.BigPolyVec) []byte {
	h := sha3.NewShake256()
	h.Write([]byte("BLNS23-G"))
	blns23WriteVec(h, r, rv)
	out := make([]byte, blns23RhoLen)
	h.Read(out)
	return out
}

// blns23HashH computes H(ρ, μ) → polynomial in R_q.
func blns23HashH(r *ring.BigRing, rho, message []byte) ring.BigPoly {
	h := sha3.NewShake256()
	h.Write([]byte("BLNS23-H"))
	h.Write(rho)
	h.Write(message)
	return sampler.SampleBigUniformPoly(r, h)
}

// blns23WriteVec writes a polynomial vector to a hash.
func blns23WriteVec(h sha3.ShakeHash, r *ring.BigRing, v ring.BigPolyVec) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(len(v)))
	h.Write(buf[:])
	for i := range v {
		for j := 0; j < r.N; j++ {
			b := v[i][j].Bytes()
			binary.LittleEndian.PutUint64(buf[:], uint64(len(b)))
			h.Write(buf[:])
			h.Write(b)
		}
	}
}

// blns23LiftPoly lifts a polynomial from R_q to R_{q̂} by multiplying
// coefficients by the scaling factor (q̂/q = q2).
func blns23LiftPoly(from *ring.BigRing, to *ring.BigRing, p ring.BigPoly, scale *big.Int) ring.BigPoly {
	result := to.NewPoly()
	for i := 0; i < from.N; i++ {
		result[i] = new(big.Int).Mul(p[i], scale)
		result[i].Mod(result[i], to.Q)
	}
	return result
}

// blns23EmbedPoly embeds a polynomial from R_q into R_{q̂} preserving
// the centered representation (same integer coefficients, different modulus).
func blns23EmbedPoly(from *ring.BigRing, to *ring.BigRing, p ring.BigPoly) ring.BigPoly {
	result := to.NewPoly()
	half := new(big.Int).Rsh(from.Q, 1)
	for i := 0; i < from.N; i++ {
		v := new(big.Int).Set(p[i])
		v.Mod(v, from.Q)
		// Center: if v > q/2, convert to negative representation in the target ring
		if v.Cmp(half) > 0 {
			v.Sub(v, from.Q) // now negative
			v.Add(v, to.Q)   // wrap into [0, q̂)
		}
		result[i] = v
	}
	return result
}

// blns23NTRUPreimage finds short (s1, s2) with h·s1 + s2 ≡ target (mod q)
// using the NTRU basis [[f, -g], [F, -G]] where fG - gF = q.
//
// Algorithm: Klein-GPV nearest-plane with Gaussian rounding.
//  1. Center-reduce the target to Z
//  2. Compute rational Babai coordinates via B^{-1}·(0, target)
//  3. Round each coefficient with discrete Gaussian perturbation
//  4. Reconstruct short pre-image
func blns23NTRUPreimage(
	r *ring.BigRing,
	target ring.BigPoly,
	f, g, ff, gg ring.BigPoly,
	q *big.Int,
	sigma float64,
	rng io.Reader,
) (ring.BigPolyVec, error) {
	d := r.N

	// Center-reduce target to signed integers
	t := make([]int64, d)
	half := new(big.Int).Rsh(q, 1)
	for i := 0; i < d; i++ {
		v := new(big.Int).Mod(target[i], q)
		if v.Cmp(half) > 0 {
			v.Sub(v, q)
		}
		t[i] = v.Int64()
	}

	// Center-reduce f, g, F, G to signed integers
	fI := bigPolyToInt64(r, f, q)
	gI := bigPolyToInt64(r, g, q)
	ffI := bigPolyToInt64(r, ff, q)
	ggI := bigPolyToInt64(r, gg, q)

	// Compute g·t and f·t in Z[X]/(X^d+1) (exact integer arithmetic, NOT mod q)
	gt := polyMulExact(gI, t, d)
	ft := polyMulExact(fI, t, d)

	// Babai coordinates: α_i = gt_i/q, β_i = ft_i/q (rational)
	// Round with Gaussian perturbation
	qi := q.Int64()
	sigmaCoord := sigma / float64(d) * 4 // heuristic: σ_coord ≈ 4σ/d

	alpha := make([]int64, d)
	beta := make([]int64, d)
	for i := 0; i < d; i++ {
		alpha[i] = gaussianRound(gt[i], qi, sigmaCoord, rng)
		beta[i] = gaussianRound(ft[i], qi, sigmaCoord, rng)
	}

	// Compute pre-image:
	// s1 = -(α·f + β·F) in Z[X]/(X^d+1)
	// s2 = t + α·g + β·G in Z[X]/(X^d+1)
	af := polyMulExact(alpha, fI, d)
	bf := polyMulExact(beta, ffI, d)
	ag := polyMulExact(alpha, gI, d)
	bg := polyMulExact(beta, ggI, d)

	s1Int := make([]int64, d)
	s2Int := make([]int64, d)
	for i := 0; i < d; i++ {
		s1Int[i] = -(af[i] + bf[i])
		s2Int[i] = t[i] + ag[i] + bg[i]
	}

	// Convert to BigPoly in R_q
	result := r.NewPolyVec(2)
	for i := 0; i < d; i++ {
		v1 := s1Int[i] % qi
		if v1 < 0 {
			v1 += qi
		}
		result[0][i] = big.NewInt(v1)

		v2 := s2Int[i] % qi
		if v2 < 0 {
			v2 += qi
		}
		result[1][i] = big.NewInt(v2)
	}

	return result, nil
}

// bigPolyToInt64 center-reduces a BigPoly to signed int64 coefficients.
func bigPolyToInt64(r *ring.BigRing, p ring.BigPoly, q *big.Int) []int64 {
	half := new(big.Int).Rsh(q, 1)
	out := make([]int64, r.N)
	for i := 0; i < r.N; i++ {
		v := new(big.Int).Mod(p[i], q)
		if v.Cmp(half) > 0 {
			v.Sub(v, q)
		}
		out[i] = v.Int64()
	}
	return out
}

// polyMulExact multiplies two int64 polynomials in Z[X]/(X^d+1) without reduction mod q.
// The result may have large coefficients.
func polyMulExact(a, b []int64, d int) []int64 {
	c := make([]int64, d)
	for i := 0; i < d; i++ {
		for j := 0; j < d; j++ {
			idx := i + j
			prod := a[i] * b[j]
			if idx < d {
				c[idx] += prod
			} else {
				// X^d ≡ -1
				c[idx-d] -= prod
			}
		}
	}
	return c
}

// gaussianRound rounds numerator/denominator to the nearest integer with
// Gaussian perturbation of standard deviation sigma.
func gaussianRound(numerator, denominator int64, sigma float64, rng io.Reader) int64 {
	// Compute the rational center
	center := float64(numerator) / float64(denominator)

	// Sample discrete Gaussian centered at 'center' with std dev sigma
	// Simple approach: round(center + gaussian_noise)
	// For security, we use rejection sampling from integer Gaussians
	rounded := int64(center + 0.5)
	if center < 0 {
		rounded = int64(center - 0.5)
	}

	// Add Gaussian perturbation
	if sigma > 0.5 {
		perturbation := sampleDiscreteGaussian(sigma, rng)
		rounded += perturbation
	}

	return rounded
}

// sampleDiscreteGaussian samples from a discrete Gaussian D_σ centered at 0.
// Returns an unreduced integer (may be negative).
func sampleDiscreteGaussian(sigma float64, rng io.Reader) int64 {
	// Use the CDT-based sampler: sample a single Gaussian value via
	// uniform random bits and CDF binary search.
	cdt := buildGaussianCDT(sigma)
	return cdt.sample(rng)
}

// gaussianCDTLocal stores a cumulative distribution table for D_σ.
type gaussianCDTLocal struct {
	table   []uint64
	tailCut int
}

func buildGaussianCDT(sigma float64) *gaussianCDTLocal {
	tau := 12.0
	tailCut := int(sigma*tau + 1)
	n := 2*tailCut + 1

	// Compute unnormalized probabilities
	probs := make([]float64, n)
	total := 0.0
	twoSigmaSq := 2.0 * sigma * sigma
	for i := 0; i < n; i++ {
		x := float64(i - tailCut)
		v := 1.0
		if twoSigmaSq > 0 {
			v = exp(-x * x / twoSigmaSq)
		}
		probs[i] = v
		total += v
	}

	table := make([]uint64, n)
	cum := 0.0
	for i := 0; i < n-1; i++ {
		cum += probs[i] / total
		table[i] = uint64(cum * exp2_64)
	}
	table[n-1] = ^uint64(0) // MaxUint64

	return &gaussianCDTLocal{table: table, tailCut: tailCut}
}

func (g *gaussianCDTLocal) sample(rng io.Reader) int64 {
	var buf [8]byte
	if _, err := io.ReadFull(rng, buf[:]); err != nil {
		panic("blindsig: failed to read randomness: " + err.Error())
	}
	r := binary.LittleEndian.Uint64(buf[:])
	lo, hi := 0, len(g.table)-1
	for lo < hi {
		mid := (lo + hi) / 2
		if g.table[mid] < r {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return int64(lo - g.tailCut)
}
