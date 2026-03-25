package blindsig

import (
	"testing"
)

var testBLNS23Params *BLNS23Params

func init() {
	testBLNS23Params = BLNS23DefaultParams()
}

func blns23TestKeypair(t *testing.T) (*BLNS23PrivateKey, *BLNS23PublicKey) {
	t.Helper()
	sk, pk, err := GenerateBLNS23Key(testBLNS23Params)
	if err != nil {
		t.Fatalf("GenerateBLNS23Key: %v", err)
	}
	return sk, pk
}

func blns23TestSign(t *testing.T, sk *BLNS23PrivateKey, pk *BLNS23PublicKey, msg []byte) *BLNS23Signature {
	t.Helper()
	sig, err := BLNS23BlindSign(msg, sk, pk)
	if err != nil {
		t.Fatalf("BLNS23BlindSign: %v", err)
	}
	return sig
}

func TestBLNS23FullProtocol(t *testing.T) {
	sk, pk := blns23TestKeypair(t)
	message := []byte("vote for candidate A")

	// Round 1: User blinds the message
	state, req, err := BLNS23UserBlind(message, pk)
	if err != nil {
		t.Fatalf("UserBlind: %v", err)
	}

	// Round 2: Signer responds
	resp, err := BLNS23SignerRespond(req, sk)
	if err != nil {
		t.Fatalf("SignerRespond: %v", err)
	}

	// Round 3: User creates signature
	sig, err := BLNS23UserFinalize(state, resp, pk)
	if err != nil {
		t.Fatalf("UserFinalize: %v", err)
	}

	// Verify
	if !BLNS23Verify(message, sig, pk) {
		t.Fatal("valid blind signature rejected")
	}
}

func TestBLNS23Convenience(t *testing.T) {
	sk, pk := blns23TestKeypair(t)
	message := []byte("convenience test")

	sig, err := BLNS23BlindSign(message, sk, pk)
	if err != nil {
		t.Fatal(err)
	}

	if !BLNS23Verify(message, sig, pk) {
		t.Fatal("valid signature rejected")
	}
}

func TestBLNS23RejectsTamperedMessage(t *testing.T) {
	sk, pk := blns23TestKeypair(t)
	sig := blns23TestSign(t, sk, pk, []byte("original"))

	if BLNS23Verify([]byte("tampered"), sig, pk) {
		t.Fatal("signature verified on wrong message")
	}
}

func TestBLNS23RejectsWrongKey(t *testing.T) {
	sk1, pk1 := blns23TestKeypair(t)
	_, pk2 := blns23TestKeypair(t)

	sig := blns23TestSign(t, sk1, pk1, []byte("hello"))

	if BLNS23Verify([]byte("hello"), sig, pk2) {
		t.Fatal("signature verified with wrong key")
	}
}

func TestBLNS23RejectsNilSignature(t *testing.T) {
	_, pk := blns23TestKeypair(t)

	if BLNS23Verify([]byte("hello"), nil, pk) {
		t.Fatal("nil signature should not verify")
	}
}

func TestBLNS23RejectsBadRho(t *testing.T) {
	sk, pk := blns23TestKeypair(t)
	sig := blns23TestSign(t, sk, pk, []byte("hello"))

	// Tamper with ρ
	sig.Rho[0] ^= 0xFF
	if BLNS23Verify([]byte("hello"), sig, pk) {
		t.Fatal("signature with tampered ρ should not verify")
	}
}

func TestBLNS23Unlinkability(t *testing.T) {
	sk, pk := blns23TestKeypair(t)
	msg := []byte("same message")

	sig1 := blns23TestSign(t, sk, pk, msg)
	sig2 := blns23TestSign(t, sk, pk, msg)

	if !BLNS23Verify(msg, sig1, pk) || !BLNS23Verify(msg, sig2, pk) {
		t.Fatal("valid signatures rejected")
	}

	// ρ values should differ (different random r each time)
	same := true
	for i := range sig1.Rho {
		if sig1.Rho[i] != sig2.Rho[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two blind signatures have identical ρ — should differ")
	}
}

func TestBLNS23EmptyMessage(t *testing.T) {
	sk, pk := blns23TestKeypair(t)
	sig := blns23TestSign(t, sk, pk, []byte{})

	if !BLNS23Verify([]byte{}, sig, pk) {
		t.Fatal("empty message signature rejected")
	}
}

func TestBLNS23PreimageCorrectness(t *testing.T) {
	sk, pk := blns23TestKeypair(t)
	r := sk.Params.SigRing

	// Create a random target
	state, req, err := BLNS23UserBlind([]byte("preimage test"), pk)
	if err != nil {
		t.Fatal(err)
	}
	_ = state

	resp, err := BLNS23SignerRespond(req, sk)
	if err != nil {
		t.Fatal(err)
	}

	// Check A·s = c
	as := r.Add(r.Mul(pk.A[0], resp.S[0]), resp.S[1])
	if !r.Equal(as, r.Reduce(req.C)) {
		t.Fatal("pre-image does not satisfy A·s = c")
	}
}

func BenchmarkBLNS23KeyGen(b *testing.B) {
	params := BLNS23DefaultParams()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateBLNS23Key(params)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBLNS23BlindSign(b *testing.B) {
	sk, pk := func() (*BLNS23PrivateKey, *BLNS23PublicKey) {
		sk, pk, err := GenerateBLNS23Key(testBLNS23Params)
		if err != nil {
			b.Fatal(err)
		}
		return sk, pk
	}()
	msg := []byte("benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := BLNS23BlindSign(msg, sk, pk)
		if err != nil {
			b.Fatal(err)
		}
		if !BLNS23Verify(msg, sig, pk) {
			b.Fatal("verification failed")
		}
	}
}
