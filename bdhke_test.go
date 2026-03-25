package blindsig

import (
	"bytes"
	"testing"
)

func TestBDHKEFullProtocol(t *testing.T) {
	sk, pk, err := GenerateBDHKEMintKey()
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("secret-token-12345")

	// Step 1: User blinds the secret
	state, blinded, err := BDHKEBlind(secret)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: Mint signs the blinded message
	blindSig, err := BDHKESign(blinded, sk)
	if err != nil {
		t.Fatal(err)
	}

	// Step 3: User unblinds to get a valid token
	token, err := BDHKEUnblind(secret, blindSig, state, pk)
	if err != nil {
		t.Fatal(err)
	}

	// Step 4: Mint verifies the token
	if !BDHKEVerify(token, sk) {
		t.Fatal("valid token rejected")
	}
}

func TestBDHKERejectsTamperedSecret(t *testing.T) {
	sk, pk, _ := GenerateBDHKEMintKey()

	state, blinded, _ := BDHKEBlind([]byte("real-secret"))
	blindSig, _ := BDHKESign(blinded, sk)
	token, _ := BDHKEUnblind([]byte("real-secret"), blindSig, state, pk)

	// Tamper with the secret
	token.Secret = []byte("fake-secret")
	if BDHKEVerify(token, sk) {
		t.Fatal("token with tampered secret should not verify")
	}
}

func TestBDHKERejectsWrongMint(t *testing.T) {
	sk1, pk1, _ := GenerateBDHKEMintKey()
	sk2, _, _ := GenerateBDHKEMintKey()

	state, blinded, _ := BDHKEBlind([]byte("token"))
	blindSig, _ := BDHKESign(blinded, sk1)
	token, _ := BDHKEUnblind([]byte("token"), blindSig, state, pk1)

	// Verify with the wrong mint
	if BDHKEVerify(token, sk2) {
		t.Fatal("token should not verify with wrong mint key")
	}
}

func TestBDHKERejectsNilToken(t *testing.T) {
	sk, _, _ := GenerateBDHKEMintKey()

	if BDHKEVerify(nil, sk) {
		t.Fatal("nil token should not verify")
	}
}

func TestBDHKEUnlinkability(t *testing.T) {
	sk, pk, _ := GenerateBDHKEMintKey()

	// Same secret, two different blinding sessions
	state1, blinded1, _ := BDHKEBlind([]byte("same-secret"))
	state2, blinded2, _ := BDHKEBlind([]byte("same-secret"))

	// Blinded messages should differ (different random r)
	if blinded1.x.Cmp(blinded2.x) == 0 && blinded1.y.Cmp(blinded2.y) == 0 {
		t.Fatal("blinded messages should differ")
	}

	// Both should produce valid tokens
	blindSig1, _ := BDHKESign(blinded1, sk)
	blindSig2, _ := BDHKESign(blinded2, sk)

	token1, _ := BDHKEUnblind([]byte("same-secret"), blindSig1, state1, pk)
	token2, _ := BDHKEUnblind([]byte("same-secret"), blindSig2, state2, pk)

	if !BDHKEVerify(token1, sk) || !BDHKEVerify(token2, sk) {
		t.Fatal("valid tokens rejected")
	}

	// Unblinded tokens should be IDENTICAL (same C = k·hash_to_curve(secret))
	if token1.Cx.Cmp(token2.Cx) != 0 || token1.Cy.Cmp(token2.Cy) != 0 {
		t.Fatal("unblinded tokens for same secret should be identical")
	}
}

func TestBDHKEDifferentSecrets(t *testing.T) {
	sk, pk, _ := GenerateBDHKEMintKey()

	secrets := [][]byte{[]byte("token-1"), []byte("token-2"), []byte("token-3")}
	tokens := make([]*BDHKEToken, len(secrets))

	for i, s := range secrets {
		state, blinded, _ := BDHKEBlind(s)
		blindSig, _ := BDHKESign(blinded, sk)
		token, err := BDHKEUnblind(s, blindSig, state, pk)
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = token

		if !BDHKEVerify(token, sk) {
			t.Fatalf("token %d rejected", i)
		}
	}

	// Tokens for different secrets should have different C values
	for i := 0; i < len(tokens); i++ {
		for j := i + 1; j < len(tokens); j++ {
			if tokens[i].Cx.Cmp(tokens[j].Cx) == 0 && tokens[i].Cy.Cmp(tokens[j].Cy) == 0 {
				t.Fatalf("tokens %d and %d have identical C", i, j)
			}
		}
	}
}

func TestBDHKEEmptySecret(t *testing.T) {
	sk, pk, _ := GenerateBDHKEMintKey()

	state, blinded, _ := BDHKEBlind([]byte{})
	blindSig, _ := BDHKESign(blinded, sk)
	token, err := BDHKEUnblind([]byte{}, blindSig, state, pk)
	if err != nil {
		t.Fatal(err)
	}
	if !BDHKEVerify(token, sk) {
		t.Fatal("empty secret token rejected")
	}
}

func TestBDHKESerializationRoundtrip(t *testing.T) {
	sk, pk, _ := GenerateBDHKEMintKey()

	// Public key roundtrip
	pkBytes := pk.Bytes()
	pk2, err := ParseBDHKEMintPublicKey(pkBytes)
	if err != nil {
		t.Fatal(err)
	}
	if pk.x.Cmp(pk2.x) != 0 || pk.y.Cmp(pk2.y) != 0 {
		t.Fatal("public key roundtrip failed")
	}

	// Blinded message roundtrip
	state, blinded, _ := BDHKEBlind([]byte("roundtrip"))
	bBytes := blinded.Bytes()
	blinded2, err := ParseBDHKEBlindedMessage(bBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Blind signature roundtrip
	blindSig, _ := BDHKESign(blinded2, sk)
	sBytes := blindSig.Bytes()
	blindSig2, err := ParseBDHKEBlindSignature(sBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Unblind with deserialized blind signature
	token, err := BDHKEUnblind([]byte("roundtrip"), blindSig2, state, pk)
	if err != nil {
		t.Fatal(err)
	}
	if !BDHKEVerify(token, sk) {
		t.Fatal("token from deserialized components rejected")
	}

	// Token roundtrip
	tBytes := token.Bytes()
	if len(tBytes) != 32+len("roundtrip") {
		t.Fatalf("token bytes length = %d, want %d", len(tBytes), 32+len("roundtrip"))
	}
	if !bytes.Equal(tBytes[32:], []byte("roundtrip")) {
		t.Fatal("token secret not preserved in serialization")
	}
}

func TestBDHKEHashToCurveDeterministic(t *testing.T) {
	x1, y1 := bdhkeHashToCurve([]byte("test"))
	x2, y2 := bdhkeHashToCurve([]byte("test"))

	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.Fatal("hash_to_curve is not deterministic")
	}

	// Different inputs should give different points
	x3, y3 := bdhkeHashToCurve([]byte("other"))
	if x1.Cmp(x3) == 0 && y1.Cmp(y3) == 0 {
		t.Fatal("different inputs produced same point")
	}
}

func BenchmarkBDHKEFullProtocol(b *testing.B) {
	sk, pk, _ := GenerateBDHKEMintKey()
	secret := []byte("benchmark-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state, blinded, _ := BDHKEBlind(secret)
		blindSig, _ := BDHKESign(blinded, sk)
		token, _ := BDHKEUnblind(secret, blindSig, state, pk)
		if !BDHKEVerify(token, sk) {
			b.Fatal("verification failed")
		}
	}
}
