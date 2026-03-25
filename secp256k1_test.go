package blindsig

import (
	"crypto/sha256"
	"testing"
)

func secp256k1TestKeypair(t *testing.T) (*Secp256k1PrivateKey, *Secp256k1PublicKey) {
	t.Helper()
	sk, pk, err := GenerateSecp256k1Key()
	if err != nil {
		t.Fatalf("GenerateSecp256k1Key: %v", err)
	}
	return sk, pk
}

func secp256k1Hash(msg []byte) []byte {
	h := sha256.Sum256(msg)
	return h[:]
}

func secp256k1TestSign(t *testing.T, sk *Secp256k1PrivateKey, msg []byte) *Secp256k1Signature {
	t.Helper()
	sig, err := Secp256k1BlindSign(secp256k1Hash(msg), sk)
	if err != nil {
		t.Fatalf("Secp256k1BlindSign: %v", err)
	}
	return sig
}

func TestSecp256k1FullProtocol(t *testing.T) {
	sk, pk := secp256k1TestKeypair(t)
	hash := secp256k1Hash([]byte("vote for candidate A"))

	signerState, commitment, err := Secp256k1SignerCommit()
	if err != nil {
		t.Fatal(err)
	}
	clientState, challenge, err := Secp256k1ClientChallenge(hash, commitment, pk)
	if err != nil {
		t.Fatal(err)
	}
	response, err := Secp256k1SignerRespond(signerState, challenge, sk)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Secp256k1ClientUnblind(clientState, response, pk)
	if err != nil {
		t.Fatal(err)
	}

	if !Secp256k1Verify(hash, sig, pk) {
		t.Fatal("valid blind signature rejected")
	}
}

func TestSecp256k1Convenience(t *testing.T) {
	sk, pk := secp256k1TestKeypair(t)
	hash := secp256k1Hash([]byte("convenience test"))

	sig, err := Secp256k1BlindSign(hash, sk)
	if err != nil {
		t.Fatal(err)
	}

	if !Secp256k1Verify(hash, sig, pk) {
		t.Fatal("valid signature rejected")
	}
}

func TestSecp256k1RejectsTamperedHash(t *testing.T) {
	sk, pk := secp256k1TestKeypair(t)
	sig := secp256k1TestSign(t, sk, []byte("original"))

	if Secp256k1Verify(secp256k1Hash([]byte("tampered")), sig, pk) {
		t.Fatal("signature verified on wrong hash")
	}
}

func TestSecp256k1RejectsWrongKey(t *testing.T) {
	sk1, _ := secp256k1TestKeypair(t)
	_, pk2 := secp256k1TestKeypair(t)

	sig := secp256k1TestSign(t, sk1, []byte("hello"))

	if Secp256k1Verify(secp256k1Hash([]byte("hello")), sig, pk2) {
		t.Fatal("signature verified with wrong key")
	}
}

func TestSecp256k1RejectsNilSignature(t *testing.T) {
	_, pk := secp256k1TestKeypair(t)

	if Secp256k1Verify(secp256k1Hash([]byte("hello")), nil, pk) {
		t.Fatal("nil signature should not verify")
	}
}

func TestSecp256k1Unlinkability(t *testing.T) {
	sk, pk := secp256k1TestKeypair(t)
	hash := secp256k1Hash([]byte("same message"))

	sig1, err := Secp256k1BlindSign(hash, sk)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := Secp256k1BlindSign(hash, sk)
	if err != nil {
		t.Fatal(err)
	}

	if !Secp256k1Verify(hash, sig1, pk) || !Secp256k1Verify(hash, sig2, pk) {
		t.Fatal("valid signatures rejected")
	}

	if sig1.R.Equals(&sig2.R) {
		t.Fatal("two blind signatures have identical R'")
	}
}

func TestSecp256k1EmptyMessage(t *testing.T) {
	sk, pk := secp256k1TestKeypair(t)
	hash := secp256k1Hash([]byte{})

	sig, err := Secp256k1BlindSign(hash, sk)
	if err != nil {
		t.Fatal(err)
	}

	if !Secp256k1Verify(hash, sig, pk) {
		t.Fatal("empty message signature rejected")
	}
}

func TestSecp256k1SignatureRoundtrip(t *testing.T) {
	sk, pk := secp256k1TestKeypair(t)
	hash := secp256k1Hash([]byte("roundtrip"))

	sig, err := Secp256k1BlindSign(hash, sk)
	if err != nil {
		t.Fatal(err)
	}

	data := sig.Bytes()
	if len(data) != 64 {
		t.Fatalf("signature size = %d, want 64", len(data))
	}

	sig2, err := ParseSecp256k1Signature(data)
	if err != nil {
		t.Fatal(err)
	}

	if !Secp256k1Verify(hash, sig2, pk) {
		t.Fatal("parsed signature failed verification")
	}
}

func TestSecp256k1PublicKeyRoundtrip(t *testing.T) {
	_, pk := secp256k1TestKeypair(t)

	data := pk.Bytes()
	if len(data) != 33 {
		t.Fatalf("public key size = %d, want 33", len(data))
	}

	pk2, err := ParseSecp256k1PublicKey(data)
	if err != nil {
		t.Fatal(err)
	}

	if !pk.key.IsEqual(pk2.key) {
		t.Fatal("public key roundtrip mismatch")
	}
}

func TestSecp256k1MultipleMessagesDistinct(t *testing.T) {
	sk, pk := secp256k1TestKeypair(t)

	messages := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	sigs := make([]*Secp256k1Signature, len(messages))
	for i, msg := range messages {
		hash := secp256k1Hash(msg)
		var err error
		sigs[i], err = Secp256k1BlindSign(hash, sk)
		if err != nil {
			t.Fatal(err)
		}
		if !Secp256k1Verify(hash, sigs[i], pk) {
			t.Fatalf("message %d: valid signature rejected", i)
		}
	}

	for i := 0; i < len(sigs); i++ {
		for j := i + 1; j < len(sigs); j++ {
			if sigs[i].R.Equals(&sigs[j].R) && sigs[i].S.Equals(&sigs[j].S) {
				t.Fatalf("signatures %d and %d are identical", i, j)
			}
		}
	}
}

func BenchmarkSecp256k1BlindSign(b *testing.B) {
	sk, _, _ := GenerateSecp256k1Key()
	hash := secp256k1Hash([]byte("benchmark"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := Secp256k1BlindSign(hash, sk)
		if err != nil {
			b.Fatal(err)
		}
		if !Secp256k1Verify(hash, sig, sk.PublicKey()) {
			b.Fatal("verification failed")
		}
	}
}
