package blindsig

import (
	"testing"
)

func ed25519TestKeypair(t *testing.T) (*Ed25519PrivateKey, *Ed25519PublicKey) {
	t.Helper()
	sk, pk, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	return sk, pk
}

func ed25519TestSign(t *testing.T, sk *Ed25519PrivateKey, msg []byte) *Ed25519Signature {
	t.Helper()
	sig, err := Ed25519BlindSign(msg, sk)
	if err != nil {
		t.Fatalf("Ed25519BlindSign: %v", err)
	}
	return sig
}

func TestEd25519FullProtocol(t *testing.T) {
	sk, pk := ed25519TestKeypair(t)
	message := []byte("vote for candidate A")

	signerState, commitment, err := Ed25519SignerCommit()
	if err != nil {
		t.Fatal(err)
	}
	clientState, challenge, err := Ed25519ClientChallenge(message, commitment, pk)
	if err != nil {
		t.Fatal(err)
	}
	response, err := Ed25519SignerRespond(signerState, challenge, sk)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Ed25519ClientUnblind(clientState, response, pk)
	if err != nil {
		t.Fatal(err)
	}

	if !Ed25519Verify(message, sig, pk) {
		t.Fatal("valid blind signature rejected")
	}
}

func TestEd25519Convenience(t *testing.T) {
	sk, pk := ed25519TestKeypair(t)
	sig := ed25519TestSign(t, sk, []byte("convenience test"))

	if !Ed25519Verify([]byte("convenience test"), sig, pk) {
		t.Fatal("valid signature rejected")
	}
}

func TestEd25519RejectsTamperedMessage(t *testing.T) {
	sk, pk := ed25519TestKeypair(t)
	sig := ed25519TestSign(t, sk, []byte("original"))

	if Ed25519Verify([]byte("tampered"), sig, pk) {
		t.Fatal("signature verified on wrong message")
	}
}

func TestEd25519RejectsWrongKey(t *testing.T) {
	sk1, _ := ed25519TestKeypair(t)
	_, pk2 := ed25519TestKeypair(t)
	sig := ed25519TestSign(t, sk1, []byte("hello"))

	if Ed25519Verify([]byte("hello"), sig, pk2) {
		t.Fatal("signature verified with wrong key")
	}
}

func TestEd25519RejectsNilSignature(t *testing.T) {
	_, pk := ed25519TestKeypair(t)

	if Ed25519Verify([]byte("hello"), nil, pk) {
		t.Fatal("nil signature should not verify")
	}
}

func TestEd25519Unlinkability(t *testing.T) {
	sk, pk := ed25519TestKeypair(t)
	msg := []byte("same message")

	sig1 := ed25519TestSign(t, sk, msg)
	sig2 := ed25519TestSign(t, sk, msg)

	if !Ed25519Verify(msg, sig1, pk) || !Ed25519Verify(msg, sig2, pk) {
		t.Fatal("valid signatures rejected")
	}
	if sig1.Rx.Cmp(sig2.Rx) == 0 && sig1.Ry.Cmp(sig2.Ry) == 0 {
		t.Fatal("two blind signatures have identical R'")
	}
}

func TestEd25519EmptyMessage(t *testing.T) {
	sk, pk := ed25519TestKeypair(t)
	sig := ed25519TestSign(t, sk, []byte{})

	if !Ed25519Verify([]byte{}, sig, pk) {
		t.Fatal("empty message signature rejected")
	}
}

func TestEd25519SignatureRoundtrip(t *testing.T) {
	sk, pk := ed25519TestKeypair(t)
	sig := ed25519TestSign(t, sk, []byte("roundtrip"))

	data := sig.Bytes()
	if len(data) != 64 {
		t.Fatalf("signature size = %d, want 64", len(data))
	}
	sig2, err := ParseEd25519Signature(data)
	if err != nil {
		t.Fatal(err)
	}
	if !Ed25519Verify([]byte("roundtrip"), sig2, pk) {
		t.Fatal("parsed signature failed verification")
	}
}

func TestEd25519PublicKeyRoundtrip(t *testing.T) {
	_, pk := ed25519TestKeypair(t)

	data := pk.Bytes()
	if len(data) != 32 {
		t.Fatalf("public key size = %d, want 32", len(data))
	}
	pk2, err := ParseEd25519PublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if pk.x.Cmp(pk2.x) != 0 || pk.y.Cmp(pk2.y) != 0 {
		t.Fatal("public key roundtrip mismatch")
	}
}

func TestEd25519MultipleMessagesDistinct(t *testing.T) {
	sk, pk := ed25519TestKeypair(t)

	messages := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	sigs := make([]*Ed25519Signature, len(messages))
	for i, msg := range messages {
		sigs[i] = ed25519TestSign(t, sk, msg)
		if !Ed25519Verify(msg, sigs[i], pk) {
			t.Fatalf("message %d: valid signature rejected", i)
		}
	}
	for i := 0; i < len(sigs); i++ {
		for j := i + 1; j < len(sigs); j++ {
			if sigs[i].S.Cmp(sigs[j].S) == 0 && sigs[i].Rx.Cmp(sigs[j].Rx) == 0 {
				t.Fatalf("signatures %d and %d are identical", i, j)
			}
		}
	}
}

func BenchmarkEd25519BlindSign(b *testing.B) {
	sk, _, _ := GenerateEd25519Key()
	msg := []byte("benchmark")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := Ed25519BlindSign(msg, sk)
		if err != nil {
			b.Fatal(err)
		}
		if !Ed25519Verify(msg, sig, sk.PublicKey()) {
			b.Fatal("verification failed")
		}
	}
}
