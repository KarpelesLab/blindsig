package blindsig

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/mldsa"
)

func generateMLDSATestKey(t *testing.T) *mldsa.Key65 {
	t.Helper()
	key, err := GenerateMLDSAKey()
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}
	return key
}

func TestMLDSAFullProtocol(t *testing.T) {
	key := generateMLDSATestKey(t)
	pub := key.PublicKey()
	message := []byte("vote for candidate A")

	// Step 1: Client blinds the message
	blindedMsg, token, err := BlindMessageMLDSA(message, pub)
	if err != nil {
		t.Fatalf("BlindMessageMLDSA: %v", err)
	}

	// Step 2: Server signs the blinded message
	blindSig, err := SignBlindedMLDSA(blindedMsg, &key.PrivateKey65)
	if err != nil {
		t.Fatalf("SignBlindedMLDSA: %v", err)
	}

	// Step 3: Client unblinds the signature
	sig, err := UnblindSignatureMLDSA(blindSig, token, pub)
	if err != nil {
		t.Fatalf("UnblindSignatureMLDSA: %v", err)
	}

	// Step 4: Anyone verifies
	if !VerifySignatureMLDSA(message, sig, pub) {
		t.Fatal("valid signature rejected")
	}
}

func TestMLDSAVerifyRejectsTamperedMessage(t *testing.T) {
	key := generateMLDSATestKey(t)
	pub := key.PublicKey()
	message := []byte("original message")

	blindedMsg, token, err := BlindMessageMLDSA(message, pub)
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := SignBlindedMLDSA(blindedMsg, &key.PrivateKey65)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := UnblindSignatureMLDSA(blindSig, token, pub)
	if err != nil {
		t.Fatal(err)
	}

	if VerifySignatureMLDSA([]byte("tampered message"), sig, pub) {
		t.Fatal("signature verified on wrong message")
	}
}

func TestMLDSAVerifyRejectsWrongKey(t *testing.T) {
	key1 := generateMLDSATestKey(t)
	key2 := generateMLDSATestKey(t)
	message := []byte("hello")

	blindedMsg, token, err := BlindMessageMLDSA(message, key1.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := SignBlindedMLDSA(blindedMsg, &key1.PrivateKey65)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := UnblindSignatureMLDSA(blindSig, token, key1.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if VerifySignatureMLDSA(message, sig, key2.PublicKey()) {
		t.Fatal("signature verified with wrong key")
	}
}

func TestMLDSAVerifyRejectsRandomSignature(t *testing.T) {
	key := generateMLDSATestKey(t)
	message := []byte("hello")

	fakeSig := make([]byte, MLDSASignatureSize)
	rand.Read(fakeSig)
	if VerifySignatureMLDSA(message, fakeSig, key.PublicKey()) {
		t.Fatal("random signature should not verify")
	}
}

func TestMLDSAVerifyRejectsBadLength(t *testing.T) {
	key := generateMLDSATestKey(t)
	message := []byte("hello")

	if VerifySignatureMLDSA(message, []byte("too short"), key.PublicKey()) {
		t.Fatal("short signature should not verify")
	}
	if VerifySignatureMLDSA(message, nil, key.PublicKey()) {
		t.Fatal("nil signature should not verify")
	}
}

func TestMLDSASignBlindedRejectsBadSize(t *testing.T) {
	key := generateMLDSATestKey(t)

	_, err := SignBlindedMLDSA([]byte("too short"), &key.PrivateKey65)
	if err == nil {
		t.Fatal("expected error for wrong-sized blinded message")
	}

	_, err = SignBlindedMLDSA(make([]byte, 128), &key.PrivateKey65)
	if err == nil {
		t.Fatal("expected error for oversized blinded message")
	}
}

func TestMLDSAUnblindRejectsBadSizes(t *testing.T) {
	key := generateMLDSATestKey(t)
	pub := key.PublicKey()

	_, err := UnblindSignatureMLDSA([]byte("short"), make([]byte, mldsaTokenSize), pub)
	if err == nil {
		t.Fatal("expected error for wrong-sized blind signature")
	}

	_, err = UnblindSignatureMLDSA(make([]byte, mldsa.SignatureSize65), []byte("short"), pub)
	if err == nil {
		t.Fatal("expected error for wrong-sized blinding factor")
	}
}

func TestMLDSAMultipleMessagesDistinct(t *testing.T) {
	key := generateMLDSATestKey(t)
	pub := key.PublicKey()

	messages := [][]byte{
		[]byte("message one"),
		[]byte("message two"),
		[]byte("message three"),
	}

	sigs := make([][]byte, len(messages))
	for i, msg := range messages {
		blindedMsg, token, err := BlindMessageMLDSA(msg, pub)
		if err != nil {
			t.Fatal(err)
		}
		blindSig, err := SignBlindedMLDSA(blindedMsg, &key.PrivateKey65)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := UnblindSignatureMLDSA(blindSig, token, pub)
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = sig

		if !VerifySignatureMLDSA(msg, sig, pub) {
			t.Fatalf("message %d: valid signature rejected", i)
		}
	}

	// Signatures should be distinct
	for i := 0; i < len(sigs); i++ {
		for j := i + 1; j < len(sigs); j++ {
			if bytes.Equal(sigs[i], sigs[j]) {
				t.Fatalf("signatures %d and %d are identical", i, j)
			}
		}
	}
}

func TestMLDSABlindedMessageIsOpaque(t *testing.T) {
	key := generateMLDSATestKey(t)
	pub := key.PublicKey()
	message := []byte("secret ballot")

	// The blinded message should not contain the original message
	blindedMsg, _, err := BlindMessageMLDSA(message, pub)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(blindedMsg, message) {
		t.Fatal("blinded message contains original message")
	}
}

func TestMLDSADifferentTokensProduceDifferentBlinding(t *testing.T) {
	key := generateMLDSATestKey(t)
	pub := key.PublicKey()
	message := []byte("same message")

	blinded1, _, err := BlindMessageMLDSA(message, pub)
	if err != nil {
		t.Fatal(err)
	}
	blinded2, _, err := BlindMessageMLDSA(message, pub)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(blinded1, blinded2) {
		t.Fatal("same message produced identical blinded messages (tokens should differ)")
	}
}

func TestMLDSAEmptyMessage(t *testing.T) {
	key := generateMLDSATestKey(t)
	pub := key.PublicKey()

	blindedMsg, token, err := BlindMessageMLDSA([]byte{}, pub)
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := SignBlindedMLDSA(blindedMsg, &key.PrivateKey65)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := UnblindSignatureMLDSA(blindSig, token, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignatureMLDSA([]byte{}, sig, pub) {
		t.Fatal("empty message signature rejected")
	}
}

func TestMLDSASignatureSize(t *testing.T) {
	key := generateMLDSATestKey(t)
	pub := key.PublicKey()
	message := []byte("size check")

	blindedMsg, token, err := BlindMessageMLDSA(message, pub)
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := SignBlindedMLDSA(blindedMsg, &key.PrivateKey65)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := UnblindSignatureMLDSA(blindSig, token, pub)
	if err != nil {
		t.Fatal(err)
	}

	if len(sig) != MLDSASignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), MLDSASignatureSize)
	}
}

func BenchmarkMLDSAFullProtocol(b *testing.B) {
	key, err := GenerateMLDSAKey()
	if err != nil {
		b.Fatal(err)
	}
	pub := key.PublicKey()
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blindedMsg, token, err := BlindMessageMLDSA(message, pub)
		if err != nil {
			b.Fatal(err)
		}
		blindSig, err := SignBlindedMLDSA(blindedMsg, &key.PrivateKey65)
		if err != nil {
			b.Fatal(err)
		}
		sig, err := UnblindSignatureMLDSA(blindSig, token, pub)
		if err != nil {
			b.Fatal(err)
		}
		if !VerifySignatureMLDSA(message, sig, pub) {
			b.Fatal("verification failed")
		}
	}
}
