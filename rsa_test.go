package blindsig

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := GenerateBlindSigningKey(3072)
	if err != nil {
		t.Fatalf("GenerateBlindSigningKey: %v", err)
	}
	return key
}

func TestGenerateBlindSigningKey(t *testing.T) {
	t.Run("3072 bits", func(t *testing.T) {
		key, err := GenerateBlindSigningKey(3072)
		if err != nil {
			t.Fatal(err)
		}
		if key.N.BitLen() < 3072 {
			t.Errorf("key too small: got %d bits", key.N.BitLen())
		}
	})

	t.Run("4096 bits", func(t *testing.T) {
		key, err := GenerateBlindSigningKey(4096)
		if err != nil {
			t.Fatal(err)
		}
		if key.N.BitLen() < 4096 {
			t.Errorf("key too small: got %d bits", key.N.BitLen())
		}
	})

	t.Run("rejects small keys", func(t *testing.T) {
		_, err := GenerateBlindSigningKey(2048)
		if err == nil {
			t.Fatal("expected error for 2048-bit key")
		}
	})
}

func TestRSAFullProtocol(t *testing.T) {
	key := generateTestKey(t)
	pub := &key.PublicKey
	message := []byte("vote for candidate A")

	// Step 1: Client blinds the message
	blinded, r, err := BlindMessage(message, pub)
	if err != nil {
		t.Fatalf("BlindMessage: %v", err)
	}

	// Step 2: Server signs the blinded message
	blindSig, err := SignBlinded(blinded, key)
	if err != nil {
		t.Fatalf("SignBlinded: %v", err)
	}

	// Step 3: Client unblinds the signature
	sig, err := UnblindSignature(blindSig, r, pub)
	if err != nil {
		t.Fatalf("UnblindSignature: %v", err)
	}

	// Step 4: Anyone verifies
	if !VerifySignature(message, sig, pub) {
		t.Fatal("valid signature rejected")
	}
}

func TestRSAVerifyRejectsTamperedMessage(t *testing.T) {
	key := generateTestKey(t)
	pub := &key.PublicKey
	message := []byte("original message")

	blinded, r, err := BlindMessage(message, pub)
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := SignBlinded(blinded, key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := UnblindSignature(blindSig, r, pub)
	if err != nil {
		t.Fatal(err)
	}

	if VerifySignature([]byte("tampered message"), sig, pub) {
		t.Fatal("signature verified on wrong message")
	}
}

func TestRSAVerifyRejectsWrongKey(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)
	message := []byte("hello")

	blinded, r, err := BlindMessage(message, &key1.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := SignBlinded(blinded, key1)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := UnblindSignature(blindSig, r, &key1.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if VerifySignature(message, sig, &key2.PublicKey) {
		t.Fatal("signature verified with wrong key")
	}
}

func TestRSAVerifyRejectsRandomSignature(t *testing.T) {
	key := generateTestKey(t)
	message := []byte("hello")

	fakeSig, _ := rand.Int(rand.Reader, key.PublicKey.N)
	if VerifySignature(message, fakeSig, &key.PublicKey) {
		t.Fatal("random signature should not verify")
	}
}

func TestRSASignBlindedRejectsOutOfRange(t *testing.T) {
	key := generateTestKey(t)

	// zero
	_, err := SignBlinded(big.NewInt(0), key)
	if err == nil {
		t.Fatal("expected error for zero input")
	}

	// negative
	_, err = SignBlinded(big.NewInt(-1), key)
	if err == nil {
		t.Fatal("expected error for negative input")
	}

	// equal to n
	_, err = SignBlinded(new(big.Int).Set(key.PublicKey.N), key)
	if err == nil {
		t.Fatal("expected error for input == n")
	}
}

func TestRSAMultipleMessagesDistinct(t *testing.T) {
	key := generateTestKey(t)
	pub := &key.PublicKey

	messages := [][]byte{
		[]byte("message one"),
		[]byte("message two"),
		[]byte("message three"),
	}

	sigs := make([]*big.Int, len(messages))
	for i, msg := range messages {
		blinded, r, err := BlindMessage(msg, pub)
		if err != nil {
			t.Fatal(err)
		}
		blindSig, err := SignBlinded(blinded, key)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := UnblindSignature(blindSig, r, pub)
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = sig

		if !VerifySignature(msg, sig, pub) {
			t.Fatalf("message %d: valid signature rejected", i)
		}
	}

	// Signatures should be distinct
	for i := 0; i < len(sigs); i++ {
		for j := i + 1; j < len(sigs); j++ {
			if sigs[i].Cmp(sigs[j]) == 0 {
				t.Fatalf("signatures %d and %d are identical", i, j)
			}
		}
	}
}

func TestRSADeterministicSignature(t *testing.T) {
	// The same message should produce the same final signature (FDH is deterministic)
	key := generateTestKey(t)
	pub := &key.PublicKey
	message := []byte("deterministic test")

	var firstSig *big.Int
	for i := 0; i < 5; i++ {
		blinded, r, err := BlindMessage(message, pub)
		if err != nil {
			t.Fatal(err)
		}
		blindSig, err := SignBlinded(blinded, key)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := UnblindSignature(blindSig, r, pub)
		if err != nil {
			t.Fatal(err)
		}
		if firstSig == nil {
			firstSig = sig
		} else if firstSig.Cmp(sig) != 0 {
			t.Fatal("same message produced different signatures")
		}
	}
}

func TestRSAEmptyMessage(t *testing.T) {
	key := generateTestKey(t)
	pub := &key.PublicKey

	blinded, r, err := BlindMessage([]byte{}, pub)
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := SignBlinded(blinded, key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := UnblindSignature(blindSig, r, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature([]byte{}, sig, pub) {
		t.Fatal("empty message signature rejected")
	}
}

func BenchmarkRSAFullProtocol(b *testing.B) {
	key, err := GenerateBlindSigningKey(3072)
	if err != nil {
		b.Fatal(err)
	}
	pub := &key.PublicKey
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blinded, r, err := BlindMessage(message, pub)
		if err != nil {
			b.Fatal(err)
		}
		blindSig, err := SignBlinded(blinded, key)
		if err != nil {
			b.Fatal(err)
		}
		sig, err := UnblindSignature(blindSig, r, pub)
		if err != nil {
			b.Fatal(err)
		}
		if !VerifySignature(message, sig, pub) {
			b.Fatal("verification failed")
		}
	}
}
