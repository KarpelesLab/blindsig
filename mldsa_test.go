package blindsig

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/mldsa"
)

func mldsaTestSign(t *testing.T, sk *mldsa.PrivateKey65, bpk *mldsa.BlindPublicKey65, message []byte) []byte {
	t.Helper()
	sig, err := MLDSABlindSign(message, sk, bpk, 100)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestMLDSAFullProtocol(t *testing.T) {
	key, err := GenerateMLDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)
	message := []byte("vote for candidate A")

	// Step 1: Signer creates commitment
	session, commitment, err := MLDSASignerCommit(&key.PrivateKey65)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: Client creates blinded challenge
	state, challenge, err := MLDSAClientChallenge(message, commitment, bpk)
	if err != nil {
		t.Fatal(err)
	}

	// Step 3: Signer responds (retry on rejection)
	var response []byte
	for {
		response, err = MLDSASignerRespond(session, challenge)
		if err == ErrMLDSARetry {
			session, commitment, err = MLDSASignerCommit(&key.PrivateKey65)
			if err != nil {
				t.Fatal(err)
			}
			state, challenge, err = MLDSAClientChallenge(message, commitment, bpk)
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		break
	}

	// Step 4: Client unblinds
	sig, err := MLDSAClientUnblind(state, response, bpk)
	if err != nil {
		t.Fatal(err)
	}

	// Step 5: Anyone verifies
	if !VerifySignatureMLDSA(message, sig, bpk) {
		t.Fatal("valid signature rejected")
	}
}

func TestMLDSAConvenience(t *testing.T) {
	key, err := GenerateMLDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)
	message := []byte("convenience test")

	sig, err := MLDSABlindSign(message, &key.PrivateKey65, bpk, 0)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifySignatureMLDSA(message, sig, bpk) {
		t.Fatal("valid signature rejected")
	}
}

func TestMLDSAVerifyRejectsTamperedMessage(t *testing.T) {
	key, _ := GenerateMLDSAKey()
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)
	sig := mldsaTestSign(t, &key.PrivateKey65, bpk, []byte("original"))

	if VerifySignatureMLDSA([]byte("tampered"), sig, bpk) {
		t.Fatal("signature verified on wrong message")
	}
}

func TestMLDSAVerifyRejectsWrongKey(t *testing.T) {
	key1, _ := GenerateMLDSAKey()
	key2, _ := GenerateMLDSAKey()
	bpk1 := MLDSABlindPublicKey(&key1.PrivateKey65)
	bpk2 := MLDSABlindPublicKey(&key2.PrivateKey65)

	sig := mldsaTestSign(t, &key1.PrivateKey65, bpk1, []byte("hello"))

	if VerifySignatureMLDSA([]byte("hello"), sig, bpk2) {
		t.Fatal("signature verified with wrong key")
	}
}

func TestMLDSAVerifyRejectsRandomSignature(t *testing.T) {
	key, _ := GenerateMLDSAKey()
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)

	fake := make([]byte, MLDSASignatureSize)
	rand.Read(fake)
	if VerifySignatureMLDSA([]byte("hello"), fake, bpk) {
		t.Fatal("random signature should not verify")
	}
}

func TestMLDSAVerifyRejectsBadLength(t *testing.T) {
	key, _ := GenerateMLDSAKey()
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)

	if VerifySignatureMLDSA([]byte("hello"), []byte("short"), bpk) {
		t.Fatal("short signature should not verify")
	}
	if VerifySignatureMLDSA([]byte("hello"), nil, bpk) {
		t.Fatal("nil signature should not verify")
	}
}

func TestMLDSAMultipleMessagesDistinct(t *testing.T) {
	key, _ := GenerateMLDSAKey()
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)

	messages := [][]byte{
		[]byte("message one"),
		[]byte("message two"),
		[]byte("message three"),
	}

	sigs := make([][]byte, len(messages))
	for i, msg := range messages {
		sigs[i] = mldsaTestSign(t, &key.PrivateKey65, bpk, msg)
		if !VerifySignatureMLDSA(msg, sigs[i], bpk) {
			t.Fatalf("message %d: valid signature rejected", i)
		}
	}

	for i := 0; i < len(sigs); i++ {
		for j := i + 1; j < len(sigs); j++ {
			if bytes.Equal(sigs[i], sigs[j]) {
				t.Fatalf("signatures %d and %d are identical", i, j)
			}
		}
	}
}

func TestMLDSAUnlinkability(t *testing.T) {
	// Two blind signatures on the same message should differ
	// (different random blinding each time)
	key, _ := GenerateMLDSAKey()
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)
	msg := []byte("same message")

	sig1 := mldsaTestSign(t, &key.PrivateKey65, bpk, msg)
	sig2 := mldsaTestSign(t, &key.PrivateKey65, bpk, msg)

	if bytes.Equal(sig1, sig2) {
		t.Fatal("two blind signatures on same message are identical")
	}

	if !VerifySignatureMLDSA(msg, sig1, bpk) || !VerifySignatureMLDSA(msg, sig2, bpk) {
		t.Fatal("valid signatures rejected")
	}
}

func TestMLDSAEmptyMessage(t *testing.T) {
	key, _ := GenerateMLDSAKey()
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)

	sig := mldsaTestSign(t, &key.PrivateKey65, bpk, []byte{})
	if !VerifySignatureMLDSA([]byte{}, sig, bpk) {
		t.Fatal("empty message signature rejected")
	}
}

func TestMLDSASignatureSize(t *testing.T) {
	key, _ := GenerateMLDSAKey()
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)

	sig := mldsaTestSign(t, &key.PrivateKey65, bpk, []byte("size check"))
	if len(sig) != MLDSASignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), MLDSASignatureSize)
	}
}

func TestMLDSAPublicKeySerialization(t *testing.T) {
	key, _ := GenerateMLDSAKey()
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)
	msg := []byte("serialization test")

	sig := mldsaTestSign(t, &key.PrivateKey65, bpk, msg)

	// Serialize and deserialize the blind public key
	b := bpk.Bytes()
	bpk2, err := mldsa.ParseBlindPublicKey65(b)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifySignatureMLDSA(msg, sig, bpk2) {
		t.Fatal("signature failed verification with deserialized key")
	}
}

func BenchmarkMLDSAFullProtocol(b *testing.B) {
	key, _ := GenerateMLDSAKey()
	bpk := MLDSABlindPublicKey(&key.PrivateKey65)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := MLDSABlindSign(message, &key.PrivateKey65, bpk, 0)
		if err != nil {
			b.Fatal(err)
		}
		if !VerifySignatureMLDSA(message, sig, bpk) {
			b.Fatal("verification failed")
		}
	}
}
