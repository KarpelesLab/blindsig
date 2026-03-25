package blindsig

import (
	"testing"
)

func schnorrTestKeypair(t *testing.T) (*SchnorrPrivateKey, *SchnorrPublicKey) {
	t.Helper()
	sk, pk, err := GenerateSchnorrKey()
	if err != nil {
		t.Fatalf("GenerateSchnorrKey: %v", err)
	}
	return sk, pk
}

func schnorrTestSign(t *testing.T, sk *SchnorrPrivateKey, msg []byte) *SchnorrSignature {
	t.Helper()
	sig, err := SchnorrBlindSign(msg, sk)
	if err != nil {
		t.Fatalf("SchnorrBlindSign: %v", err)
	}
	return sig
}

func TestSchnorrFullProtocol(t *testing.T) {
	sk, pk := schnorrTestKeypair(t)
	message := []byte("vote for candidate A")

	// Round 1: Signer commits
	signerState, commitment, err := SchnorrSignerCommit()
	if err != nil {
		t.Fatal(err)
	}

	// Round 2: Client creates blinded challenge
	clientState, challenge, err := SchnorrClientChallenge(message, commitment, pk)
	if err != nil {
		t.Fatal(err)
	}

	// Round 3: Signer responds
	response, err := SchnorrSignerRespond(signerState, challenge, sk)
	if err != nil {
		t.Fatal(err)
	}

	// Client unblinds
	sig, err := SchnorrClientUnblind(clientState, response, pk)
	if err != nil {
		t.Fatal(err)
	}

	// Verify
	if !SchnorrVerify(message, sig, pk) {
		t.Fatal("valid blind signature rejected")
	}
}

func TestSchnorrConvenience(t *testing.T) {
	sk, pk := schnorrTestKeypair(t)
	sig := schnorrTestSign(t, sk, []byte("convenience test"))

	if !SchnorrVerify([]byte("convenience test"), sig, pk) {
		t.Fatal("valid signature rejected")
	}
}

func TestSchnorrRejectsTamperedMessage(t *testing.T) {
	sk, pk := schnorrTestKeypair(t)
	sig := schnorrTestSign(t, sk, []byte("original"))

	if SchnorrVerify([]byte("tampered"), sig, pk) {
		t.Fatal("signature verified on wrong message")
	}
}

func TestSchnorrRejectsWrongKey(t *testing.T) {
	sk1, _ := schnorrTestKeypair(t)
	_, pk2 := schnorrTestKeypair(t)

	sig := schnorrTestSign(t, sk1, []byte("hello"))

	if SchnorrVerify([]byte("hello"), sig, pk2) {
		t.Fatal("signature verified with wrong key")
	}
}

func TestSchnorrRejectsNilSignature(t *testing.T) {
	_, pk := schnorrTestKeypair(t)

	if SchnorrVerify([]byte("hello"), nil, pk) {
		t.Fatal("nil signature should not verify")
	}
}

func TestSchnorrUnlinkability(t *testing.T) {
	sk, pk := schnorrTestKeypair(t)
	msg := []byte("same message")

	sig1 := schnorrTestSign(t, sk, msg)
	sig2 := schnorrTestSign(t, sk, msg)

	if !SchnorrVerify(msg, sig1, pk) || !SchnorrVerify(msg, sig2, pk) {
		t.Fatal("valid signatures rejected")
	}

	// R' values should differ (different random blinding each time)
	if sig1.Rx.Cmp(sig2.Rx) == 0 && sig1.Ry.Cmp(sig2.Ry) == 0 {
		t.Fatal("two blind signatures have identical R' — should differ")
	}

	// s' values should differ too
	if sig1.S.Cmp(sig2.S) == 0 {
		t.Fatal("two blind signatures have identical s' — should differ")
	}
}

func TestSchnorrEmptyMessage(t *testing.T) {
	sk, pk := schnorrTestKeypair(t)
	sig := schnorrTestSign(t, sk, []byte{})

	if !SchnorrVerify([]byte{}, sig, pk) {
		t.Fatal("empty message signature rejected")
	}
}

func TestSchnorrSignatureRoundtrip(t *testing.T) {
	sk, pk := schnorrTestKeypair(t)
	sig := schnorrTestSign(t, sk, []byte("roundtrip"))

	// Serialize and parse
	data := sig.Bytes()
	if len(data) != 64 {
		t.Fatalf("signature size = %d, want 64", len(data))
	}

	sig2, err := ParseSchnorrSignature(data)
	if err != nil {
		t.Fatal(err)
	}

	if !SchnorrVerify([]byte("roundtrip"), sig2, pk) {
		t.Fatal("parsed signature failed verification")
	}
}

func TestSchnorrPublicKeyRoundtrip(t *testing.T) {
	_, pk := schnorrTestKeypair(t)

	data := pk.Bytes()
	if len(data) != 32 {
		t.Fatalf("public key size = %d, want 32", len(data))
	}

	pk2, err := ParseSchnorrPublicKey(data)
	if err != nil {
		t.Fatal(err)
	}

	// Sign with original key, verify with parsed key
	sk, _ := schnorrTestKeypair(t)
	sig := schnorrTestSign(t, sk, []byte("pk roundtrip"))
	// Verify with the original pk for that sk
	if !SchnorrVerify([]byte("pk roundtrip"), sig, sk.PublicKey()) {
		t.Fatal("original pk verification failed")
	}

	// Verify pk2 roundtripped correctly
	if pk.x.Cmp(pk2.x) != 0 || pk.y.Cmp(pk2.y) != 0 {
		t.Fatal("public key roundtrip mismatch")
	}
}

func TestSchnorrMultipleMessagesDistinct(t *testing.T) {
	sk, pk := schnorrTestKeypair(t)

	messages := [][]byte{
		[]byte("message one"),
		[]byte("message two"),
		[]byte("message three"),
	}

	sigs := make([]*SchnorrSignature, len(messages))
	for i, msg := range messages {
		sigs[i] = schnorrTestSign(t, sk, msg)
		if !SchnorrVerify(msg, sigs[i], pk) {
			t.Fatalf("message %d: valid signature rejected", i)
		}
	}

	// Each signature should be unique
	for i := 0; i < len(sigs); i++ {
		for j := i + 1; j < len(sigs); j++ {
			if sigs[i].S.Cmp(sigs[j].S) == 0 && sigs[i].Rx.Cmp(sigs[j].Rx) == 0 {
				t.Fatalf("signatures %d and %d are identical", i, j)
			}
		}
	}
}

func BenchmarkSchnorrBlindSign(b *testing.B) {
	sk, pk := func() (*SchnorrPrivateKey, *SchnorrPublicKey) {
		sk, pk, _ := GenerateSchnorrKey()
		return sk, pk
	}()
	msg := []byte("benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := SchnorrBlindSign(msg, sk)
		if err != nil {
			b.Fatal(err)
		}
		if !SchnorrVerify(msg, sig, pk) {
			b.Fatal("verification failed")
		}
	}
}
