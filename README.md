# blindsig

[![Tests](https://github.com/KarpelesLab/blindsig/actions/workflows/test.yml/badge.svg)](https://github.com/KarpelesLab/blindsig/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/KarpelesLab/blindsig/badge.svg?branch=master)](https://coveralls.io/github/KarpelesLab/blindsig?branch=master)
[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/blindsig.svg)](https://pkg.go.dev/github.com/KarpelesLab/blindsig)
[![Go Report Card](https://goreportcard.com/badge/github.com/KarpelesLab/blindsig)](https://goreportcard.com/report/github.com/KarpelesLab/blindsig)

Blind signature schemes in Go. A blind signature lets a signer sign a message **without learning what the message is**, and later, when the signature is revealed, the signer **cannot link it back** to the signing session that produced it.

Four schemes are provided:

| Scheme | Assumption | Quantum-safe | Signature size | Rounds |
|--------|-----------|:------------:|---------------:|:------:|
| **RSA** (Chaum 1983) | Factoring | No | 384 B (3072-bit) | 1 |
| **Ed25519** (Schnorr) | Discrete log | No | 64 B | 3 |
| **secp256k1** (Schnorr/BIP-340) | Discrete log | No | 64 B | 3 |
| **BLNS23** (Beullens et al. 2023) | Ring-SIS + Ring-LWE + NTRU | Yes | ~50 KB | 2 |

## Installation

```bash
go get github.com/KarpelesLab/blindsig
```

## What is a blind signature?

A blind signature protocol has three parties: a **user** (wants a signature), a **signer** (has the signing key), and a **verifier** (checks the signature later).

1. The user **blinds** their message — transforming it so the signer cannot read it.
2. The signer **signs** the blinded value — without learning anything about the original message.
3. The user **unblinds** the result — recovering a valid signature on the original message.
4. Anyone can **verify** the signature against the signer's public key.

The critical security property is **unlinkability**: even if the signer later sees the (message, signature) pair, they cannot determine which signing session produced it. This is what makes blind signatures useful for anonymous voting, e-cash, and privacy-preserving credentials.

## RSA blind signatures

The RSA scheme uses Chaum's protocol (1983) with full-domain hashing (FDH). Unlinkability comes from RSA's algebraic homomorphism: the blinding factor `r^e` multiplied into the message cancels perfectly when divided out after signing, leaving no trace.

### How it works

```
Client                              Server
------                              ------
m = FDH(message)
pick random r, compute r^e mod n
blinded = m · r^e mod n
                     blinded ──►
                                    blindSig = blinded^d mod n
                     ◄── blindSig
sig = blindSig · r^{-1} mod n
    = m^d mod n                     (valid RSA signature)
```

The signer computes `blinded^d = (m · r^e)^d = m^d · r`. The client removes `r` by multiplying by `r^{-1}`, leaving `m^d` — a standard RSA signature. The signer only ever saw `m · r^e`, which is uniformly random and reveals nothing about `m`.

### Usage

```go
package main

import (
    "fmt"
    "github.com/KarpelesLab/blindsig"
)

func main() {
    // Key generation
    key, _ := blindsig.GenerateBlindSigningKey(3072)
    pub := &key.PublicKey

    message := []byte("vote for candidate A")

    // Client: blind the message
    blinded, r, _ := blindsig.BlindMessage(message, pub)

    // Server: sign without seeing the message
    blindSig, _ := blindsig.SignBlinded(blinded, key)

    // Client: unblind to get a valid signature
    sig, _ := blindsig.UnblindSignature(blindSig, r, pub)

    // Anyone: verify
    valid := blindsig.VerifySignature(message, sig, pub)
    fmt.Println("Valid:", valid) // true
}
```

## Schnorr blind signatures (Ed25519)

The Schnorr scheme uses the classic blind Schnorr protocol over the Ed25519 curve. Unlinkability comes from the client adding random blinding factors to both the commitment point and the challenge, which cancel out algebraically in the final signature.

### How it works

```
Client                              Server
------                              ------
                                    pick random k
                                    R = kB
                     ◄── R
pick random α, β
R' = R + αB + βA                    (blinded commitment)
e' = H(R' || A || msg)
e = e' + β                          (blinded challenge)
                     e ──►
                                    s = k + e·a mod L
                     ◄── s
s' = s + α mod L                    (unblind response)
sig = (R', s')                       (64 bytes)
```

The signer saw `e` and `R`, but the signature contains `e'` (derived from `R'`) and `s'`. Since α and β are random and unknown to the signer, they cannot link `(R, e)` to `(R', s')`. The algebraic identity holds because `s'B = (k + ea + α)B = R + eA + αB = R' + e'A` (since `e = e' + β` and `R' = R + αB + βA`).

### Usage

```go
package main

import (
    "fmt"
    "github.com/KarpelesLab/blindsig"
)

func main() {
    // Key generation
    sk, pk, _ := blindsig.GenerateSchnorrKey()

    message := []byte("vote for candidate A")

    // Round 1 — Server: commit
    signerState, commitment, _ := blindsig.SchnorrSignerCommit()

    // Round 2 — Client: create blinded challenge
    clientState, challenge, _ := blindsig.SchnorrClientChallenge(message, commitment, pk)

    // Round 3 — Server: respond
    response, _ := blindsig.SchnorrSignerRespond(signerState, challenge, sk)

    // Client: unblind
    sig, _ := blindsig.SchnorrClientUnblind(clientState, response, pk)

    // Anyone: verify
    valid := blindsig.SchnorrVerify(message, sig, pk)
    fmt.Println("Valid:", valid) // true
}
```

Or using the convenience function:

```go
sig, _ := blindsig.SchnorrBlindSign(message, sk)
valid := blindsig.SchnorrVerify(message, sig, sk.PublicKey())
```

## secp256k1 blind signatures (BIP-340)

The secp256k1 scheme uses the same blind Schnorr protocol as Ed25519 but over the secp256k1 curve with BIP-340 conventions: x-only R encoding, even-y enforcement, and BLAKE-256 challenge hash. Signatures are compatible with the Bitcoin/Decred Schnorr ecosystem.

The sign convention is `s = k - e·x` (subtraction, vs Ed25519's addition), so the blinding signs are flipped: `R' = R - αG - βP` and `s' = s - α`. The client retries blinding if `R'.y` is odd (about 50% of the time, adding ~1 retry on average).

Note: secp256k1 blind signing takes a **32-byte hash** (pre-hashed message), not the raw message.

### Usage

```go
package main

import (
    "crypto/sha256"
    "fmt"
    "github.com/KarpelesLab/blindsig"
)

func main() {
    sk, pk, _ := blindsig.GenerateSecp256k1Key()

    hash := sha256.Sum256([]byte("vote for candidate A"))

    // Round 1 — Server: commit
    signerState, commitment, _ := blindsig.Secp256k1SignerCommit()

    // Round 2 — Client: create blinded challenge
    clientState, challenge, _ := blindsig.Secp256k1ClientChallenge(hash[:], commitment, pk)

    // Round 3 — Server: respond
    response, _ := blindsig.Secp256k1SignerRespond(signerState, challenge, sk)

    // Client: unblind
    sig, _ := blindsig.Secp256k1ClientUnblind(clientState, response, pk)

    // Anyone: verify
    valid := blindsig.Secp256k1Verify(hash[:], sig, pk)
    fmt.Println("Valid:", valid) // true
}
```

## BLNS23 lattice-based blind signatures

The BLNS23 scheme ([ePrint 2023/077](https://eprint.iacr.org/2023/077)) is a post-quantum blind signature based on standard lattice assumptions (Ring-SIS, Ring-LWE, and NTRU). Unlike RSA, lattice-based schemes don't have algebraic homomorphism, so the blinding mechanism is fundamentally different.

### How it works

The key insight: the signer never sees **any component** of the final signature. Instead of algebraic unblinding, BLNS23 uses a combination of hash commitments, NTRU pre-image sampling, and zero-knowledge proofs.

```
Client                              Server
------                              ------
pick random short r
ρ = G(r)                            (hash, kept secret for now)
h = H(ρ, message)                   (target hash)
c = B·r + h                         (blinded commitment)
                       c ──►
                                    find short s with A·s = c
                                    (uses NTRU trapdoor)
                       ◄── s
verify A·s = c
π = NIZK proof that ∃(r, s):
    A·s = B·r + h   (linear relation)
    ||s||, ||r|| small   (shortness)

signature = (ρ, π)
```

**Why it's blind:** The signer sees only `c`, which is `B·r + H(G(r), message)`. Since `r` is random and unknown to the signer, `c` looks uniformly random — it reveals nothing about the message. The final signature is `(ρ, π)` where `ρ = G(r)` (a hash the signer never saw) and `π` is a zero-knowledge proof (which by definition reveals nothing beyond the statement's truth). The signer cannot link `c` to `(ρ, π)` because they never learn `r`, and the NIZK is simulated.

**Why it's unforgeable:** Finding short `s` with `A·s = c` requires the NTRU trapdoor. Without it, this is the Ring-SIS problem (conjectured hard even for quantum computers). The user cannot forge signatures because they cannot produce short pre-images on their own.

### Usage

```go
package main

import (
    "fmt"
    "github.com/KarpelesLab/blindsig"
)

func main() {
    // Key generation
    params := blindsig.BLNS23DefaultParams()
    sk, pk, _ := blindsig.GenerateBLNS23Key(params)

    message := []byte("vote for candidate A")

    // Round 1 — Client: create blinded commitment
    state, req, _ := blindsig.BLNS23UserBlind(message, pk)

    // Round 2 — Server: compute pre-image (never sees the message)
    resp, _ := blindsig.BLNS23SignerRespond(req, sk)

    // Client: create signature from signer's response
    sig, _ := blindsig.BLNS23UserFinalize(state, resp, pk)

    // Anyone: verify
    valid := blindsig.BLNS23Verify(message, sig, pk)
    fmt.Println("Valid:", valid) // true
}
```

There is also a convenience function for local use (testing, single-process scenarios):

```go
sig, _ := blindsig.BLNS23BlindSign(message, sk, pk)
valid := blindsig.BLNS23Verify(message, sig, pk)
```

## Comparing the three schemes

### How blinding works

The three schemes achieve blindness through different mechanisms:

**RSA** exploits the multiplicative homomorphism of modular exponentiation. The blinding factor `r^e` is multiplied into the message before signing and divided out after. The signer's computation `(m · r^e)^d` distributes as `m^d · r`, so the final signature `m^d` contains no trace of the blinding interaction. Elegant and non-interactive, but broken by quantum computers (Shor's algorithm).

**Schnorr** exploits the additive homomorphism of elliptic curve points. The client adds random offsets `αB` and `βA` to the commitment point, and a corresponding shift `β` to the challenge. After the signer responds, the client adds `α` to the response. All three blinding terms cancel algebraically: `s'B = R' + e'A`. The signer saw `(R, e)` but the signature contains `(R', e')` — completely unlinkable. Fast (sub-millisecond) with tiny 64-byte signatures, but also not quantum-safe.

**BLNS23** uses a fundamentally different approach because lattice-based cryptography has no useful homomorphism. Instead:

1. **The message is hidden inside a hash commitment.** The signer sees `c = B·r + H(G(r), μ)`, but since `r` is random, `c` is computationally indistinguishable from a random ring element. The signer learns nothing about `μ`.

2. **The signer's contribution (the pre-image `s`) never appears directly in the signature.** The signature is `(ρ, π)` — a hash and a zero-knowledge proof. The proof demonstrates that valid `r` and `s` exist without revealing them.

3. **The zero-knowledge proof provides unlinkability.** Even though the signer knows they produced some `s` for some `c`, the proof `π` is computationally indistinguishable from a simulated proof. The signer cannot match `π` to their signing session.

### Comparison table

| Property | RSA | Ed25519 | secp256k1 | BLNS23 |
|----------|-----|---------|-----------|--------|
| Blinding mechanism | Multiply by r^e | Shift R,e by +α,+β | Shift R,e by -α,-β | Hash commitment + NIZK |
| What the signer sees | m·r^e (random) | e (shifted challenge) | e (shifted challenge) | B·r + H(G(r),μ) (random) |
| What's in the signature | m^d | (R', s') | (R'.x, s') | (ρ, π) — hash + ZK proof |
| Unlinkability source | r^e cancels | α, β cancel | α, β cancel | ZK proof reveals nothing |
| Quantum-safe | No | No | No | Yes |
| Rounds | 1 | 3 | 3 | 2 |
| Key size (public) | 384 B | 32 B | 33 B | ~2 KB |
| Signature size | 384 B | 64 B | 64 B | ~50 KB |
| Hardness assumption | Factoring | DLP (Ed25519) | DLP (secp256k1) | Ring-SIS + LWE + NTRU |

### When to use which

- **Ed25519**: Best for most applications today. Tiny 64-byte signatures, fast operations, and widely deployed.

- **secp256k1**: When you need compatibility with the Bitcoin/Decred ecosystem (BIP-340 Schnorr). Same security and size as Ed25519 but uses the secp256k1 curve.

- **RSA**: When you need a non-interactive protocol (single round). The 384-byte signatures are larger but still compact. Useful when round-trip latency is a concern.

- **BLNS23**: When you need quantum resistance. The larger signatures (~50 KB) and two-round protocol are the cost of post-quantum security. As lattice-based proof systems improve, these sizes will shrink.

## Parameters

### RSA

- Minimum key size: 3072 bits (NIST SP 800-57)
- Hash: FDH using MGF1-SHA256 expansion to modulus size
- Signing: CRT exponentiation with timing blinding and Shamir fault detection

### Schnorr (Ed25519)

- Curve: Ed25519 (twisted Edwards, birational to Curve25519)
- Group order L: 2^252 + 27742317777372353535851937790883648493
- Challenge hash: SHA-512(R' || A || msg) mod L
- Signature: (R', s') = 64 bytes

### BLNS23

From the paper (Table 2):

| Parameter | Value | Description |
|-----------|-------|-------------|
| d | 512 | Polynomial ring degree (X^512 + 1) |
| q | 7933 | Signature ring modulus |
| q̂ | ≈ 2^41 | Proof ring modulus (q × 277199453) |
| σ | 232 | Gaussian std dev for pre-image sampling |
| r coefficients | {-2,-1,0,1,2} | User commitment randomness |
| NIZK κ | 60 | Challenge polynomial weight |

## References

- D. Chaum. *Blind Signatures for Untraceable Payments.* CRYPTO 1982.
- D. Pointcheval, J. Stern. *Security Arguments for Digital Signatures and Blind Signatures.* J. Cryptology, 2000. — Blind Schnorr security analysis.
- W. Beullens, V. Lyubashevsky, N. K. Nguyen, G. Seiler. *Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal.* [ePrint 2023/077](https://eprint.iacr.org/2023/077).
- V. Lyubashevsky, N. K. Nguyen, M. Plançon. *Lattice-Based Zero-Knowledge Proofs and Applications.* CRYPTO 2022. [ePrint 2022/284](https://eprint.iacr.org/2022/284).

## License

See [LICENSE](LICENSE) for details.
