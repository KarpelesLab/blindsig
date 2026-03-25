// Package blindsig implements blind signature schemes.
//
// Blind signatures allow a signer to sign a message without learning its
// content. Three schemes are provided:
//
//   - RSA blind signatures (Chaum, 1983) using full-domain hashing.
//     Non-interactive (1 round). 384-byte signatures. Not quantum-safe.
//
//   - Schnorr blind signatures over Ed25519. Interactive (3 rounds).
//     64-byte signatures. Not quantum-safe, but efficient and compact.
//
//   - BLNS23 lattice-based blind signatures (Beullens-Lyubashevsky-Nguyen-Seiler,
//     ePrint 2023/077) using NTRU pre-image sampling and NIZK proofs.
//     Interactive (2 rounds). ~50 KB signatures. Quantum-resistant.
//
// All three schemes provide full unlinkability: the signer cannot correlate
// a signing session with the resulting signature.
package blindsig

import "errors"

// ErrInvalidSignature is returned when a blind signature fails verification.
var ErrInvalidSignature = errors.New("invalid blind signature")
