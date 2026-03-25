// Package blindsig implements blind signature schemes.
//
// Blind signatures allow a signer to sign a message without learning its
// content. Two schemes are provided:
//
//   - RSA blind signatures (Chaum, 1983) using full-domain hashing.
//     Provides full unlinkability: the signer cannot correlate a signing
//     session with the resulting signature.
//
//   - BLNS23 lattice-based blind signatures (Beullens-Lyubashevsky-Nguyen-Seiler,
//     ePrint 2023/077) using NTRU pre-image sampling and NIZK proofs.
//     Provides full unlinkability: the signer computes a short pre-image of a
//     blinded commitment, and the user creates a zero-knowledge proof as the
//     signature. The signer never sees any component of the final signature.
//     Quantum-resistant, based on Ring-SIS, Ring-LWE, and NTRU assumptions.
//     2-round protocol. Signature size ~15 KB.
package blindsig

import "errors"

// ErrInvalidSignature is returned when a blind signature fails verification.
var ErrInvalidSignature = errors.New("invalid blind signature")
