// Package blindsig implements blind signature schemes.
//
// Blind signatures allow a signer to sign a message without learning its
// content. Two schemes are provided:
//
//   - RSA blind signatures (Chaum, 1983) using full-domain hashing.
//     Provides full unlinkability: the signer cannot correlate a signing
//     session with the resulting signature.
//
//   - ML-DSA-65 blind signatures using an interactive Schnorr-over-lattice
//     protocol. Provides full unlinkability via algebraic blinding (the client
//     randomizes the commitment with A·α). Uses ML-DSA-65 key material with
//     t = A·s1 (no s2 error term). Quantum-resistant (NIST security level 3).
//     The protocol is 3-move: commit → challenge → respond, with possible
//     retries on rejection sampling.
package blindsig

import "errors"

// ErrInvalidSignature is returned when a blind signature fails verification.
var ErrInvalidSignature = errors.New("invalid blind signature")
