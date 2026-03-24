// Package blindsig implements blind signature schemes.
//
// Blind signatures allow a signer to sign a message without learning its
// content. Two schemes are provided:
//
//   - RSA blind signatures (Chaum, 1983) using full-domain hashing.
//     Provides full unlinkability: the signer cannot correlate a signing
//     session with the resulting signature.
//
//   - ML-DSA-65 blind signatures using hash commitments.
//     Provides message hiding: the signer never sees the message content.
//     Does NOT provide unlinkability — the signer can later link a signature
//     to the signing session if they retained the blinded message.
//     This scheme is quantum-resistant (NIST security level 3).
package blindsig

import "errors"

// ErrInvalidSignature is returned when a blind signature fails verification.
var ErrInvalidSignature = errors.New("invalid blind signature")
