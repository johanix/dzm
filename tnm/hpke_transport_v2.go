/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared crypto abstraction encryption/decryption transport functions (V2)
 * Handles both HPKE and JOSE backends through the crypto abstraction layer
 */

package tnm

import (
	"encoding/base64"
	"fmt"

	"github.com/johanix/tdns/v2/crypto"
)

// EncryptAndEncodeV2 encrypts plaintext using the specified crypto backend and encodes it for transport
// The transport format is: base64(<backend-specific ciphertext>)
// For HPKE: <encapsulated_key (32 bytes)><encrypted_data>
// For JOSE: JWE compact serialization (header.encrypted_key.iv.ciphertext.tag)
func EncryptAndEncodeV2(recipientPubKey crypto.PublicKey, plaintext []byte, backend crypto.Backend) ([]byte, error) {
	if backend == nil {
		return nil, fmt.Errorf("backend is nil")
	}

	// Encrypt using the crypto backend
	ciphertext, err := backend.Encrypt(recipientPubKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with %s backend: %v", backend.Name(), err)
	}

	// Base64 encode the encrypted data
	base64Data := []byte(base64.StdEncoding.EncodeToString(ciphertext))

	return base64Data, nil
}

// DecodeAndDecryptV2 decodes base64-encoded encrypted data and decrypts it using the specified crypto backend
// The transport format is: base64(<backend-specific ciphertext>)
// For HPKE: <encapsulated_key (32 bytes)><encrypted_data>
// For JOSE: JWE compact serialization (header.encrypted_key.iv.ciphertext.tag)
func DecodeAndDecryptV2(privateKey crypto.PrivateKey, base64Data []byte, backend crypto.Backend) ([]byte, error) {
	if backend == nil {
		return nil, fmt.Errorf("backend is nil")
	}

	// Decode base64 to get encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(string(base64Data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 encrypted data: %v", err)
	}

	// Decrypt using the crypto backend
	// Each backend handles its own ciphertext format internally
	plaintext, err := backend.Decrypt(privateKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with %s backend: %v", backend.Name(), err)
	}

	return plaintext, nil
}

// EncryptSignAndEncodeV2 encrypts plaintext and signs it, creating JWS(JWE(payload))
// This creates authenticated distributions using JWS(JWE(...)) structure.
// The transport format is: base64(JWS(JWE(...)))
// - Step 1: JWE encrypts the payload for the recipient(s)
// - Step 2: JWS signs the JWE structure with the sender's signing key
// This provides both confidentiality (JWE) and authenticity (JWS).
func EncryptSignAndEncodeV2(recipientPubKey crypto.PublicKey, plaintext []byte, signingKey crypto.PrivateKey, backend crypto.Backend, metadata map[string]interface{}) ([]byte, error) {
	if backend == nil {
		return nil, fmt.Errorf("backend is nil")
	}
	if signingKey == nil {
		return nil, fmt.Errorf("signing key is nil")
	}

	// Create recipients slice (currently single-recipient)
	recipients := []crypto.PublicKey{recipientPubKey}

	// Step 1: Encrypt using EncryptMultiRecipient (creates JWE)
	jwe, err := backend.EncryptMultiRecipient(recipients, plaintext, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with %s backend: %v", backend.Name(), err)
	}

	// Step 2: Sign the JWE (creates JWS(JWE))
	jws, err := backend.Sign(signingKey, jwe)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with %s backend: %v", backend.Name(), err)
	}

	// Base64 encode the JWS for transport
	base64Data := []byte(base64.StdEncoding.EncodeToString(jws))

	return base64Data, nil
}

// DecodeDecryptAndVerifyV2 decodes, verifies signature, and decrypts JWS(JWE(payload))
// This verifies authenticity before decryption using a two-step process.
// The transport format is: base64(JWS(JWE(...)))
// - Step 1: Verifies the JWS signature using the sender's public key
// - Step 2: Decrypts the JWE content using the recipient's private key
// Returns an error if signature verification fails.
func DecodeDecryptAndVerifyV2(privateKey crypto.PrivateKey, verificationKey crypto.PublicKey, base64Data []byte, backend crypto.Backend) ([]byte, error) {
	if backend == nil {
		return nil, fmt.Errorf("backend is nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if verificationKey == nil {
		return nil, fmt.Errorf("verification key is nil")
	}

	// Decode base64 to get JWS
	jws, err := base64.StdEncoding.DecodeString(string(base64Data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 JWS: %v", err)
	}

	// Step 1: Verify the JWS signature and extract the JWE payload
	// The JWS payload is the JWE structure
	// We need to parse the JWS, verify it, and extract the JWE
	// For now, use a simple approach: verify with empty data (signature verification only)
	// Then manually extract the JWE from the JWS structure

	// Parse JWS to extract JWE payload
	// JWS Compact Serialization: <header>.<payload>.<signature>
	parts := splitJWS(jws)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (which is the JWE)
	jwe, err := base64Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWS payload: %v", err)
	}

	// Verify the JWS signature (data is the JWE we're about to decrypt)
	valid, err := backend.Verify(verificationKey, jwe, jws)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature with %s backend: %v", backend.Name(), err)
	}
	if !valid {
		return nil, fmt.Errorf("signature verification failed: invalid signature")
	}

	// Step 2: Decrypt the JWE using the recipient's private key
	plaintext, err := backend.DecryptMultiRecipient(privateKey, jwe)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with %s backend: %v", backend.Name(), err)
	}

	return plaintext, nil
}

// splitJWS splits a JWS Compact Serialization into its three parts
func splitJWS(jws []byte) [][]byte {
	// Split by '.'
	var parts [][]byte
	start := 0
	for i := 0; i < len(jws); i++ {
		if jws[i] == '.' {
			parts = append(parts, jws[start:i])
			start = i + 1
		}
	}
	// Add last part
	if start < len(jws) {
		parts = append(parts, jws[start:])
	}
	return parts
}

// base64Decode decodes base64url (RFC 4648) data
func base64Decode(data []byte) ([]byte, error) {
	// JWS uses base64url encoding (RFC 4648), not standard base64
	// Go's base64.RawURLEncoding handles this
	decoded, err := base64.RawURLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
