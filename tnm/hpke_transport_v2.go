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
