/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared cryptographic helper functions for TDNS Node Management
 * These functions abstract encryption/decryption operations and can be used
 * by both KDC and KRS components.
 */

package tnm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/v2/crypto"
	_ "github.com/johanix/tdns/v2/crypto/hpke" // Auto-register HPKE backend
	_ "github.com/johanix/tdns/v2/crypto/jose" // Auto-register JOSE backend
)

// SelectBackend selects a crypto backend based on supported crypto list and forced preference.
// This is a generic version that works with any supported crypto list (not just Node structs).
//
// Parameters:
//   - supportedCrypto: List of supported backends (e.g., []string{"hpke"}, []string{"jose"}, []string{"hpke", "jose"})
//   - forcedCrypto: Optional backend to force ("hpke" or "jose"); empty string auto-selects
//
// Returns:
//   - backendName: The selected backend name ("hpke" or "jose")
func SelectBackend(supportedCrypto []string, forcedCrypto string) string {
	// If forced crypto is specified, use it if supported
	if forcedCrypto != "" {
		for _, supported := range supportedCrypto {
			if supported == forcedCrypto {
				return forcedCrypto
			}
		}
		// Forced crypto not supported - fall through to auto-select
		log.Printf("TNM: Warning: Forced crypto backend %s not in supported list %v, auto-selecting instead", forcedCrypto, supportedCrypto)
	}

	// Use the first supported backend
	// Later: could have policy (prefer JOSE, fallback to HPKE, etc.)
	if len(supportedCrypto) > 0 {
		return supportedCrypto[0]
	}
	// Fallback to HPKE if no supported crypto is specified
	return "hpke"
}

// EncryptPayload encrypts an arbitrary plaintext payload using the specified crypto backend.
// This is the core encryption function that abstracts crypto backend selection and encryption
// from operation-specific logic. Both KDC and KRS can use this function.
//
// Parameters:
//   - plaintext: The unencrypted payload to encrypt (operation-agnostic)
//   - publicKeyData: Raw public key bytes (HPKE: 32-byte X25519 key, JOSE: JWK JSON bytes)
//   - backendName: The crypto backend to use ("hpke" or "jose")
//   - supportedCrypto: Optional list of supported backends (for validation); can be nil
//   - context: Optional context string for logging (e.g., "node ID" or "KDC")
//
// Returns:
//   - ciphertext: The encrypted payload
//   - ephemeralPub: Ephemeral public key (32 bytes for HPKE, empty for JOSE)
//   - error: Any error during encryption
func EncryptPayload(plaintext []byte, publicKeyData []byte, backendName string, supportedCrypto []string, context string) (ciphertext []byte, ephemeralPub []byte, err error) {
	if plaintext == nil {
		return nil, nil, fmt.Errorf("plaintext is nil")
	}
	if publicKeyData == nil || len(publicKeyData) == 0 {
		return nil, nil, fmt.Errorf("public key data is nil or empty")
	}
	if backendName == "" {
		return nil, nil, fmt.Errorf("backend name is empty")
	}

	// Validate backend is supported if supportedCrypto list is provided
	if supportedCrypto != nil && len(supportedCrypto) > 0 {
		found := false
		for _, supported := range supportedCrypto {
			if supported == backendName {
				found = true
				break
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("backend %s not in supported crypto list %v", backendName, supportedCrypto)
		}
	}

	// Get crypto backend
	backend, err := crypto.GetBackend(backendName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get crypto backend %s: %v", backendName, err)
	}

	logCtx := context
	if logCtx == "" {
		logCtx = "payload"
	}
	log.Printf("TNM: Encrypting %s using %s backend", logCtx, backendName)

	// Parse public key using the selected backend
	publicKey, err := backend.ParsePublicKey(publicKeyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key with %s backend: %v", backendName, err)
	}

	// Encrypt the plaintext using the backend
	ciphertext, err = backend.Encrypt(publicKey, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt payload with %s backend: %v", backendName, err)
	}

	// Handle ephemeral public key extraction based on backend
	// - HPKE: Extract from ciphertext (first 32 bytes is encapsulated key)
	// - JOSE: Ephemeral key is embedded in JWE header, return empty
	if backendName == "hpke" {
		// For HPKE, the first 32 bytes of ciphertext is the encapsulated key (ephemeral public key)
		// NOTE: This embeds HPKE-specific ciphertext format knowledge. If HPKE format changes, this will break.
		// TODO: Consider adding GetEphemeralKey(ciphertext []byte) []byte method to crypto.Backend interface
		if len(ciphertext) >= 32 {
			ephemeralPub = make([]byte, 32)
			copy(ephemeralPub, ciphertext[:32])
		}
	} else {
		// JOSE (JWE) wraps the ephemeral key exchange within the ciphertext itself:
		// The JWE header contains the ephemeral public key used for ECDH-ES key agreement,
		// so there's no separate ephemeralPubKey field needed. The recipient extracts it
		// from the JWE header during decryption. Set to empty to indicate this difference.
		ephemeralPub = []byte{}
	}

	log.Printf("TNM: Successfully encrypted %s using %s backend (ciphertext length: %d)", logCtx, backendName, len(ciphertext))
	return ciphertext, ephemeralPub, nil
}
