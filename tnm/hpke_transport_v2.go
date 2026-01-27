/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared crypto abstraction encryption/decryption transport functions (V2)
 * DEPRECATED: Use github.com/johanix/tdns/v2/distrib instead
 */

package tnm

import (
	"github.com/johanix/tdns/v2/crypto"
	"github.com/johanix/tdns/v2/distrib"
)

// EncryptAndEncodeV2 encrypts plaintext using the specified crypto backend and encodes it for transport
// DEPRECATED: Use distrib.EncryptAndEncode instead
func EncryptAndEncodeV2(recipientPubKey crypto.PublicKey, plaintext []byte, backend crypto.Backend) ([]byte, error) {
	return distrib.EncryptAndEncode(recipientPubKey, plaintext, backend)
}

// DecodeAndDecryptV2 decodes base64-encoded encrypted data and decrypts it using the specified crypto backend
// DEPRECATED: Use distrib.DecodeAndDecrypt instead
func DecodeAndDecryptV2(privateKey crypto.PrivateKey, base64Data []byte, backend crypto.Backend) ([]byte, error) {
	return distrib.DecodeAndDecrypt(privateKey, base64Data, backend)
}

// EncryptSignAndEncodeV2 encrypts plaintext and signs it, creating JWS(JWE(payload))
// DEPRECATED: Use distrib.EncryptSignAndEncode instead
func EncryptSignAndEncodeV2(recipientPubKey crypto.PublicKey, plaintext []byte, signingKey crypto.PrivateKey, backend crypto.Backend, metadata map[string]interface{}) ([]byte, error) {
	return distrib.EncryptSignAndEncode(recipientPubKey, plaintext, signingKey, backend, metadata)
}

// DecodeDecryptAndVerifyV2 decodes, verifies signature, and decrypts JWS(JWE(payload))
// DEPRECATED: Use distrib.DecodeDecryptAndVerify instead
func DecodeDecryptAndVerifyV2(privateKey crypto.PrivateKey, verificationKey crypto.PublicKey, base64Data []byte, backend crypto.Backend) ([]byte, error) {
	return distrib.DecodeDecryptAndVerify(privateKey, verificationKey, base64Data, backend)
}
