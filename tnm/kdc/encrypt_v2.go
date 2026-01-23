/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE encryption functions for key distribution (V2 - crypto abstraction)
 * This is the v2 implementation using the crypto abstraction layer.
 * The v1 implementation (encrypt.go) remains unchanged for backward compatibility.
 */

package kdc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	tnm "github.com/johanix/tdns-nm/tnm"
	"github.com/johanix/tdns/v2/crypto"
	"github.com/johanix/tdns/v2/hpke"
)

// EncryptKeyForNodeV2 encrypts a DNSSEC key's private key material for a specific node
// using the provided crypto backend (HPKE or JOSE).
// This is the v2 implementation using crypto abstraction.
// Returns: encrypted key data, ephemeral public key used (backend-specific), distribution ID, error
// This function also stores the distribution record in the database
// kdcConf is optional - if provided, expires_at will be set based on DistributionTTL
// distributionID is optional - if provided, uses that ID; otherwise generates one for this key
// backend specifies which crypto backend to use (hpke or jose)
func (kdc *KdcDB) EncryptKeyForNodeV2(
	key *DNSSECKey,
	node *Node,
	backend crypto.Backend,
	kdcConf *tnm.KdcConf,
	distributionID ...string,
) (encryptedKey []byte, ephemeralPubKey []byte, distID string, err error) {
	if key == nil {
		return nil, nil, "", fmt.Errorf("key is nil")
	}
	if node == nil {
		return nil, nil, "", fmt.Errorf("node is nil")
	}
	if backend == nil {
		return nil, nil, "", fmt.Errorf("backend is nil")
	}

	// Use provided distribution ID, or get/create one for this key
	if len(distributionID) > 0 && distributionID[0] != "" {
		distID = distributionID[0]
	} else {
		distID, err = kdc.GetOrCreateDistributionID(key.ZoneName, key)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to get/create distribution ID: %v", err)
		}
	}

	// Parse node's public key using the backend
	nodePubKey, err := backend.ParsePublicKey(node.LongTermPubKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse node public key with %s backend: %v", backend.Name(), err)
	}

	// Encrypt the private key using the backend
	ciphertext, err := backend.Encrypt(nodePubKey, key.PrivateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to encrypt key with %s backend: %v", backend.Name(), err)
	}

	// For ephemeral public key:
	// - HPKE: Returns the encapsulated key (32 bytes for X25519)
	// - JOSE: JWE includes ephemeral key in the header, so we return nil
	// To maintain compatibility with existing code, extract ephemeral key from ciphertext for HPKE
	var ephemeralPub []byte
	if backend.Name() == "hpke" {
		// For HPKE, the first 32 bytes of ciphertext is the encapsulated key (ephemeral public key)
		if len(ciphertext) >= 32 {
			ephemeralPub = make([]byte, 32)
			copy(ephemeralPub, ciphertext[:32])
		}
	}
	// For JOSE, ephemeralPub remains nil (ephemeral key is in JWE header)

	// Generate a unique ID for this distribution record
	distRecordID := make([]byte, 16)
	if _, err := rand.Read(distRecordID); err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate distribution record ID: %v", err)
	}
	distRecordIDHex := hex.EncodeToString(distRecordID)

	// Calculate expires_at based on DistributionTTL if config is provided
	var expiresAt *time.Time
	if kdcConf != nil {
		ttl := kdcConf.GetDistributionTTL()
		if ttl > 0 {
			expires := time.Now().Add(ttl)
			expiresAt = &expires
		}
	}

	// Store the distribution record in the database
	distRecord := &DistributionRecord{
		ID:             distRecordIDHex,
		ZoneName:       key.ZoneName,
		KeyID:          key.ID,
		NodeID:         node.ID,
		EncryptedKey:   ciphertext,
		EphemeralPubKey: ephemeralPub,
		CreatedAt:      time.Now(),
		ExpiresAt:      expiresAt,
		Status:         hpke.DistributionStatusPending,
		DistributionID: distID,
		Operation:      "roll_key",
		Payload:        make(map[string]interface{}),
	}

	if err := kdc.AddDistributionRecord(distRecord); err != nil {
		// Log error but don't fail - the encryption succeeded
		// TODO: Consider making this a hard error
		fmt.Printf("Warning: Failed to store distribution record: %v\n", err)
	}

	return ciphertext, ephemeralPub, distID, nil
}
