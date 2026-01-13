/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE decryption and key storage for tdns-krs
 */

package krs

import (
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns/v0.x/hpke"
)

// DecryptAndStoreKey decrypts encrypted key data and stores the key in the database
func DecryptAndStoreKey(krsDB *KrsDB, encryptedKey []byte, ephemeralPrivKey []byte, longTermPrivKey []byte, distributionID, zoneID string) error {
	// Decrypt using HPKE
	// The encryptedKey contains the encapsulated key + ciphertext
	// We use the long-term private key to decrypt
	plaintext, err := hpke.Decrypt(longTermPrivKey, nil, encryptedKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt key: %v", err)
	}

	// TODO: Parse the decrypted plaintext as a DNSSEC private key (PEM format)
	// For now, we'll store it as-is
	log.Printf("KRS: Successfully decrypted key for distribution %s, zone %s (size: %d bytes)", distributionID, zoneID, len(plaintext))

	// TODO: Extract key metadata from the distribution or from a separate metadata query
	// For now, create a basic ReceivedKey structure
	key := &ReceivedKey{
		ID:             distributionID,
		ZoneName:       zoneID, // zoneID parameter is actually zone name
		KeyID:          0, // TODO: Extract from metadata
		KeyType:        "ZSK", // TODO: Extract from metadata
		Algorithm:      15,    // TODO: Extract from metadata (ED25519)
		Flags:          256,   // TODO: Extract from metadata (ZSK flags)
		PublicKey:      "",    // TODO: Extract from metadata
		PrivateKey:     plaintext,
		State:          "received",
		ReceivedAt:     time.Now(),
		DistributionID: distributionID,
	}

	// Store in database
	if err := krsDB.AddReceivedKey(key); err != nil {
		return fmt.Errorf("failed to store received key: %v", err)
	}

	log.Printf("KRS: Stored key for distribution %s, zone %s", distributionID, zoneID)
	return nil
}
