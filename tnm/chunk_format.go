/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CHUNK format functions - now using generic utilities from tdns/v2/core
 * This file re-exports core functions for backward compatibility within tnm package
 */

package tnm

import (
	"github.com/johanix/tdns/v2/core"
)

// ManifestData is re-exported from core for backward compatibility within tnm
type ManifestData = core.ManifestData

// CreateCHUNKManifest creates a CHUNK manifest record from manifest data.
// Re-exported from core.CreateCHUNKManifest for backward compatibility.
func CreateCHUNKManifest(manifestData *ManifestData, format uint8) (*core.CHUNK, error) {
	return core.CreateCHUNKManifest(manifestData, format)
}

// ExtractManifestData extracts ManifestData from a CHUNK manifest record.
// Re-exported from core.ExtractManifestData for backward compatibility.
func ExtractManifestData(chunk *core.CHUNK) (*ManifestData, error) {
	return core.ExtractManifestData(chunk)
}

// CalculateCHUNKHMAC calculates HMAC-SHA256 for a CHUNK manifest record.
// Re-exported from core.CalculateCHUNKHMAC for backward compatibility.
func CalculateCHUNKHMAC(chunk *core.CHUNK, hmacKey []byte) error {
	return core.CalculateCHUNKHMAC(chunk, hmacKey)
}

// VerifyCHUNKHMAC verifies the HMAC-SHA256 for a CHUNK manifest record.
// Re-exported from core.VerifyCHUNKHMAC for backward compatibility.
func VerifyCHUNKHMAC(chunk *core.CHUNK, hmacKey []byte) (bool, error) {
	return core.VerifyCHUNKHMAC(chunk, hmacKey)
}
