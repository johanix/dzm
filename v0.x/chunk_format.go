/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared CHUNK format marshaling/unmarshaling functions
 */

package dzm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/johanix/tdns/v0.x/core"
)

// ManifestData represents the JSON structure stored in a CHUNK manifest's Data field
type ManifestData struct {
	ChunkCount uint16                 `json:"chunk_count"`
	ChunkSize  uint16                 `json:"chunk_size,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Payload    []byte                 `json:"payload,omitempty"`
}

// CreateCHUNKManifest creates a CHUNK manifest record from manifest data
func CreateCHUNKManifest(manifestData *ManifestData, format uint8) (*core.CHUNK, error) {
	manifestJSON, err := json.Marshal(manifestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest JSON: %v", err)
	}

	chunk := &core.CHUNK{
		Format:     format,
		HMACLen:    0, // Will be set after HMAC calculation
		HMAC:       nil,
		Sequence:   0, // Unused for manifest
		Total:      0, // 0 indicates manifest
		DataLength: uint16(len(manifestJSON)),
		Data:       manifestJSON,
	}

	return chunk, nil
}

// ExtractManifestData extracts ManifestData from a CHUNK manifest record
func ExtractManifestData(chunk *core.CHUNK) (*ManifestData, error) {
	if chunk.Total != 0 {
		return nil, fmt.Errorf("ExtractManifestData can only be called for manifest chunks (Total=0), got Total=%d", chunk.Total)
	}

	if chunk.Format != core.FormatJSON {
		return nil, fmt.Errorf("unsupported CHUNK format: %d (expected FormatJSON=%d)", chunk.Format, core.FormatJSON)
	}

	var manifestData ManifestData
	if err := json.Unmarshal(chunk.Data, &manifestData); err != nil {
		return nil, fmt.Errorf("failed to parse CHUNK manifest JSON: %v", err)
	}

	return &manifestData, nil
}

// CalculateCHUNKHMAC calculates HMAC-SHA256 for a CHUNK manifest record
func CalculateCHUNKHMAC(chunk *core.CHUNK, hmacKey []byte) error {
	if chunk.Total != 0 {
		return fmt.Errorf("HMAC can only be calculated for manifest chunks (Total=0), got Total=%d", chunk.Total)
	}

	if len(hmacKey) != 32 {
		return fmt.Errorf("HMAC key must be 32 bytes (SHA-256), got %d bytes", len(hmacKey))
	}

	// HMAC data is: Format (1 byte) + JSON data
	hmacData := make([]byte, 0, 1+len(chunk.Data))
	hmacData = append(hmacData, chunk.Format)
	hmacData = append(hmacData, chunk.Data...)

	// Calculate HMAC-SHA256
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(hmacData)
	hmacResult := mac.Sum(nil)

	// Set HMAC in CHUNK
	chunk.HMAC = hmacResult
	chunk.HMACLen = uint16(len(hmacResult))

	return nil
}

// VerifyCHUNKHMAC verifies the HMAC-SHA256 for a CHUNK manifest record
func VerifyCHUNKHMAC(chunk *core.CHUNK, hmacKey []byte) (bool, error) {
	if chunk.Total != 0 {
		return false, fmt.Errorf("HMAC can only be verified for manifest chunks (Total=0), got Total=%d", chunk.Total)
	}

	if len(hmacKey) != 32 {
		return false, fmt.Errorf("HMAC key must be 32 bytes (SHA-256), got %d bytes", len(hmacKey))
	}

	if chunk.HMACLen == 0 || len(chunk.HMAC) == 0 {
		return false, fmt.Errorf("CHUNK HMAC is not set")
	}

	// HMAC data is: Format (1 byte) + JSON data
	hmacData := make([]byte, 0, 1+len(chunk.Data))
	hmacData = append(hmacData, chunk.Format)
	hmacData = append(hmacData, chunk.Data...)

	// Calculate expected HMAC
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(hmacData)
	expectedHMAC := mac.Sum(nil)

	// Compare HMACs (constant-time comparison)
	return hmac.Equal(chunk.HMAC, expectedHMAC), nil
}
