/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared CHUNK format marshaling/unmarshaling functions
 */

package dzm

import (
	"encoding/json"
	"fmt"

	"github.com/johanix/tdns/v0.x/tdns/core"
)

// MarshalManifestToCHUNK marshals a MANIFEST into JSON format for CHUNK record
func MarshalManifestToCHUNK(manifest *core.MANIFEST) ([]byte, error) {
	jsonFields := struct {
		ChunkCount uint16                 `json:"chunk_count"`
		ChunkSize  uint16                 `json:"chunk_size,omitempty"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
		Payload    []byte                 `json:"payload,omitempty"`
	}{
		ChunkCount: manifest.ChunkCount,
		ChunkSize:  manifest.ChunkSize,
		Metadata:   manifest.Metadata,
		Payload:    manifest.Payload,
	}
	
	manifestJSON, err := json.Marshal(jsonFields)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest JSON for CHUNK: %v", err)
	}
	
	return manifestJSON, nil
}

// UnmarshalManifestFromCHUNK unmarshals MANIFEST data from a CHUNK record
func UnmarshalManifestFromCHUNK(chunk *core.CHUNK) (*core.MANIFEST, error) {
	if chunk.Total != 0 {
		return nil, fmt.Errorf("CHUNK is not a manifest chunk (Total=%d, expected 0)", chunk.Total)
	}

	if chunk.Format != core.FormatJSON {
		return nil, fmt.Errorf("unsupported CHUNK format: %d (expected FormatJSON=%d)", chunk.Format, core.FormatJSON)
	}

	// Parse JSON data from CHUNK
	var manifestData struct {
		ChunkCount uint16                 `json:"chunk_count"`
		ChunkSize  uint16                 `json:"chunk_size,omitempty"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
		Payload    []byte                 `json:"payload,omitempty"`
	}

	if err := json.Unmarshal(chunk.Data, &manifestData); err != nil {
		return nil, fmt.Errorf("failed to parse CHUNK manifest JSON: %v", err)
	}

	// Convert to MANIFEST structure for compatibility with existing code
	manifest := &core.MANIFEST{
		Format:     chunk.Format,
		HMAC:       chunk.HMAC,
		ChunkCount: manifestData.ChunkCount,
		ChunkSize:  manifestData.ChunkSize,
		Metadata:   manifestData.Metadata,
		Payload:    manifestData.Payload,
	}

	return manifest, nil
}

// CreateCHUNKFromManifest creates a CHUNK record from a MANIFEST
func CreateCHUNKFromManifest(manifest *core.MANIFEST) (*core.CHUNK, error) {
	manifestJSON, err := MarshalManifestToCHUNK(manifest)
	if err != nil {
		return nil, err
	}
	
	manifestCHUNK := &core.CHUNK{
		Format:     manifest.Format,
		HMACLen:    uint16(len(manifest.HMAC)),
		HMAC:       manifest.HMAC,
		Sequence:   0, // Unused for manifest
		Total:      0, // 0 indicates manifest
		DataLength: uint16(len(manifestJSON)),
		Data:       manifestJSON,
	}
	
	return manifestCHUNK, nil
}
