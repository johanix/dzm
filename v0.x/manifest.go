/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared manifest creation helper functions
 */

package dzm

import (
	"encoding/json"
	"time"
)

// CreateManifestMetadata creates base metadata for a distribution manifest
// extraFields can be used to add additional metadata fields
func CreateManifestMetadata(contentType, distributionID, nodeID string, extraFields map[string]interface{}) map[string]interface{} {
	metadata := map[string]interface{}{
		"content":         contentType,
		"distribution_id": distributionID,
		"node_id":         nodeID,
		"timestamp":       time.Now().Unix(), // Unix timestamp for replay protection
	}
	
	// Add any extra fields
	for k, v := range extraFields {
		metadata[k] = v
	}
	
	return metadata
}

// ShouldIncludePayloadInline determines if a payload should be included inline in the manifest
// Returns true if the payload fits within DNS message size limits
func ShouldIncludePayloadInline(payloadSize, estimatedTotalSize int) bool {
	const inlinePayloadThreshold = 500
	const maxTotalSize = 1200
	
	return payloadSize <= inlinePayloadThreshold && estimatedTotalSize < maxTotalSize
}

// EstimateManifestSize estimates the size of a CHUNK manifest with the given metadata and payload
// Uses a placeholder HMAC for size estimation
func EstimateManifestSize(metadata map[string]interface{}, payload []byte) int {
	// Create test manifest data
	testManifestData := &ManifestData{
		ChunkCount: 0,
		ChunkSize:  0,
		Metadata:   metadata,
		Payload:    payload,
	}
	
	// Marshal to JSON to get size
	manifestJSON, err := json.Marshal(testManifestData)
	if err != nil {
		// Fallback estimate if marshaling fails
		return 500
	}
	
	// CHUNK manifest size = Format (1) + HMACLen (2) + HMAC (32) + Sequence (2) + Total (2) + DataLength (2) + Data
	// Format: 1 byte
	// HMACLen: 2 bytes
	// HMAC: 32 bytes
	// Sequence: 2 bytes
	// Total: 2 bytes
	// DataLength: 2 bytes
	// Data: len(manifestJSON) bytes
	return 1 + 2 + 32 + 2 + 2 + 2 + len(manifestJSON)
}
