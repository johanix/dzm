/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared manifest creation helper functions
 */

package dzm

import (
	"time"

	"github.com/johanix/tdns/v0.x/tdns/core"
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

// EstimateManifestSize estimates the size of a manifest with the given metadata and payload
// Uses a placeholder HMAC for size estimation
func EstimateManifestSize(metadata map[string]interface{}, payload []byte) int {
	testHMAC := make([]byte, 32) // HMAC-SHA256 is 32 bytes
	testManifest := &core.MANIFEST{
		Format:     core.FormatJSON,
		ChunkCount: 0,
		ChunkSize:  0,
		HMAC:       testHMAC,
		Metadata:   metadata,
		Payload:    payload,
	}
	return testManifest.Len()
}
