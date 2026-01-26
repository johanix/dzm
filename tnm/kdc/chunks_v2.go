/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Chunk preparation and retrieval for CHUNK queries (V2 - crypto abstraction)
 * This is the v2 implementation using the crypto abstraction layer.
 * The v1 implementation (chunks.go) remains unchanged for backward compatibility.
 */

package kdc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"

	"github.com/go-jose/go-jose/v4"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/crypto"

	tnm "github.com/johanix/tdns-nm/tnm"
)

// selectBackendForNode determines which crypto backend to use for a node
// based on the node's SupportedCrypto field.
// This is a convenience wrapper around tnm.SelectBackend that works with Node structs.
// forcedCrypto: if provided ("hpke" or "jose"), forces that backend (if node supports it)
// Returns the backend name (e.g., "hpke", "jose")
func selectBackendForNode(node *Node, forcedCrypto string) string {
	backendName := tnm.SelectBackend(node.SupportedCrypto, forcedCrypto)
	if forcedCrypto != "" && backendName != forcedCrypto {
		log.Printf("KDC: Warning: Node %s does not support forced crypto backend %s, auto-selected %s instead", node.ID, forcedCrypto, backendName)
	}
	return backendName
}

// prepareChunksForNodeV2 prepares chunks for a node's distribution event
// using the crypto abstraction layer to support both HPKE and JOSE.
// This is called on-demand when CHUNK is queried.
// The crypto backend is selected based on the node's SupportedCrypto field.
//
// TODO: Consider refactoring this function (~365 lines) by extracting helper functions
// for better readability and testability:
//   - buildKeyOperationsPayload() - handles key_operations, mgmt_operations, mixed_operations
//   - buildNodeOperationsPayload() - handles node_operations
//   - determineContentType() - analyzes operations to determine content type
//   - buildManifestMetadata() - creates manifest metadata with extra fields
//   - splitIntoChunks() - handles CHUNK splitting logic
//
// This would separate concerns: cache lookup, backend selection, content type determination,
// payload construction, encryption, manifest creation, and CHUNK splitting.
func (kdc *KdcDB) prepareChunksForNodeV2(
	nodeID, distributionID string,
	conf *tnm.KdcConf,
) (*preparedChunks, error) {
	cacheKey := fmt.Sprintf("%s:%s", nodeID, distributionID)

	// Check cache first (use same cache as v1 for now)
	globalChunkCache.mu.RLock()
	if cached, ok := globalChunkCache.cache[cacheKey]; ok {
		globalChunkCache.mu.RUnlock()
		log.Printf("KDC: Using cached chunks for node %s, distribution %s", nodeID, distributionID)
		return cached, nil
	}
	globalChunkCache.mu.RUnlock()

	// Not in cache, prepare chunks
	log.Printf("KDC: Preparing chunks (v2) for node %s, distribution %s", nodeID, distributionID)

	// Get the node to determine backend and access public key
	node, err := kdc.GetNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeID, err)
	}

	// Get all distribution records for this distributionID to check for stored crypto backend
	records, err := kdc.GetDistributionRecordsForDistributionID(distributionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get distribution records: %v", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no distribution records found for distribution %s (may have been purged after completion)", distributionID)
	}

	// Check if any record has a stored crypto backend in its payload (for ping operations)
	var forcedCrypto string
	for _, record := range records {
		if record.Payload != nil {
			if cryptoBackend, ok := record.Payload["crypto"].(string); ok && cryptoBackend != "" {
				forcedCrypto = cryptoBackend
				log.Printf("KDC: Found stored crypto backend %s in distribution record payload", cryptoBackend)
				break
			}
		}
	}

	// Select crypto backend - use stored one if available, otherwise auto-select
	backendName := selectBackendForNode(node, forcedCrypto)
	backend, err := crypto.GetBackend(backendName)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto backend %s: %v", backendName, err)
	}

	log.Printf("KDC: Using %s backend for node %s", backendName, nodeID)

	// Parse node's public key using the selected backend
	// For JOSE, we use LongTermJosePubKey; for HPKE, we use LongTermPubKey
	var nodePubKey crypto.PublicKey
	if backendName == "hpke" {
		// Defensive check: refuse HPKE operations for JOSE-only nodes
		if len(node.SupportedCrypto) == 1 && node.SupportedCrypto[0] == "jose" {
			return nil, fmt.Errorf("node %s only supports JOSE crypto backend, cannot use HPKE", nodeID)
		}
		if node.LongTermHpkePubKey == nil || len(node.LongTermHpkePubKey) != 32 {
			return nil, fmt.Errorf("node %s has invalid HPKE public key length: %d (expected 32)", nodeID, len(node.LongTermHpkePubKey))
		}
		nodePubKey, err = backend.ParsePublicKey(node.LongTermHpkePubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse node HPKE public key: %v", err)
		}
	} else if backendName == "jose" {
		if len(node.LongTermJosePubKey) == 0 {
			return nil, fmt.Errorf("node %s does not have a JOSE public key stored (required for JOSE backend)", nodeID)
		}
		nodePubKey, err = backend.ParsePublicKey(node.LongTermJosePubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse node JOSE public key: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported crypto backend: %s", backendName)
	}

	// Filter to records for this node (or all nodes if nodeID is empty)
	// Normalize node IDs for comparison (handle trailing dot differences)
	nodeIDNormalized := strings.TrimSuffix(nodeID, ".")
	var nodeRecords []*DistributionRecord
	for _, record := range records {
		recordNodeIDNormalized := strings.TrimSuffix(record.NodeID, ".")
		if recordNodeIDNormalized == nodeIDNormalized || record.NodeID == "" {
			nodeRecords = append(nodeRecords, record)
		}
	}

	if len(nodeRecords) == 0 {
		log.Printf("KDC: Distribution %s exists but has no records for node %s (found %d records for other nodes)", distributionID, nodeID, len(records))
		return nil, fmt.Errorf("no distribution records found for node %s, distribution %s (distribution exists but not for this node)", nodeID, distributionID)
	}

	// Determine content type by analyzing all operations in this distribution
	hasNodeOps := false // update_components
	hasKeyOps := false  // roll_key, delete_key
	hasMgmtOps := false // ping

	for _, record := range nodeRecords {
		switch record.Operation {
		case "update_components":
			hasNodeOps = true
		case "roll_key", "delete_key":
			hasKeyOps = true
		case "ping":
			hasMgmtOps = true
		}
	}

	// Determine contentType based on operation mix
	contentType := "key_operations" // default
	if hasNodeOps && !hasKeyOps && !hasMgmtOps {
		contentType = "node_operations"
	} else if !hasNodeOps && hasKeyOps && !hasMgmtOps {
		contentType = "key_operations"
	} else if !hasNodeOps && !hasKeyOps && hasMgmtOps {
		contentType = "mgmt_operations"
	} else if hasNodeOps || hasKeyOps || hasMgmtOps {
		contentType = "mixed_operations"
	}

	log.Printf("KDC: Distribution %s contains: node_ops=%v, key_ops=%v, mgmt_ops=%v -> contentType=%s",
		distributionID, hasNodeOps, hasKeyOps, hasMgmtOps, contentType)

	var base64Data []byte
	var zoneCount int
	var keyCount int
	var operationCount int

	if contentType == "node_operations" {
		// For node_operations, use the encrypted data directly from the distribution record
		// (Already encrypted with the intended component list)
		if len(nodeRecords) != 1 {
			return nil, fmt.Errorf("node_operations distribution should have exactly one record, got %d", len(nodeRecords))
		}

		record := nodeRecords[0]
		if record.Operation != "update_components" {
			return nil, fmt.Errorf("node_operations distribution has non-update_components operation: %s", record.Operation)
		}

		// The distribution record contains encrypted component list
		// For v2, this should already be encrypted with the correct backend
		// Just base64 encode for transport
		base64Data = []byte(base64.StdEncoding.EncodeToString(record.EncryptedKey))

		log.Printf("KDC: Using encrypted component list from distribution record: %d bytes -> base64 %d bytes",
			len(record.EncryptedKey), len(base64Data))

		zoneCount = 0
		keyCount = 0
	} else if contentType == "key_operations" || contentType == "mgmt_operations" || contentType == "mixed_operations" {
		// Prepare JSON structure with operation-based distribution entries
		entries := make([]tnm.DistributionEntry, 0, len(nodeRecords))
		zoneSet := make(map[string]bool)

		for _, record := range nodeRecords {
			entry := tnm.DistributionEntry{
				Operation: record.Operation,
				Metadata:  record.Payload,
			}

			switch record.Operation {
			case string(OperationRollKey):
				// Fetch key details from dnssec_keys table
				key, err := kdc.GetDNSSECKeyByID(record.ZoneName, record.KeyID)
				if err != nil {
					log.Printf("KDC: Warning: Failed to get key %s for zone %s: %v", record.KeyID, record.ZoneName, err)
					continue
				}

				// Populate entry with key details
				entry.ZoneName = record.ZoneName
				entry.KeyID = record.KeyID
				entry.KeyType = string(key.KeyType)
				entry.Algorithm = key.Algorithm
				entry.Flags = key.Flags
				entry.PublicKey = key.PublicKey
				entry.PrivateKey = base64.StdEncoding.EncodeToString(key.PrivateKey)

				zoneSet[record.ZoneName] = true

			case string(OperationPing):
				// Ping operation - metadata already contains nonce and timestamp
				// No additional fields needed

			case string(OperationDeleteKey):
				// Delete key operation
				entry.ZoneName = record.ZoneName
				entry.KeyID = record.KeyID
				zoneSet[record.ZoneName] = true

			default:
				log.Printf("KDC: Warning: Unknown operation type %q in distribution %s", record.Operation, distributionID)
				continue
			}

			entries = append(entries, entry)
		}

		operationCount = len(entries)
		keyCount = 0
		for _, entry := range entries {
			if entry.Operation == "roll_key" || entry.Operation == "delete_key" {
				keyCount++
			}
		}
		zoneCount = len(zoneSet)

		if operationCount == 0 {
			return nil, fmt.Errorf("no valid operations found for node %s, distribution %s", nodeID, distributionID)
		}

		// Marshal to JSON (cleartext)
		entriesJSON, err := json.Marshal(entries)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal entries JSON: %v", err)
		}

		// Debug logging: log cleartext content (masking private keys)
		if tdns.Globals.Debug {
			// Create a copy for logging with masked private keys
			logEntries := make([]map[string]interface{}, len(entries))
			for i, entry := range entries {
				logEntry := map[string]interface{}{
					"operation": entry.Operation,
					"zone_name": entry.ZoneName,
					"key_id":    entry.KeyID,
				}
				if entry.Operation == string(OperationRollKey) {
					logEntry["key_type"] = entry.KeyType
					logEntry["algorithm"] = entry.Algorithm
					logEntry["flags"] = entry.Flags
					logEntry["public_key"] = entry.PublicKey
					logEntry["private_key"] = "***MASKED***"
				}
				if entry.Metadata != nil {
					logEntry["metadata"] = entry.Metadata
				}
				logEntries[i] = logEntry
			}
			logJSON, _ := json.Marshal(logEntries)
			log.Printf("KDC: DEBUG: Cleartext distribution payload (private keys masked): %s", string(logJSON))
		}

		log.Printf("KDC: Prepared %s: %d operations (%d key ops) for %d zones, JSON size: %d bytes",
			contentType, operationCount, keyCount, zoneCount, len(entriesJSON))

		// Encrypt the entire JSON payload using the selected backend
		ciphertext, err := backend.Encrypt(nodePubKey, entriesJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt distribution payload with %s backend: %v", backendName, err)
		}

		// Base64 encode for transport
		base64Data = []byte(base64.StdEncoding.EncodeToString(ciphertext))
		log.Printf("KDC: Encrypted distribution payload with %s: cleartext %d bytes -> ciphertext %d bytes -> base64 %d bytes",
			backendName, len(entriesJSON), len(ciphertext), len(base64Data))
	} else {
		return nil, fmt.Errorf("invalid or unsupported content type: %s for distribution %s", contentType, distributionID)
	}

	// Calculate checksum
	hash := sha256.Sum256([]byte(base64Data))
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Create manifest metadata with crypto field
	extraFields := make(map[string]interface{})
	if contentType == "key_operations" || contentType == "mgmt_operations" || contentType == "mixed_operations" {
		extraFields["zone_count"] = zoneCount
		extraFields["key_count"] = keyCount
		extraFields["operation_count"] = operationCount
	} else if contentType == "node_operations" {
		// Get component count from stored distribution component list
		_, intendedComponents, err := kdc.GetDistributionComponentList(distributionID)
		if err == nil {
			extraFields["component_count"] = len(intendedComponents)
			log.Printf("KDC: Set component_count in metadata to %d (from stored distribution component list)", len(intendedComponents))
		} else {
			log.Printf("KDC: Warning: Failed to get component list for distribution %s to set metadata: %v", distributionID, err)
		}
	}
	// Add retire_time from config if available
	if conf != nil && conf.RetireTime > 0 {
		extraFields["retire_time"] = conf.RetireTime.String()
	}
	// Add distribution_ttl from config if available (for KRS validation)
	if conf != nil && conf.GetDistributionTTL() > 0 {
		extraFields["distribution_ttl"] = conf.GetDistributionTTL().String()
	}

	// NEW: Add crypto backend to metadata
	extraFields["crypto"] = backendName

	metadata := tnm.CreateManifestMetadata(contentType, distributionID, nodeID, extraFields)

	// Determine if payload should be included inline
	payloadSize := len(base64Data)
	testSize := tnm.EstimateManifestSize(metadata, base64Data)

	// Check if the manifest fits in DNS message
	const estimatedDNSOverhead = 150
	estimatedTotalSize := estimatedDNSOverhead + testSize
	includeInline := tnm.ShouldIncludePayloadInline(payloadSize, estimatedTotalSize)

	var dataChunks []*core.CHUNK
	var chunkCount uint16
	var chunkSize uint16

	if includeInline {
		chunkCount = 0
		chunkSize = 0
		log.Printf("KDC: Payload size %d bytes (base64), manifest size %d bytes, estimated total %d bytes - including inline in CHUNK manifest",
			payloadSize, testSize, estimatedTotalSize)
	} else {
		// Use default chunk size if conf is nil
		const defaultChunkSize = 60000
		var chunkSizeInt int
		if conf != nil {
			chunkSizeInt = conf.GetChunkMaxSize()
		} else {
			chunkSizeInt = defaultChunkSize
		}
		dataChunks = tnm.SplitIntoCHUNKs([]byte(base64Data), chunkSizeInt, core.FormatJSON)
		// Check for integer overflow before converting to uint16
		if len(dataChunks) > math.MaxUint16 {
			return nil, fmt.Errorf("too many chunks: %d (max: %d)", len(dataChunks), math.MaxUint16)
		}
		if chunkSizeInt > math.MaxUint16 {
			return nil, fmt.Errorf("chunk size too large: %d (max: %d)", chunkSizeInt, math.MaxUint16)
		}
		chunkCount = uint16(len(dataChunks))
		chunkSize = uint16(chunkSizeInt)
		log.Printf("KDC: Payload size %d bytes (base64), manifest size %d bytes, estimated total %d bytes - exceeds inline threshold, splitting into %d chunks",
			payloadSize, testSize, estimatedTotalSize, chunkCount)
	}

	// Create manifest data
	manifestData := &tnm.ManifestData{
		ChunkCount: chunkCount,
		ChunkSize:  chunkSize,
		Metadata:   metadata,
	}

	// Include payload inline if it fits
	if includeInline {
		manifestData.Payload = make([]byte, len(base64Data))
		copy(manifestData.Payload, base64Data)
	}

	// Create manifest CHUNK (Total=0)
	manifestCHUNK, err := tnm.CreateCHUNKManifest(manifestData, core.FormatJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create CHUNK manifest: %v", err)
	}

	// Calculate HMAC using the recipient node's long-term public key
	// Select the appropriate key based on the crypto backend used for encryption
	var hmacKey []byte
	if backendName == "hpke" {
		// For HPKE, use the X25519 public key directly (32 bytes)
		if node.LongTermHpkePubKey == nil || len(node.LongTermHpkePubKey) != 32 {
			return nil, fmt.Errorf("node %s has invalid HPKE public key for HMAC: length %d (expected 32)", nodeID, len(node.LongTermHpkePubKey))
		}
		hmacKey = node.LongTermHpkePubKey
	} else if backendName == "jose" {
		// For JOSE, extract the x-coordinate from the ECDSA P-256 public key (32 bytes)
		if len(node.LongTermJosePubKey) == 0 {
			return nil, fmt.Errorf("node %s does not have a JOSE public key stored (required for HMAC)", nodeID)
		}
		// Parse JWK to extract ECDSA public key
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(node.LongTermJosePubKey, &jwk); err != nil {
			return nil, fmt.Errorf("failed to parse node JOSE public key for HMAC: %v", err)
		}
		ecdsaKey, ok := jwk.Key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("node %s JOSE public key is not an ECDSA key (required for HMAC)", nodeID)
		}
		// Validate curve is P-256 (required for this backend)
		if ecdsaKey.Curve != elliptic.P256() {
			return nil, fmt.Errorf("node %s JOSE public key uses unsupported curve: %s (expected P-256)", nodeID, ecdsaKey.Curve.Params().Name)
		}
		// Extract x-coordinate (32 bytes for P-256)
		xBytes := ecdsaKey.X.Bytes()
		// Calculate expected coordinate length for P-256: (256 bits + 7) / 8 = 32 bytes
		expectedLen := (ecdsaKey.Curve.Params().BitSize + 7) / 8
		if len(xBytes) > expectedLen {
			return nil, fmt.Errorf("node %s JOSE public key x-coordinate too large: %d bytes (max: %d for P-256)", nodeID, len(xBytes), expectedLen)
		}
		// Pad to expectedLen bytes if needed (ECDSA coordinates are variable length)
		hmacKey = make([]byte, expectedLen)
		copy(hmacKey[expectedLen-len(xBytes):], xBytes)
	} else {
		return nil, fmt.Errorf("unsupported crypto backend for HMAC: %s", backendName)
	}
	if err := tnm.CalculateCHUNKHMAC(manifestCHUNK, hmacKey); err != nil {
		return nil, fmt.Errorf("failed to calculate HMAC: %v", err)
	}
	log.Printf("KDC: Calculated HMAC for CHUNK manifest using node %s %s public key (%d bytes)", nodeID, backendName, len(hmacKey))

	// Create CHUNK records (manifest + data chunks)
	allChunks := make([]*core.CHUNK, 0)
	allChunks = append(allChunks, manifestCHUNK)
	allChunks = append(allChunks, dataChunks...)

	prepared := &preparedChunks{
		chunks:    allChunks,
		checksum:  checksum,
		timestamp: 0,
	}

	// Cache it
	globalChunkCache.mu.Lock()
	globalChunkCache.cache[cacheKey] = prepared
	globalChunkCache.mu.Unlock()

	log.Printf("KDC: Prepared %d CHUNK records for node %s, distribution %s using %s backend",
		len(allChunks), nodeID, distributionID, backendName)
	return prepared, nil
}
