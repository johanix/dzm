/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Chunk preparation and retrieval for CHUNK queries
 */

package kdc

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/johanix/tdns/v0.x/tdns/hpke"

	dzm "github.com/johanix/dzm/v0.x"
)

// chunkCache stores prepared chunks in memory (keyed by nodeID+distributionID)
type chunkCache struct {
	mu    sync.RWMutex
	cache map[string]*preparedChunks
}

type preparedChunks struct {
	chunks []*core.CHUNK // CHUNK records (manifest + data chunks)
	checksum  string
	timestamp int64
}

var globalChunkCache = &chunkCache{
	cache: make(map[string]*preparedChunks),
}

// prepareChunksForNode prepares chunks for a node's distribution event
// This is called on-demand when CHUNK is queried
func (kdc *KdcDB) prepareChunksForNode(nodeID, distributionID string, conf *KdcConf) (*preparedChunks, error) {
	cacheKey := fmt.Sprintf("%s:%s", nodeID, distributionID)

	// Check cache first
	globalChunkCache.mu.RLock()
	if cached, ok := globalChunkCache.cache[cacheKey]; ok {
		globalChunkCache.mu.RUnlock()
		log.Printf("KDC: Using cached chunks for node %s, distribution %s", nodeID, distributionID)
		return cached, nil
	}
	globalChunkCache.mu.RUnlock()

	// Not in cache, prepare chunks
	log.Printf("KDC: Preparing chunks for node %s, distribution %s", nodeID, distributionID)

	// Get the node to access its long-term public key for HMAC
	node, err := kdc.GetNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeID, err)
	}
	if len(node.LongTermPubKey) != 32 {
		return nil, fmt.Errorf("node %s has invalid public key length: %d (expected 32)", nodeID, len(node.LongTermPubKey))
	}

	// Get all distribution records for this distributionID
	records, err := kdc.GetDistributionRecordsForDistributionID(distributionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get distribution records: %v", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no distribution records found for distribution %s (may have been purged after completion)", distributionID)
	}

	// Filter to records for this node (or all nodes if nodeID is empty)
	var nodeRecords []*DistributionRecord
	for _, record := range records {
		if record.NodeID == nodeID || record.NodeID == "" {
			nodeRecords = append(nodeRecords, record)
		}
	}

	if len(nodeRecords) == 0 {
		log.Printf("KDC: Distribution %s exists but has no records for node %s (found %d records for other nodes)", distributionID, nodeID, len(records))
		return nil, fmt.Errorf("no distribution records found for node %s, distribution %s (distribution exists but not for this node)", nodeID, distributionID)
	}

	// Determine content type based on distribution records
	// Check if this is a node_components distribution (zone_name and key_id are NULL)
	// Otherwise, use "encrypted_keys" for key distributions
	contentType := "encrypted_keys"
	if len(nodeRecords) > 0 && nodeRecords[0].ZoneName == "" && nodeRecords[0].KeyID == "" {
		contentType = "node_components"
	}
	
	var base64Data []byte
	var zoneCount int
	var keyCount int

	if contentType == "node_components" {
		// For node_components distributions, use the encrypted data directly from the distribution record
		// The distribution record already contains the correct encrypted component list
		// (created with the intended component list, not the current DB state)
		if len(nodeRecords) != 1 {
			return nil, fmt.Errorf("node_components distribution should have exactly one record, got %d", len(nodeRecords))
		}
		
		record := nodeRecords[0]
		
		// The distribution record already contains the encrypted component list
		// Format stored: <ephemeral_pub_key (32 bytes)><ciphertext>
		// We just need to combine them and base64 encode
		if len(record.EphemeralPubKey) != 32 {
			return nil, fmt.Errorf("invalid ephemeral public key length: %d (expected 32)", len(record.EphemeralPubKey))
		}
		
		// Combine ephemeral public key and ciphertext for transport
		// Format: <ephemeral_pub_key (32 bytes)><ciphertext>
		encryptedData := append(record.EphemeralPubKey, record.EncryptedKey...)
		
		// Base64 encode the encrypted data
		base64Data = []byte(base64.StdEncoding.EncodeToString(encryptedData))
		
		log.Printf("KDC: Using encrypted component list from distribution record: encrypted %d bytes -> base64 %d bytes", 
			len(encryptedData), len(base64Data))
		
		zoneCount = 0 // node_components doesn't have zones
		keyCount = 0  // node_components doesn't have keys
	} else if contentType == "encrypted_keys" {
		// Prepare JSON structure with all key data (including private keys in cleartext)
		// The entire JSON will be encrypted using HPKE
		type KeyEntry struct {
			ZoneName   string `json:"zone_name"`
			KeyID      string `json:"key_id"`
			KeyType    string `json:"key_type,omitempty"`
			Algorithm  uint8  `json:"algorithm,omitempty"`
			Flags      uint16 `json:"flags,omitempty"`
			PublicKey  string `json:"public_key,omitempty"`
			PrivateKey string `json:"private_key"` // Private key in cleartext (will be encrypted as part of entire payload)
		}

		entries := make([]KeyEntry, 0, len(nodeRecords))
		zoneSet := make(map[string]bool)
		
		for _, record := range nodeRecords {
			// Get the key details to include key_id and private key
			key, err := kdc.GetDNSSECKeyByID(record.ZoneName, record.KeyID)
			if err != nil {
				log.Printf("KDC: Warning: Failed to get key %s for zone %s: %v", record.KeyID, record.ZoneName, err)
				continue
			}

			// Decrypt the private key from the distribution record to get cleartext
			// The record.EncryptedKey was encrypted using HPKE, we need to decrypt it
			// But wait - we don't have the node's private key here. We need to get the cleartext private key
			// from the DNSSECKey structure instead.
			entry := KeyEntry{
				ZoneName:  record.ZoneName,
				KeyID:     record.KeyID,
				KeyType:   string(key.KeyType),
				Algorithm: key.Algorithm,
				Flags:     key.Flags,
				PublicKey: key.PublicKey,
				PrivateKey: base64.StdEncoding.EncodeToString(key.PrivateKey), // Base64-encode private key bytes
			}
			entries = append(entries, entry)
			zoneSet[record.ZoneName] = true
		}

		keyCount = len(entries)
		zoneCount = len(zoneSet)

		if keyCount == 0 {
			return nil, fmt.Errorf("no valid keys found for node %s, distribution %s", nodeID, distributionID)
		}

		// Marshal to JSON (cleartext)
		keysJSON, err := json.Marshal(entries)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal keys JSON: %v", err)
		}

		// Debug logging: log cleartext content (masking private keys)
		if tdns.Globals.Debug {
			// Create a copy for logging with masked private keys
			logEntries := make([]map[string]interface{}, len(entries))
			for i, entry := range entries {
				logEntries[i] = map[string]interface{}{
					"zone_name":   entry.ZoneName,
					"key_id":      entry.KeyID,
					"key_type":    entry.KeyType,
					"algorithm":   entry.Algorithm,
					"flags":       entry.Flags,
					"public_key":  entry.PublicKey,
					"private_key": "***MASKED***",
				}
			}
			logJSON, _ := json.Marshal(logEntries)
			log.Printf("KDC: DEBUG: Cleartext distribution payload (private keys masked): %s", string(logJSON))
		}

		log.Printf("KDC: Prepared keys JSON: %d keys for %d zones, JSON size: %d bytes", 
			keyCount, zoneCount, len(keysJSON))

		// Encrypt the entire JSON payload using HPKE and encode for transport
		base64Data, err = dzm.EncryptAndEncode(node.LongTermPubKey, keysJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt distribution payload: %v", err)
		}
		log.Printf("KDC: Encrypted distribution payload: cleartext %d bytes -> base64 %d bytes", 
			len(keysJSON), len(base64Data))
	} else {
		// "zonelist" mode (fallback)
		// Collect zone names from distribution records
		zoneSet := make(map[string]bool)
		for _, record := range nodeRecords {
			zoneSet[record.ZoneName] = true
		}

		zones := make([]string, 0, len(zoneSet))
		for zone := range zoneSet {
			zones = append(zones, zone)
		}

		zoneCount = len(zones)

		// Prepare JSON data: zone list
		zoneListJSON, err := json.Marshal(zones)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal zone list: %v", err)
		}

		// Base64 encode
		base64Data = []byte(base64.StdEncoding.EncodeToString(zoneListJSON))
	}

	// Calculate checksum
	hash := sha256.Sum256([]byte(base64Data))
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Create manifest metadata
	extraFields := make(map[string]interface{})
	if contentType == "encrypted_keys" {
		extraFields["zone_count"] = zoneCount
		extraFields["key_count"] = keyCount
	} else if contentType == "node_components" {
		// Get component count from the stored component list for this distribution
		// This ensures the metadata matches the actual payload (which comes from the distribution record)
		_, intendedComponents, err := kdc.GetDistributionComponentList(distributionID)
		if err == nil {
			extraFields["component_count"] = len(intendedComponents)
			log.Printf("KDC: Set component_count in metadata to %d (from stored distribution component list)", len(intendedComponents))
		} else {
			// Fallback: if we can't get the stored list, log a warning but don't fail
			log.Printf("KDC: Warning: Failed to get component list for distribution %s to set metadata: %v", distributionID, err)
			// Don't set component_count if we can't get the correct value
		}
	}
	// Add retire_time from config if available
	if conf != nil && conf.RetireTime > 0 {
		extraFields["retire_time"] = conf.RetireTime.String() // Convert duration to string (e.g., "168h0m0s")
	}
	// Add distribution_ttl from config if available (for KRS validation)
	if conf != nil && conf.GetDistributionTTL() > 0 {
		extraFields["distribution_ttl"] = conf.GetDistributionTTL().String() // Convert duration to string (e.g., "5m0s")
	}
	metadata := dzm.CreateManifestMetadata(contentType, distributionID, nodeID, extraFields)

	// Determine if payload should be included inline
	payloadSize := len(base64Data)
	testSize := dzm.EstimateManifestSize(metadata, base64Data)
	
	// Check if the manifest fits in DNS message (accounting for headers and QNAME)
	// Estimate: DNS headers (~12) + QNAME (~100) + RR header (~10) + manifest data
	const estimatedDNSOverhead = 150
	estimatedTotalSize := estimatedDNSOverhead + testSize
	includeInline := dzm.ShouldIncludePayloadInline(payloadSize, estimatedTotalSize)

	var dataChunks []*core.CHUNK
	var chunkCount uint16
	var chunkSize uint16

	if includeInline {
		// Payload fits inline, include it directly in manifest
		chunkCount = 0
		chunkSize = 0
		log.Printf("KDC: Payload size %d bytes (base64), manifest size %d bytes, estimated total %d bytes - including inline in CHUNK manifest", 
			payloadSize, testSize, estimatedTotalSize)
	} else {
		// Payload is too large, split into chunks
		chunkSizeInt := conf.GetChunkMaxSize()
		dataChunks = dzm.SplitIntoCHUNKs([]byte(base64Data), chunkSizeInt, core.FormatJSON)
		chunkCount = uint16(len(dataChunks))
		chunkSize = uint16(chunkSizeInt)
		log.Printf("KDC: Payload size %d bytes (base64), manifest size %d bytes, estimated total %d bytes - exceeds inline threshold, splitting into %d chunks", 
			payloadSize, testSize, estimatedTotalSize, chunkCount)
	}

	// Create manifest data
	manifestData := &dzm.ManifestData{
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
	manifestCHUNK, err := dzm.CreateCHUNKManifest(manifestData, core.FormatJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create CHUNK manifest: %v", err)
	}

	// Calculate HMAC using the recipient node's long-term public key
	// This ensures each distribution is authenticated for the specific recipient node
	if err := dzm.CalculateCHUNKHMAC(manifestCHUNK, node.LongTermPubKey); err != nil {
		return nil, fmt.Errorf("failed to calculate HMAC: %v", err)
	}
	log.Printf("KDC: Calculated HMAC for CHUNK manifest using node %s public key (%d bytes)", nodeID, len(manifestCHUNK.HMAC))

	// Create CHUNK records (manifest + data chunks)
	allChunks := make([]*core.CHUNK, 0)
	allChunks = append(allChunks, manifestCHUNK)
	allChunks = append(allChunks, dataChunks...)

	prepared := &preparedChunks{
		chunks:    allChunks,
		checksum:  checksum,
		timestamp: 0, // TODO: add timestamp
	}

	// Cache it
	globalChunkCache.mu.Lock()
	globalChunkCache.cache[cacheKey] = prepared
	globalChunkCache.mu.Unlock()

	log.Printf("KDC: Prepared %d CHUNK records for node %s, distribution %s", 
		len(allChunks), nodeID, distributionID)
	return prepared, nil
}



// GetCHUNKForNode retrieves a CHUNK record for a node's distribution event
// chunkID 0 returns the manifest CHUNK (Total=0), chunkID > 0 returns data CHUNK (Total>0)
func (kdc *KdcDB) GetCHUNKForNode(nodeID, distributionID string, chunkID uint16, conf *KdcConf) (*core.CHUNK, error) {
	prepared, err := kdc.prepareChunksForNode(nodeID, distributionID, conf)
	if err != nil {
		return nil, err
	}

	if int(chunkID) >= len(prepared.chunks) {
		return nil, fmt.Errorf("CHUNK ID %d out of range (max %d)", chunkID, len(prepared.chunks)-1)
	}

	return prepared.chunks[chunkID], nil
}

// GetDistributionRecordsForDistributionID gets all distribution records for a distribution ID
func (kdc *KdcDB) GetDistributionRecordsForDistributionID(distributionID string) ([]*DistributionRecord, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key, 
			created_at, expires_at, status, distribution_id, completed_at
			FROM distribution_records 
			WHERE distribution_id = ? 
			ORDER BY created_at DESC`,
		distributionID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution records: %v", err)
	}
	defer rows.Close()

	var records []*DistributionRecord
	for rows.Next() {
		record := &DistributionRecord{}
		var zoneName sql.NullString
		var keyID sql.NullString
		var nodeID sql.NullString
		var expiresAt sql.NullTime
		var completedAt sql.NullTime
		var statusStr string
		if err := rows.Scan(
			&record.ID, &zoneName, &keyID, &nodeID,
			&record.EncryptedKey, &record.EphemeralPubKey, &record.CreatedAt,
			&expiresAt, &statusStr, &record.DistributionID, &completedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan distribution record: %v", err)
		}
		if zoneName.Valid {
			record.ZoneName = zoneName.String
		}
		if keyID.Valid {
			record.KeyID = keyID.String
		}
		if nodeID.Valid {
			record.NodeID = nodeID.String
		}
		if expiresAt.Valid {
			record.ExpiresAt = &expiresAt.Time
		}
		if completedAt.Valid {
			record.CompletedAt = &completedAt.Time
		}
		record.Status = hpke.DistributionStatus(statusStr)
		records = append(records, record)
	}
	return records, rows.Err()
}

// DistributionInfo contains distribution ID and the nodes it applies to
type DistributionInfo struct {
	DistributionID string   `json:"distribution_id"`
	Nodes          []string `json:"nodes"`
}

// GetAllDistributionIDs returns all unique distribution IDs from distribution_records and cache
func (kdc *KdcDB) GetAllDistributionIDs() ([]string, error) {
	infos, err := kdc.GetAllDistributionInfos()
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(infos))
	for i, info := range infos {
		ids[i] = info.DistributionID
	}
	return ids, nil
}

// GetAllDistributionInfos returns all distribution IDs with their associated nodes
func (kdc *KdcDB) GetAllDistributionInfos() ([]DistributionInfo, error) {
	// Get distribution IDs and nodes from database
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT distribution_id, node_id FROM distribution_records ORDER BY distribution_id, node_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution IDs: %v", err)
	}
	defer rows.Close()

	distributionMap := make(map[string]map[string]bool) // distID -> set of nodeIDs
	for rows.Next() {
		var distID string
		var nodeID sql.NullString
		if err := rows.Scan(&distID, &nodeID); err != nil {
			return nil, fmt.Errorf("failed to scan distribution ID: %v", err)
		}
		if distributionMap[distID] == nil {
			distributionMap[distID] = make(map[string]bool)
		}
		if nodeID.Valid && nodeID.String != "" {
			distributionMap[distID][nodeID.String] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Also get distribution IDs from cache (for test distributions)
	globalChunkCache.mu.RLock()
	for cacheKey := range globalChunkCache.cache {
		// Cache key format: "nodeID:distributionID"
		parts := strings.Split(cacheKey, ":")
		if len(parts) == 2 {
			nodeID := parts[0]
			distID := parts[1]
			// Skip if distribution ID is empty
			if distID == "" {
				log.Printf("KDC: Warning: found cache entry with empty distribution ID: %s", cacheKey)
				continue
			}
			if distributionMap[distID] == nil {
				distributionMap[distID] = make(map[string]bool)
			}
			distributionMap[distID][nodeID] = true
		} else {
			log.Printf("KDC: Warning: invalid cache key format (expected 'nodeID:distributionID'): %s", cacheKey)
		}
	}
	globalChunkCache.mu.RUnlock()

	// Convert map to sorted slice
	distributionIDs := make([]string, 0, len(distributionMap))
	for distID := range distributionMap {
		distributionIDs = append(distributionIDs, distID)
	}
	sort.Strings(distributionIDs)

	infos := make([]DistributionInfo, 0, len(distributionIDs))
	for _, distID := range distributionIDs {
		// Skip empty distribution IDs
		if distID == "" {
			log.Printf("KDC: Warning: skipping empty distribution ID")
			continue
		}
		nodeSet := distributionMap[distID]
		nodes := make([]string, 0, len(nodeSet))
		for nodeID := range nodeSet {
			nodes = append(nodes, nodeID)
		}
		sort.Strings(nodes)
		infos = append(infos, DistributionInfo{
			DistributionID: distID,
			Nodes:          nodes,
		})
	}
	return infos, nil
}

// DeleteDistribution deletes all distribution records for a given distribution ID
func (kdc *KdcDB) DeleteDistribution(distributionID string) error {
	_, err := kdc.DB.Exec(
		`DELETE FROM distribution_records WHERE distribution_id = ?`,
		distributionID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete distribution records: %v", err)
	}
	return nil
}

// ClearDistributionCache clears the chunk cache for a distribution
func ClearDistributionCache(distributionID string) {
	globalChunkCache.mu.Lock()
	defer globalChunkCache.mu.Unlock()
	
	// Remove all cache entries matching this distribution ID
	for key := range globalChunkCache.cache {
		if strings.HasSuffix(key, ":"+distributionID) {
			delete(globalChunkCache.cache, key)
		}
	}
}

// PrepareTextChunks prepares chunks for a text distribution (clear_text or encrypted_text)
// This creates a persistent distribution record that can be queried by KRS
// contentType should be "clear_text" or "encrypted_text"
func (kdc *KdcDB) PrepareTextChunks(nodeID, distributionID, text string, contentType string, conf *KdcConf) (*preparedChunks, error) {
	cacheKey := fmt.Sprintf("%s:%s", nodeID, distributionID)

	// Check cache first
	globalChunkCache.mu.RLock()
	if cached, ok := globalChunkCache.cache[cacheKey]; ok {
		globalChunkCache.mu.RUnlock()
		log.Printf("KDC: Using cached %s chunks for node %s, distribution %s", contentType, nodeID, distributionID)
		return cached, nil
	}
	globalChunkCache.mu.RUnlock()

	// Not in cache, prepare chunks
	log.Printf("KDC: Preparing %s chunks for node %s, distribution %s", contentType, nodeID, distributionID)

	// Get the node to access its long-term public key for HMAC
	node, err := kdc.GetNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeID, err)
	}
	if len(node.LongTermPubKey) != 32 {
		return nil, fmt.Errorf("node %s has invalid public key length: %d (expected 32)", nodeID, len(node.LongTermPubKey))
	}

	var dataToChunk []byte
	// var err error

	if contentType == "encrypted_text" {
		// Encrypt the text using HPKE and encode for transport
		dataToChunk, err = dzm.EncryptAndEncode(node.LongTermPubKey, []byte(text))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt text: %v", err)
		}
		log.Printf("KDC: Encrypted text (%d bytes) -> base64 (%d bytes)", len(text), len(dataToChunk))
	} else {
		// clear_text: just base64 encode the text
		dataToChunk = []byte(base64.StdEncoding.EncodeToString([]byte(text)))
	}

	// Calculate checksum
	hash := sha256.Sum256(dataToChunk)
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Determine if payload should be included inline
	payloadSize := len(dataToChunk)
	testMetadata := map[string]interface{}{
		"content":         contentType,
		"distribution_id": distributionID,
		"node_id":         nodeID,
		"text_length":     len(text),
	}
	testSize := dzm.EstimateManifestSize(testMetadata, dataToChunk)
	
	// Check if the manifest fits in DNS message
	const estimatedDNSOverhead = 150
	estimatedTotalSize := estimatedDNSOverhead + testSize
	includeInline := dzm.ShouldIncludePayloadInline(payloadSize, estimatedTotalSize)

	var dataChunks []*core.CHUNK
	var chunkCount uint16
	var chunkSize uint16

	if includeInline {
		// Payload fits inline, include it directly in manifest
		chunkCount = 0
		chunkSize = 0
		log.Printf("KDC: Test text payload size %d bytes, manifest size %d bytes, estimated total %d bytes - including inline in CHUNK manifest", 
			payloadSize, testSize, estimatedTotalSize)
	} else {
		// Payload is too large, split into chunks
		chunkSizeInt := conf.GetChunkMaxSize()
		dataChunks = dzm.SplitIntoCHUNKs(dataToChunk, chunkSizeInt, core.FormatJSON)
		chunkCount = uint16(len(dataChunks))
		chunkSize = uint16(chunkSizeInt)
		log.Printf("KDC: Test text payload size %d bytes, manifest size %d bytes, estimated total %d bytes - exceeds inline threshold, splitting into %d chunks", 
			payloadSize, testSize, estimatedTotalSize, chunkCount)
	}

	// Create manifest data
	extraFields := map[string]interface{}{
		"text_length": len(text),
	}
	metadata := dzm.CreateManifestMetadata(contentType, distributionID, nodeID, extraFields)
	manifestData := &dzm.ManifestData{
		ChunkCount: chunkCount,
		ChunkSize:  chunkSize,
		Metadata:   metadata,
	}

	// Include payload inline if it fits
	if includeInline {
		manifestData.Payload = make([]byte, len(dataToChunk))
		copy(manifestData.Payload, dataToChunk)
	}

	// Create manifest CHUNK (Total=0)
	manifestCHUNK, err := dzm.CreateCHUNKManifest(manifestData, core.FormatJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create CHUNK manifest: %v", err)
	}

	// Calculate HMAC using the recipient node's long-term public key
	// This ensures each distribution is authenticated for the specific recipient node
	if err := dzm.CalculateCHUNKHMAC(manifestCHUNK, node.LongTermPubKey); err != nil {
		return nil, fmt.Errorf("failed to calculate HMAC: %v", err)
	}
	log.Printf("KDC: Calculated HMAC for CHUNK manifest using node %s public key (%d bytes)", nodeID, len(manifestCHUNK.HMAC))

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

	// Create a dummy distribution record in the database so it shows up in listings
	// Use special placeholder values for test distributions
	distRecordID := make([]byte, 16)
	if _, err := rand.Read(distRecordID); err != nil {
		log.Printf("KDC: Warning: Failed to generate distribution record ID: %v", err)
	} else {
		distRecordIDHex := hex.EncodeToString(distRecordID)
		// Create a dummy distribution record with placeholder values
		// We use "test" as zone_id and key_id, but these don't need to exist due to
		// the way we query (we also check cache)
		distRecord := &DistributionRecord{
			ID:             distRecordIDHex,
			ZoneName:       "test", // Placeholder zone for test distributions
			KeyID:          "test", // Placeholder key for test distributions
			NodeID:         nodeID,
			EncryptedKey:   []byte("test"), // Dummy data
			EphemeralPubKey: []byte("test"), // Dummy data
			CreatedAt:      time.Now(),
			ExpiresAt:      nil,
			Status:         hpke.DistributionStatusPending,
			DistributionID: distributionID,
		}

		// Try to insert, but don't fail if it doesn't work (e.g., foreign key constraints)
		if err := kdc.AddDistributionRecord(distRecord); err != nil {
			log.Printf("KDC: Warning: Failed to store test distribution record in database (this is OK for test distributions): %v", err)
			// Continue anyway - the distribution is cached and will work
		}
	}

	log.Printf("KDC: Prepared %d %s chunks for node %s, distribution %s", len(allChunks), contentType, nodeID, distributionID)
	return prepared, nil
}

// PrepareTestTextChunks is a convenience wrapper for backward compatibility
// It calls PrepareTextChunks with contentType="clear_text"
func (kdc *KdcDB) PrepareTestTextChunks(nodeID, distributionID, testText string, conf *KdcConf) (*preparedChunks, error) {
	return kdc.PrepareTextChunks(nodeID, distributionID, testText, "clear_text", conf)
}

