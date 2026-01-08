/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CHUNK query handling for tdns-krs
 * CHUNK is a unified format that combines MANIFEST and OLDCHUNK into a single RR type
 */

package krs

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/johanix/tdns/v0.x/tdns/hpke"
	"github.com/miekg/dns"
)

// QueryCHUNK queries the KDC for a CHUNK record
// sequence: 0 for manifest, 1+ for data chunks
// chunkSize is the expected chunk size from the manifest (0 if unknown, used for TCP decision)
func QueryCHUNK(krsDB *KrsDB, conf *KrsConf, nodeID, distributionID string, sequence uint16, chunkSize uint16) (*core.CHUNK, error) {
	nodeConfig, err := krsDB.GetNodeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get node config: %v", err)
	}

	// Use KDC address from config, fallback to database if not in config
	kdcAddress := conf.Node.KdcAddress
	if kdcAddress == "" {
		kdcAddress = nodeConfig.KdcAddress
	}
	if kdcAddress == "" {
		return nil, fmt.Errorf("KDC address not configured")
	}

	// Build QNAME: <nodeid><distributionID>.<controlzone>
	// For manifest (sequence 0): node.distid.control.
	// For data chunks (sequence > 0): sequence.node.distid.control.
	controlZoneClean := conf.ControlZone
	if !strings.HasSuffix(controlZoneClean, ".") {
		controlZoneClean += "."
	}
	// Ensure nodeID is FQDN
	nodeIDFQDN := nodeID
	if !strings.HasSuffix(nodeIDFQDN, ".") {
		nodeIDFQDN = dns.Fqdn(nodeID)
	}
	
	var qname string
	if sequence == 0 {
		// Manifest chunk
		qname = fmt.Sprintf("%s%s.%s", nodeIDFQDN, distributionID, controlZoneClean)
	} else {
		// Data chunk
		qname = fmt.Sprintf("%d.%s%s.%s", sequence, nodeIDFQDN, distributionID, controlZoneClean)
	}

	// Create CHUNK query
	msg := new(dns.Msg)
	msg.SetQuestion(qname, core.TypeCHUNK)
	msg.RecursionDesired = false
	// Set EDNS0 to allow larger messages
	msg.SetEdns0(dns.DefaultMsgSize, true)

	if sequence == 0 {
		log.Printf("KRS: Querying CHUNK manifest for node %s, distribution %s", nodeID, distributionID)
		log.Printf("KRS: CHUNK query: QNAME=%s, QTYPE=CHUNK", qname)
	} else {
		log.Printf("KRS: Querying CHUNK chunk %d for node %s, distribution %s", sequence, nodeID, distributionID)
		log.Printf("KRS: CHUNK query: QNAME=%s, QTYPE=CHUNK", qname)
	}

	// UDP DNS message max size is ~1232 bytes (with EDNS0), but we need to account for
	// DNS header (~12 bytes) and QNAME (~50-100 bytes typically), leaving ~1180 bytes for payload
	// If chunk size is known and > 1180 bytes, use TCP directly
	useTCP := chunkSize > 1180 || sequence == 0 // Always use TCP for manifest (can be large)

	var resp *dns.Msg

	if useTCP {
		if sequence == 0 {
			log.Printf("KRS: Using TCP for CHUNK manifest")
		} else {
			log.Printf("KRS: Using TCP for CHUNK (chunk size %d > 1180 bytes)", chunkSize)
		}
		tcpClient := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
		resp, _, err = tcpClient.Exchange(msg, kdcAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to send CHUNK query over TCP: %v", err)
		}
	} else {
		// Try UDP first
		udpClient := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
		resp, _, err = udpClient.Exchange(msg, kdcAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to send CHUNK query: %v", err)
		}

		// Check for truncation and retry with TCP
		if resp.Truncated {
			log.Printf("KRS: CHUNK response truncated (TC=1), retrying with TCP")
			tcpClient := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
			resp, _, err = tcpClient.Exchange(msg, kdcAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to send CHUNK query over TCP: %v", err)
			}
		}
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("CHUNK query returned rcode %s", dns.RcodeToString[resp.Rcode])
	}

	// Parse CHUNK from response
	if len(resp.Answer) == 0 {
		return nil, fmt.Errorf("CHUNK response has no answer RRs")
	}

	rr := resp.Answer[0]
	if privRR, ok := rr.(*dns.PrivateRR); ok && privRR.Hdr.Rrtype == core.TypeCHUNK {
		if chunk, ok := privRR.Data.(*core.CHUNK); ok {
			if sequence == 0 {
				log.Printf("KRS: Parsed CHUNK manifest: format=%d, total=%d", chunk.Format, chunk.Total)
			} else {
				log.Printf("KRS: Parsed CHUNK chunk: sequence=%d, total=%d, data_length=%d", chunk.Sequence, chunk.Total, chunk.DataLength)
			}
			return chunk, nil
		}
	}

	return nil, fmt.Errorf("failed to parse CHUNK from response")
}

// ExtractManifestFromCHUNK extracts MANIFEST-like information from a CHUNK manifest chunk
// Returns the same structure that ProcessDistribution expects
func ExtractManifestFromCHUNK(chunk *core.CHUNK) (*core.MANIFEST, error) {
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

// ReassembleCHUNKChunks reassembles CHUNK chunks into complete data
func ReassembleCHUNKChunks(chunks []*core.CHUNK) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks to reassemble")
	}

	// Get total from first chunk (all chunks should have same Total)
	total := int(chunks[0].Total)
	if total == 0 {
		return nil, fmt.Errorf("invalid chunk total: 0 (expected > 0 for data chunks)")
	}

	if len(chunks) != total {
		return nil, fmt.Errorf("chunk count mismatch: expected %d, got %d", total, len(chunks))
	}

	// Sort chunks by sequence number
	// Note: CHUNK uses 1-based sequence numbers (1, 2, 3, ..., total)
	chunkMap := make(map[uint16]*core.CHUNK)
	for _, chunk := range chunks {
		// Validate sequence is in range [1, total] (1-based)
		if chunk.Sequence < 1 || int(chunk.Sequence) > total {
			return nil, fmt.Errorf("chunk sequence %d out of range (expected 1-%d)", chunk.Sequence, total)
		}
		if chunk.Total != uint16(total) {
			return nil, fmt.Errorf("chunk total mismatch: expected %d, got %d", total, chunk.Total)
		}
		chunkMap[chunk.Sequence] = chunk
	}

	// Reassemble in order (1-based: 1, 2, 3, ..., total)
	reassembled := make([]byte, 0)
	for i := uint16(1); i <= uint16(total); i++ {
		chunk, ok := chunkMap[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk with sequence %d", i)
		}
		reassembled = append(reassembled, chunk.Data...)
	}

	return reassembled, nil
}

// ProcessDistributionCHUNK processes a distribution using CHUNK format
// This is similar to ProcessDistribution but uses CHUNK instead of MANIFEST+OLDCHUNK
func ProcessDistributionCHUNK(krsDB *KrsDB, conf *KrsConf, distributionID string, processTextResult *string) error {
	// Use node ID from config file, not database
	// Ensure it's an FQDN
	nodeID := conf.Node.ID
	if nodeID == "" {
		return fmt.Errorf("node ID not configured in config file")
	}
	nodeID = dns.Fqdn(nodeID)

	log.Printf("KRS: Processing distribution %s for node %s (using CHUNK format)", distributionID, nodeID)

	// Query CHUNK manifest (sequence 0)
	manifestChunk, err := QueryCHUNK(krsDB, conf, nodeID, distributionID, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to query CHUNK manifest: %v", err)
	}

	// Extract manifest information from CHUNK
	manifest, err := ExtractManifestFromCHUNK(manifestChunk)
	if err != nil {
		return fmt.Errorf("failed to extract manifest from CHUNK: %v", err)
	}

	// Verify CHUNK manifest HMAC using this node's long-term public key
	if conf.Node.LongTermPrivKey != "" {
		// Load node's private key
		privateKey, err := loadPrivateKey(conf.Node.LongTermPrivKey)
		if err != nil {
			return fmt.Errorf("failed to load node private key: %v", err)
		}

		// Derive public key from private key
		publicKey, err := hpke.DerivePublicKey(privateKey)
		if err != nil {
			return fmt.Errorf("failed to derive public key from private key: %v", err)
		}

		// Verify HMAC using the public key
		valid, err := manifest.VerifyHMAC(publicKey)
		if err != nil {
			return fmt.Errorf("failed to verify CHUNK manifest HMAC: %v", err)
		}
		if !valid {
			return fmt.Errorf("CHUNK manifest HMAC verification failed - possible tampering or key mismatch")
		}
		log.Printf("KRS: CHUNK manifest HMAC verified successfully using node's public key")
	} else {
		log.Printf("KRS: Warning: Node long-term private key not configured, skipping HMAC verification")
	}

	// Extract content type, retire_time, timestamp, and distribution_ttl from metadata
	contentType := "unknown"
	retireTime := ""
	var distributionTimestamp int64
	var distributionTTL time.Duration
	if manifest.Metadata != nil {
		if c, ok := manifest.Metadata["content"].(string); ok {
			contentType = c
		}
		if rt, ok := manifest.Metadata["retire_time"].(string); ok {
			retireTime = rt
			log.Printf("KRS: Extracted retire_time from metadata: %s", retireTime)
		}
		// Extract timestamp for replay protection
		if ts, ok := manifest.Metadata["timestamp"].(float64); ok {
			distributionTimestamp = int64(ts)
			log.Printf("KRS: Extracted timestamp from metadata: %d", distributionTimestamp)
		} else {
			// Timestamp is required for replay protection
			return fmt.Errorf("missing timestamp in distribution metadata (replay protection)")
		}
		// Extract distribution_ttl (default to 5 minutes if not present)
		if ttlStr, ok := manifest.Metadata["distribution_ttl"].(string); ok {
			parsedTTL, err := time.ParseDuration(ttlStr)
			if err != nil {
				log.Printf("KRS: Warning: Failed to parse distribution_ttl '%s', using default 5 minutes: %v", ttlStr, err)
				distributionTTL = 5 * time.Minute
			} else {
				distributionTTL = parsedTTL
				log.Printf("KRS: Extracted distribution_ttl from metadata: %s", distributionTTL)
			}
		} else {
			// Default to 5 minutes if not specified (same as TSIG)
			distributionTTL = 5 * time.Minute
			log.Printf("KRS: No distribution_ttl in metadata, using default: %s", distributionTTL)
		}
	} else {
		return fmt.Errorf("missing metadata in distribution manifest (replay protection)")
	}

	// Validate timestamp freshness (replay protection)
	now := time.Now()
	distributionTime := time.Unix(distributionTimestamp, 0)
	age := now.Sub(distributionTime)
	if age < 0 {
		return fmt.Errorf("distribution timestamp is in the future (clock skew?): %v", distributionTime)
	}
	if age > distributionTTL {
		return fmt.Errorf("distribution is too old (age: %v, TTL: %v, timestamp: %v) - possible replay attack", age, distributionTTL, distributionTime)
	}
	log.Printf("KRS: Distribution timestamp validated: age %v (within TTL %v)", age, distributionTTL)

	log.Printf("KRS: Distribution content type: %s, chunk_count: %d", contentType, manifest.ChunkCount)

	var reassembled []byte

	// Check if payload is included inline in manifest
	if len(manifest.Payload) > 0 {
		// Payload is inline, use it directly
		reassembled = make([]byte, len(manifest.Payload))
		copy(reassembled, manifest.Payload)
		log.Printf("KRS: Using inline payload from CHUNK manifest (%d bytes)", len(reassembled))
	} else if manifest.ChunkCount > 0 {
		// Payload is chunked, fetch all CHUNK chunks
		// Note: CHUNK uses sequence 0 for manifest, so data chunks start at sequence 1
		var chunks []*core.CHUNK
		for i := uint16(1); i <= manifest.ChunkCount; i++ {
			chunk, err := QueryCHUNK(krsDB, conf, nodeID, distributionID, i, manifest.ChunkSize)
			if err != nil {
				return fmt.Errorf("failed to query CHUNK chunk %d: %v", i, err)
			}
			chunks = append(chunks, chunk)
			log.Printf("KRS: Fetched CHUNK chunk %d/%d (sequence %d)", i, manifest.ChunkCount, chunk.Sequence)
		}

		// Reassemble chunks
		var err error
		reassembled, err = ReassembleCHUNKChunks(chunks)
		if err != nil {
			return fmt.Errorf("failed to reassemble CHUNK chunks: %v", err)
		}

		log.Printf("KRS: Reassembled %d bytes from %d CHUNK chunks", len(reassembled), len(chunks))
	} else {
		return fmt.Errorf("CHUNK manifest has no payload and chunk_count is 0")
	}

	// Process based on content type (same logic as ProcessDistribution)
	switch contentType {
	case "clear_text":
		text, err := ProcessClearText(reassembled)
		if err != nil {
			return err
		}
		// Store text for API response (will be nil if not called from API)
		if processTextResult != nil {
			*processTextResult = text
		}
		return nil
	case "encrypted_text":
		text, err := ProcessEncryptedText(krsDB, conf, reassembled)
		if err != nil {
			return err
		}
		// Store text for API response (will be nil if not called from API)
		if processTextResult != nil {
			*processTextResult = text
		}
		return nil
	case "zonelist":
		return ProcessZoneList(krsDB, reassembled)
	case "encrypted_keys":
		return ProcessEncryptedKeys(krsDB, conf, reassembled, distributionID, retireTime)
	default:
		return fmt.Errorf("unknown content type: %s", contentType)
	}
}

