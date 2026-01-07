/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * MANIFEST and CHUNK query handling for tdns-krs
 */

package krs

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/johanix/tdns/v0.x/tdns/hpke"
	"github.com/miekg/dns"
)

// QueryMANIFEST queries the KDC for a MANIFEST record
func QueryMANIFEST(krsDB *KrsDB, conf *KrsConf, nodeID, distributionID string) (*core.MANIFEST, error) {
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
	// Node ID is an FQDN (with trailing dot), so we concatenate directly
	controlZoneClean := conf.ControlZone
	if !strings.HasSuffix(controlZoneClean, ".") {
		controlZoneClean += "."
	}
	// Ensure nodeID is FQDN
	nodeIDFQDN := nodeID
	if !strings.HasSuffix(nodeIDFQDN, ".") {
		nodeIDFQDN = dns.Fqdn(nodeID)
	}
	qname := fmt.Sprintf("%s%s.%s", nodeIDFQDN, distributionID, controlZoneClean)

	// Create MANIFEST query
	msg := new(dns.Msg)
	msg.SetQuestion(qname, core.TypeMANIFEST)
	msg.RecursionDesired = false

	log.Printf("KRS: Querying MANIFEST for node %s, distribution %s", nodeID, distributionID)
	log.Printf("KRS: MANIFEST query: QNAME=%s, QTYPE=MANIFEST", qname)

	// Send query to KDC (try UDP first, fallback to TCP if truncated)
	udpClient := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := udpClient.Exchange(msg, kdcAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to send MANIFEST query: %v", err)
	}
	
	// Check for truncation and retry with TCP
	if resp.Truncated {
		log.Printf("KRS: MANIFEST response truncated (TC=1), retrying with TCP")
		tcpClient := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
		resp, _, err = tcpClient.Exchange(msg, kdcAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to send MANIFEST query over TCP: %v", err)
		}
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("MANIFEST query returned rcode %s", dns.RcodeToString[resp.Rcode])
	}

	// Parse MANIFEST from response
	if len(resp.Answer) == 0 {
		return nil, fmt.Errorf("MANIFEST response has no answer RRs")
	}

	rr := resp.Answer[0]
	if privRR, ok := rr.(*dns.PrivateRR); ok && privRR.Hdr.Rrtype == core.TypeMANIFEST {
		if manifest, ok := privRR.Data.(*core.MANIFEST); ok {
			log.Printf("KRS: Parsed MANIFEST: format=%d, chunk_count=%d, chunk_size=%d", manifest.Format, manifest.ChunkCount, manifest.ChunkSize)
			if manifest.Metadata != nil {
				if content, ok := manifest.Metadata["content"].(string); ok {
					log.Printf("KRS: MANIFEST content type: %s", content)
				}
			}
			// If chunk size is specified and large, prefer TCP for chunk queries
			if manifest.ChunkSize > 0 && manifest.ChunkSize > 1180 {
				log.Printf("KRS: Manifest indicates large chunks (%d bytes), will use TCP for CHUNK queries", manifest.ChunkSize)
			}
			return manifest, nil
		}
	}

	return nil, fmt.Errorf("failed to parse MANIFEST from response")
}

// loadPrivateKey loads a private key from a file path
// The file should contain a hex-encoded 32-byte HPKE private key
func loadPrivateKey(keyPath string) ([]byte, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("private key path is empty")
	}

	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %v", keyPath, err)
	}

	// Parse key (skip comments, decode hex)
	keyLines := strings.Split(string(keyData), "\n")
	var keyHex string
	for _, line := range keyLines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keyHex += line
		}
	}

	if keyHex == "" {
		return nil, fmt.Errorf("could not find key in file %s", keyPath)
	}

	// Decode hex key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %v", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes (got %d)", len(key))
	}

	return key, nil
}

// QueryCHUNK queries the KDC for a specific CHUNK record
// chunkSize is the expected chunk size from the manifest (0 if unknown)
// If chunkSize > 1180 bytes, TCP is used directly (UDP max is ~1232 bytes including headers)
func QueryCHUNK(krsDB *KrsDB, conf *KrsConf, nodeID, distributionID string, chunkID uint16, chunkSize uint16) (*core.CHUNK, error) {
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

	// Build QNAME: <chunkid>.<nodeid><distributionID>.<controlzone>
	// Node ID is an FQDN (with trailing dot), so we concatenate directly
	controlZoneClean := conf.ControlZone
	if !strings.HasSuffix(controlZoneClean, ".") {
		controlZoneClean += "."
	}
	// Ensure nodeID is FQDN
	nodeIDFQDN := nodeID
	if !strings.HasSuffix(nodeIDFQDN, ".") {
		nodeIDFQDN = dns.Fqdn(nodeID)
	}
	qname := fmt.Sprintf("%d.%s%s.%s", chunkID, nodeIDFQDN, distributionID, controlZoneClean)

	// Create CHUNK query
	msg := new(dns.Msg)
	msg.SetQuestion(qname, core.TypeCHUNK)
	msg.RecursionDesired = false
	// Set EDNS0 to allow larger messages
	msg.SetEdns0(dns.DefaultMsgSize, true)

	log.Printf("KRS: Querying CHUNK chunk %d for node %s, distribution %s", chunkID, nodeID, distributionID)
	log.Printf("KRS: CHUNK query: QNAME=%s, QTYPE=CHUNK", qname)
	
	// UDP DNS message max size is ~1232 bytes (with EDNS0), but we need to account for
	// DNS header (~12 bytes) and QNAME (~50-100 bytes typically), leaving ~1180 bytes for payload
	// If chunk size is known and > 1180 bytes, use TCP directly
	useTCP := chunkSize > 1180
	
	var resp *dns.Msg
	
	if useTCP {
		log.Printf("KRS: Using TCP for CHUNK (chunk size %d > 1180 bytes)", chunkSize)
		tcpClient := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
		resp, _, err = tcpClient.Exchange(msg, kdcAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to send CHUNK query over TCP: %v", err)
		}
	} else {
		// Try UDP first for smaller chunks, fallback to TCP if truncated
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
			log.Printf("KRS: Parsed CHUNK: sequence=%d, total=%d, data_len=%d", chunk.Sequence, chunk.Total, len(chunk.Data))
			return chunk, nil
		}
	}

	log.Printf("KRS: Failed to parse CHUNK from response")
	return nil, fmt.Errorf("failed to parse CHUNK from response")
}

// ReassembleChunks reassembles chunks into the complete base64-encoded data
func ReassembleChunks(chunks []*core.CHUNK) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks to reassemble")
	}

	total := int(chunks[0].Total)
	if len(chunks) != total {
		return nil, fmt.Errorf("chunk count mismatch: expected %d, got %d", total, len(chunks))
	}

	// Sort chunks by sequence number
	chunkMap := make(map[uint16]*core.CHUNK)
	for _, chunk := range chunks {
		if int(chunk.Sequence) >= total {
			return nil, fmt.Errorf("chunk sequence %d out of range (max %d)", chunk.Sequence, total-1)
		}
		chunkMap[chunk.Sequence] = chunk
	}

	// Reassemble in order
	reassembled := make([]byte, 0)
	for i := uint16(0); i < uint16(total); i++ {
		chunk, ok := chunkMap[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk %d", i)
		}
		reassembled = append(reassembled, chunk.Data...)
	}

	return reassembled, nil
}

// ProcessDistribution processes a complete distribution event
// Queries MANIFEST, fetches all chunks, reassembles, and processes based on content type
// If processTextResult is not nil, test_text content will be stored there instead of printed
func ProcessDistribution(krsDB *KrsDB, conf *KrsConf, distributionID string, processTextResult *string) error {
	// Use node ID from config file, not database
	// Ensure it's an FQDN
	nodeID := conf.Node.ID
	if nodeID == "" {
		return fmt.Errorf("node ID not configured in config file")
	}
	nodeID = dns.Fqdn(nodeID)

	log.Printf("KRS: Processing distribution %s for node %s", distributionID, nodeID)

	// Query MANIFEST
	manifest, err := QueryMANIFEST(krsDB, conf, nodeID, distributionID)
	if err != nil {
		return fmt.Errorf("failed to query MANIFEST: %v", err)
	}

	// Verify MANIFEST Format
	if manifest.Format != core.FormatJSON {
		return fmt.Errorf("unsupported MANIFEST format: %d (expected FormatJSON=%d)", manifest.Format, core.FormatJSON)
	}

	// Verify MANIFEST HMAC using this node's long-term public key
	// The HMAC was calculated by KDC using this node's public key
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
			return fmt.Errorf("failed to verify MANIFEST HMAC: %v", err)
		}
		if !valid {
			return fmt.Errorf("MANIFEST HMAC verification failed - possible tampering or key mismatch")
		}
		log.Printf("KRS: MANIFEST HMAC verified successfully using node's public key")
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
	// Note: Real protection comes from DNSSEC (RRSIG on MANIFEST), but we check freshness here
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
		log.Printf("KRS: Using inline payload from MANIFEST (%d bytes)", len(reassembled))
	} else if manifest.ChunkCount > 0 {
		// Payload is chunked, fetch all chunks
		// Pass chunk size from manifest to QueryCHUNK so it can decide UDP vs TCP
		var chunks []*core.CHUNK
		for i := uint16(0); i < manifest.ChunkCount; i++ {
			chunk, err := QueryCHUNK(krsDB, conf, nodeID, distributionID, i, manifest.ChunkSize)
			if err != nil {
				return fmt.Errorf("failed to query CHUNK %d: %v", i, err)
			}
			chunks = append(chunks, chunk)
			log.Printf("KRS: Fetched chunk %d/%d", i+1, manifest.ChunkCount)
		}

		// Reassemble chunks
		var err error
		reassembled, err = ReassembleChunks(chunks)
		if err != nil {
			return fmt.Errorf("failed to reassemble chunks: %v", err)
		}

		log.Printf("KRS: Reassembled %d bytes from %d chunks", len(reassembled), len(chunks))
	} else {
		return fmt.Errorf("manifest has no payload and chunk_count is 0")
	}

	// Note: HMAC verification was already done above (line 318) using manifest.VerifyHMAC()
	// The HMAC protects the manifest metadata (Format + JSON fields), not the payload itself.
	// Payload integrity is protected through encryption (for encrypted_keys) or other mechanisms.

	// Process based on content type
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

// ProcessClearText processes clear_text content
// Returns the decoded text. If called directly (not from API), prints to stdout
func ProcessClearText(data []byte) (string, error) {
	// Data is base64-encoded, decode it
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 clear text: %v", err)
	}

	text := string(decoded)
	log.Printf("KRS: ===== CLEAR TEXT CONTENT =====")
	fmt.Println(text)
	log.Printf("KRS: ===== END CLEAR TEXT =====")

	return text, nil
}

// ProcessEncryptedText processes encrypted_text content
// Displays base64 transport, ciphertext, and decrypted cleartext
func ProcessEncryptedText(krsDB *KrsDB, conf *KrsConf, data []byte) (string, error) {
	// Step 1: Display base64 transport encoded message
	log.Printf("KRS: ===== ENCRYPTED TEXT CONTENT =====")
	log.Printf("KRS: --- Base64 Transport Encoded (as received, %d bytes) ---", len(data))
	fmt.Println(string(data))
	fmt.Println()

	// Step 2: Decode base64 to get ciphertext
	log.Printf("KRS: Decoding base64...")
	ciphertextBase64, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 encrypted text: %v", err)
	}
	log.Printf("KRS: Base64 decoded to %d bytes", len(ciphertextBase64))

	log.Printf("KRS: --- Ciphertext (base64 removed, %d bytes) ---", len(ciphertextBase64))
	// Display first 64 bytes as hex for readability (full ciphertext might be very long)
	if len(ciphertextBase64) > 64 {
		fmt.Printf("%x... (truncated, showing first 64 bytes)\n", ciphertextBase64[:64])
	} else {
		fmt.Printf("%x\n", ciphertextBase64)
	}
	fmt.Println()

	// Step 3: Decrypt using HPKE
	// The ciphertext from hpke.Encrypt() already contains: <encapsulated_key (32 bytes)><encrypted_data>
	// But KDC prepends ephemeralPub again, so we have: <ephemeralPub (32 bytes)><encapsulated_key (32 bytes)><encrypted_data>
	// We need to skip the first 32 bytes (duplicate ephemeralPub) and use the rest
	log.Printf("KRS: Analyzing ciphertext structure...")
	if len(ciphertextBase64) < 64 {
		return "", fmt.Errorf("ciphertext too short: %d bytes (expected at least 64: 32 for duplicate ephemeral + 32 for encapsulated key)", len(ciphertextBase64))
	}

	// Extract the actual ciphertext (skip first 32 bytes which is duplicate ephemeralPub)
	// Verify that first 32 bytes match bytes 32-64 (they should both be the encapsulated key)
	duplicateEphemeral := ciphertextBase64[:32]
	encapsulatedKey := ciphertextBase64[32:64]
	if len(encapsulatedKey) < 32 {
		return "", fmt.Errorf("ciphertext too short to extract encapsulated key: %d bytes", len(ciphertextBase64))
	}
	
	// Check if they match (they should, as KDC prepends ephemeralPub which is a copy of encapsulated key)
	match := true
	for i := 0; i < 32; i++ {
		if duplicateEphemeral[i] != encapsulatedKey[i] {
			match = false
			break
		}
	}
	if !match {
		log.Printf("KRS: WARNING: First 32 bytes (duplicate ephemeral) don't match bytes 32-64 (encapsulated key)")
		log.Printf("KRS: Duplicate ephemeral (first 32): %x", duplicateEphemeral)
		log.Printf("KRS: Encapsulated key (bytes 32-64): %x", encapsulatedKey)
	} else {
		log.Printf("KRS: Verified: duplicate ephemeral matches encapsulated key (first 32 bytes)")
	}
	
	actualCiphertext := ciphertextBase64[32:]
	log.Printf("KRS: Extracted actual ciphertext: %d bytes (skipped first 32 bytes which is duplicate ephemeralPub)", len(actualCiphertext))
	log.Printf("KRS: First 32 bytes of actual ciphertext (encapsulated key): %x", actualCiphertext[:32])

	// Load node's private key from config
	log.Printf("KRS: Loading private key from %s...", conf.Node.LongTermPrivKey)
	if conf.Node.LongTermPrivKey == "" {
		return "", fmt.Errorf("node long-term private key not configured")
	}

	// Read private key file
	privKeyData, err := os.ReadFile(conf.Node.LongTermPrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file %s: %v", conf.Node.LongTermPrivKey, err)
	}
	log.Printf("KRS: Read private key file: %d bytes", len(privKeyData))

	// Parse private key (skip comments, decode hex)
	privKeyLines := strings.Split(string(privKeyData), "\n")
	var privKeyHex string
	for _, line := range privKeyLines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			privKeyHex += line
		}
	}

	if privKeyHex == "" {
		return "", fmt.Errorf("could not find private key in file %s", conf.Node.LongTermPrivKey)
	}
	log.Printf("KRS: Extracted private key hex: %d characters", len(privKeyHex))

	// Decode hex private key
	privateKey, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex private key: %v", err)
	}

	if len(privateKey) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes (got %d)", len(privateKey))
	}
	log.Printf("KRS: Private key decoded: %d bytes", len(privateKey))
	log.Printf("KRS: Private key (first 8 bytes): %x", privateKey[:8])
	
	// Verify we can derive public key from private key (sanity check)
	derivedPubKey, err := hpke.DerivePublicKey(privateKey)
	if err != nil {
		log.Printf("KRS: WARNING: Failed to derive public key from private key: %v", err)
	} else {
		log.Printf("KRS: Derived public key from private key (first 8 bytes): %x", derivedPubKey[:8])
		log.Printf("KRS: This public key should match the node's public key stored in KDC")
	}

	// Decrypt using HPKE
	log.Printf("KRS: Attempting HPKE decryption...")
	log.Printf("KRS:   - Private key length: %d bytes", len(privateKey))
	log.Printf("KRS:   - Ciphertext length: %d bytes", len(actualCiphertext))
	log.Printf("KRS:   - Encapsulated key (first 32 bytes of actual ciphertext): %x", actualCiphertext[:32])
	plaintext, err := hpke.Decrypt(privateKey, nil, actualCiphertext)
	if err != nil {
		log.Printf("KRS: HPKE decryption failed: %v", err)
		log.Printf("KRS: Ciphertext structure:")
		log.Printf("KRS:   - Total bytes after base64 decode: %d", len(ciphertextBase64))
		log.Printf("KRS:   - Actual ciphertext (after skipping duplicate ephemeral): %d", len(actualCiphertext))
		log.Printf("KRS:   - First 32 bytes (duplicate ephemeral): %x", ciphertextBase64[:32])
		log.Printf("KRS:   - Bytes 32-64 (encapsulated key): %x", ciphertextBase64[32:64])
		log.Printf("KRS:   - Encapsulated key from actual ciphertext: %x", actualCiphertext[:32])
		if len(derivedPubKey) == 32 {
			log.Printf("KRS:   - Derived public key from private key: %x", derivedPubKey)
		}
		return "", fmt.Errorf("failed to decrypt encrypted text: %v", err)
	}
	log.Printf("KRS: HPKE decryption successful: %d bytes decrypted", len(plaintext))

	// Step 4: Display decrypted cleartext
	log.Printf("KRS: --- Cleartext (after HPKE decryption, %d bytes) ---", len(plaintext))
	text := string(plaintext)
	fmt.Println(text)
	log.Printf("KRS: ===== END ENCRYPTED TEXT =====")

	return text, nil
}

// ProcessZoneList processes zonelist content (JSON array of zone names)
func ProcessZoneList(krsDB *KrsDB, data []byte) error {
	// Data is base64-encoded JSON, decode it
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("failed to decode base64 zone list: %v", err)
	}

	var zones []string
	if err := json.Unmarshal(decoded, &zones); err != nil {
		return fmt.Errorf("failed to unmarshal zone list JSON: %v", err)
	}

	log.Printf("KRS: Received zone list with %d zones", len(zones))
	for _, zone := range zones {
		log.Printf("KRS:   - %s", zone)
	}

	// TODO: Process zone list (e.g., trigger KMREQ queries for each zone)
	return nil
}

// ProcessEncryptedKeys processes encrypted_keys content
// Data is base64-encoded encrypted payload containing the entire distribution (all keys in cleartext JSON)
// The payload format: <ephemeral_pub_key (32 bytes)><ciphertext>
// distributionID and retireTime are optional and can be passed from the manifest metadata
func ProcessEncryptedKeys(krsDB *KrsDB, conf *KrsConf, data []byte, distributionID string, retireTime string) error {
	distID := distributionID
	// Step 1: Decode base64 to get encrypted data
	log.Printf("KRS: Processing encrypted_keys content (%d bytes base64)", len(data))
	encryptedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("failed to decode base64 encrypted payload: %v", err)
	}
	log.Printf("KRS: Decoded encrypted data: %d bytes", len(encryptedData))

	// Step 2: Load node's private key for decryption
	if conf.Node.LongTermPrivKey == "" {
		return fmt.Errorf("node long-term private key not configured")
	}

	privKeyData, err := os.ReadFile(conf.Node.LongTermPrivKey)
	if err != nil {
		return fmt.Errorf("failed to read private key file %s: %v", conf.Node.LongTermPrivKey, err)
	}

	// Parse private key (skip comments, decode hex)
	privKeyLines := strings.Split(string(privKeyData), "\n")
	var privKeyHex string
	for _, line := range privKeyLines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			privKeyHex += line
		}
	}

	if privKeyHex == "" {
		return fmt.Errorf("could not find private key in file %s", conf.Node.LongTermPrivKey)
	}

	privateKey, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode hex private key: %v", err)
	}

	if len(privateKey) != 32 {
		return fmt.Errorf("private key must be 32 bytes (got %d)", len(privateKey))
	}

	log.Printf("KRS: Loaded node private key (%d bytes)", len(privateKey))

	// Step 3: Decrypt the entire payload
	// Format from KDC: <ephemeral_pub_key (32 bytes)><ciphertext>
	// Where ciphertext from hpke.Encrypt is: <encapsulated_key (32 bytes)><encrypted_data>
	// Note: For X25519, ephemeralPub == encapsulated_key (they're the same)
	// So the format is: <ephemeralPub (32 bytes)><encapsulated_key (32 bytes)><encrypted_data>
	// We need to skip the first 32 bytes (duplicate) and pass the rest to hpke.Decrypt
	if len(encryptedData) < 64 {
		return fmt.Errorf("encrypted data too short: %d bytes (expected at least 64: 32 for ephemeral + 32 for encapsulated key)", len(encryptedData))
	}

	// Extract the actual ciphertext (skip first 32 bytes which is duplicate ephemeralPub)
	// The ciphertext from hpke.Encrypt already includes the encapsulated key
	actualCiphertext := encryptedData[32:]

	log.Printf("KRS: Encrypted payload: total %d bytes, skipping first 32 bytes (duplicate ephemeralPub), ciphertext %d bytes", 
		len(encryptedData), len(actualCiphertext))

	// Decrypt using HPKE
	// hpke.Decrypt expects: <encapsulated_key (32 bytes)><encrypted_data>
	plaintextJSON, err := hpke.Decrypt(privateKey, nil, actualCiphertext)
	if err != nil {
		return fmt.Errorf("failed to decrypt distribution payload: %v", err)
	}

	log.Printf("KRS: Successfully decrypted distribution payload: %d bytes", len(plaintextJSON))

	// Step 4: Parse JSON structure (cleartext)
	type KeyEntry struct {
		ZoneName   string `json:"zone_name"`
		KeyID      string `json:"key_id"`
		KeyType    string `json:"key_type,omitempty"`
		Algorithm  uint8  `json:"algorithm,omitempty"`
		Flags      uint16 `json:"flags,omitempty"`
		PublicKey  string `json:"public_key,omitempty"`
		PrivateKey string `json:"private_key"` // Private key in cleartext
	}

	var entries []KeyEntry
	if err := json.Unmarshal(plaintextJSON, &entries); err != nil {
		return fmt.Errorf("failed to unmarshal decrypted keys JSON: %v", err)
	}

	log.Printf("KRS: Parsed %d key entries from decrypted payload", len(entries))

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
				"flags":      entry.Flags,
				"public_key":  entry.PublicKey,
				"private_key": "***MASKED***",
			}
		}
		logJSON, _ := json.Marshal(logEntries)
		log.Printf("KRS: DEBUG: Decrypted distribution payload (private keys masked): %s", string(logJSON))
	}

	// Step 5: Process each key entry and store
	// Note: AddEdgesignerKeyWithRetirement handles retiring existing edgesigner keys atomically
	successCount := 0
	for i, entry := range entries {
		log.Printf("KRS: Processing key entry %d/%d: zone=%s, key_id=%s", i+1, len(entries), entry.ZoneName, entry.KeyID)

		log.Printf("KRS: Key entry details - ZoneName: %s, KeyID: %s, KeyType: '%s', Algorithm: %d, Flags: %d", 
			entry.ZoneName, entry.KeyID, entry.KeyType, entry.Algorithm, entry.Flags)

		// Create ReceivedKey structure
		// Parse key_id as uint16 (it's stored as string in JSON but should be a keytag)
		var keyID uint16
		if _, err := fmt.Sscanf(entry.KeyID, "%d", &keyID); err != nil {
			// Try parsing as hex
			if _, err2 := fmt.Sscanf(entry.KeyID, "%x", &keyID); err2 != nil {
				log.Printf("KRS: Warning: Could not parse key_id '%s' as number, using 0", entry.KeyID)
				keyID = 0
			}
		}

		// Decode private key from base64 string
		privateKeyBytes, err := base64.StdEncoding.DecodeString(entry.PrivateKey)
		if err != nil {
			log.Printf("KRS: Error: Failed to decode private_key for entry %d: %v", i+1, err)
			continue
		}

		// Determine state based on key type
		// ZSKs go to "edgesigner" state, KSKs go to "active" state
		// Also check Flags: 257 = KSK, 256 = ZSK
		keyState := "edgesigner"
		isKSK := false
		if entry.KeyType == "KSK" {
			keyState = "active"
			isKSK = true
			log.Printf("KRS: Detected KSK from KeyType field")
		} else if entry.Flags == 257 {
			// Fallback: check flags if KeyType is missing or incorrect
			keyState = "active"
			isKSK = true
			log.Printf("KRS: Detected KSK from Flags field (257), KeyType was '%s'", entry.KeyType)
		} else {
			log.Printf("KRS: Detected ZSK (KeyType: '%s', Flags: %d)", entry.KeyType, entry.Flags)
		}

		receivedKey := &ReceivedKey{
			ID:             fmt.Sprintf("%s-%s", entry.ZoneName, entry.KeyID),
			ZoneName:       entry.ZoneName,
			KeyID:          keyID,
			KeyType:        entry.KeyType,
			Algorithm:      entry.Algorithm,
			Flags:          entry.Flags,
			PublicKey:      entry.PublicKey,
			PrivateKey:     privateKeyBytes, // Decoded from base64 string
			State:          keyState,
			ReceivedAt:     time.Now(),
			DistributionID: distID,
			RetireTime:     retireTime, // From KDC metadata
			Comment:        fmt.Sprintf("Received via encrypted_keys distribution"),
		}

		// Store in database atomically
		// For ZSKs: retires existing edgesigner keys and adds new one (ensures only one ZSK per zone in edgesigner state)
		// For KSKs: retires existing active KSKs and adds new one (ensures only one KSK per zone in active state)
		if isKSK {
			// Ensure KeyType is set correctly for KSK
			receivedKey.KeyType = "KSK"
			if err := krsDB.AddActiveKeyWithRetirement(receivedKey); err != nil {
				log.Printf("KRS: Error: Failed to store KSK for entry %d: %v", i+1, err)
				continue
			}
			log.Printf("KRS: Successfully stored KSK (key_id %d) in 'active' state for zone %s", keyID, entry.ZoneName)
		} else {
			// Ensure KeyType is set correctly for ZSK
			receivedKey.KeyType = "ZSK"
			if err := krsDB.AddEdgesignerKeyWithRetirement(receivedKey); err != nil {
				log.Printf("KRS: Error: Failed to store ZSK for entry %d: %v", i+1, err)
				continue
			}
			log.Printf("KRS: Successfully stored ZSK (key_id %d) in 'edgesigner' state for zone %s", keyID, entry.ZoneName)
		}

		successCount++
		log.Printf("KRS: Stored key for zone %s, key_id %s (keytag %d)", entry.ZoneName, entry.KeyID, keyID)
	}

	log.Printf("KRS: Successfully processed %d/%d encrypted keys", successCount, len(entries))
	if successCount == 0 {
		return fmt.Errorf("failed to process any encrypted keys")
	}

	// Send confirmation NOTIFY back to KDC
	// Get KDC address from config
	kdcAddress := conf.Node.KdcAddress
	if kdcAddress == "" {
		// Fallback to database
		nodeConfig, err := krsDB.GetNodeConfig()
		if err == nil && nodeConfig.KdcAddress != "" {
			kdcAddress = nodeConfig.KdcAddress
		}
	}

	if kdcAddress != "" && distID != "" {
		// Send confirmation asynchronously (don't block on network I/O)
		// Capture distID in closure
		distIDCopy := distID
		go func() {
			if err := SendConfirmationToKDC(distIDCopy, conf.ControlZone, kdcAddress); err != nil {
				log.Printf("KRS: Warning: Failed to send confirmation NOTIFY: %v", err)
			} else {
				log.Printf("KRS: Successfully sent confirmation NOTIFY for distribution %s", distIDCopy)
			}
		}()
	} else {
		if distID == "" {
			log.Printf("KRS: Warning: Distribution ID not available, cannot send confirmation NOTIFY")
		} else {
			log.Printf("KRS: Warning: KDC address not configured, cannot send confirmation NOTIFY")
		}
	}

	return nil
}

