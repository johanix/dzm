/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Bootstrap blob generation and management
 */

package kdc

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/johanix/tdns/v0.x/tdns/edns0"
	"github.com/johanix/tdns/v0.x/tdns/hpke"
	"github.com/miekg/dns"
)

// BootstrapBlob represents the bootstrap blob structure
type BootstrapBlob struct {
	Token              string `json:"token"`                // Bootstrap token value
	NodeID             string `json:"node_id"`               // Node ID
	KdcHpkePubKey      string `json:"kdc_hpke_pubkey"`       // KDC HPKE public key (hex encoded)
	KdcBootstrapAddress string `json:"kdc_bootstrap_address"` // KDC bootstrap address (IP:port)
	ControlZone        string `json:"control_zone"`          // Control zone name
}

// GenerateBootstrapBlobContent generates the bootstrap blob content (base64-encoded JSON)
// nodeID: The node ID
// token: The bootstrap token
// kdcConf: KDC configuration
// Returns: base64-encoded blob content, error
func GenerateBootstrapBlobContent(nodeID string, token *BootstrapToken, kdcConf *KdcConf) (string, error) {
	// Validate required configuration fields
	if kdcConf.KdcBootstrapAddress == "" {
		return "", fmt.Errorf("kdc_bootstrap_address is not configured in KDC config file - this is required for bootstrap blob generation")
	}
	if kdcConf.ControlZone == "" {
		return "", fmt.Errorf("control_zone is not configured in KDC config file - this is required for bootstrap blob generation")
	}

	// Get KDC HPKE public key
	kdcHpkePubKey, err := GetKdcHpkePubKey(kdcConf.KdcHpkePrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to get KDC HPKE public key: %v", err)
	}

	// Encode public key as hex
	kdcHpkePubKeyHex := hex.EncodeToString(kdcHpkePubKey)

	// Create bootstrap blob structure
	blob := BootstrapBlob{
		Token:               token.TokenValue,
		NodeID:              nodeID,
		KdcHpkePubKey:       kdcHpkePubKeyHex,
		KdcBootstrapAddress: kdcConf.KdcBootstrapAddress,
		ControlZone:         kdcConf.ControlZone,
	}

	// Marshal to JSON
	blobJSON, err := json.Marshal(blob)
	if err != nil {
		return "", fmt.Errorf("failed to marshal bootstrap blob: %v", err)
	}

	// Base64 encode JSON
	blobBase64 := base64.StdEncoding.EncodeToString(blobJSON)

	return blobBase64, nil
}

// GenerateBootstrapBlob generates a bootstrap blob file for a node
// nodeID: The node ID
// token: The bootstrap token
// kdcConf: KDC configuration
// outDir: Output directory (must exist)
// Returns: path to generated file, error
func GenerateBootstrapBlob(nodeID string, token *BootstrapToken, kdcConf *KdcConf, outDir string) (string, error) {
	// Verify output directory exists
	info, err := os.Stat(outDir)
	if err != nil {
		return "", fmt.Errorf("output directory does not exist or is not accessible: %v", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("output path is not a directory: %s", outDir)
	}

	// Generate blob content
	blobBase64, err := GenerateBootstrapBlobContent(nodeID, token, kdcConf)
	if err != nil {
		return "", err
	}

	// Write to file in output directory (with newline at end)
	filename := filepath.Join(outDir, fmt.Sprintf("%s.bootstrap", nodeID))
	blobContent := []byte(blobBase64)
	blobContent = append(blobContent, '\n') // Add newline at end
	if err := os.WriteFile(filename, blobContent, 0644); err != nil {
		return "", fmt.Errorf("failed to write bootstrap blob file: %v", err)
	}

	// Get absolute path
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return filename, nil // Return relative path if absolute fails
	}

	return absPath, nil
}

// ParseBootstrapBlob parses a bootstrap blob file
// filename: Path to bootstrap blob file
// Returns: BootstrapBlob, error
func ParseBootstrapBlob(filename string) (*BootstrapBlob, error) {
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap blob file: %v", err)
	}

	// Process file content: skip comment lines and extract base64 content
	lines := strings.Split(string(data), "\n")
	var blobBase64Lines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comment lines (starting with #)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		blobBase64Lines = append(blobBase64Lines, line)
	}
	
	if len(blobBase64Lines) == 0 {
		return nil, fmt.Errorf("no base64 content found in bootstrap blob file")
	}
	
	// Join all non-comment lines (base64 can span multiple lines)
	blobBase64 := strings.Join(blobBase64Lines, "")

	// Base64 decode
	blobJSON, err := base64.StdEncoding.DecodeString(blobBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	// Unmarshal JSON
	var blob BootstrapBlob
	if err := json.Unmarshal(blobJSON, &blob); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &blob, nil
}

// BootstrapRequest represents the decrypted bootstrap request from a node
type BootstrapRequest struct {
	HpkePubKey    string `json:"hpke_pubkey"`    // HPKE public key (hex encoded)
	Sig0PubKey    string `json:"sig0_pubkey"`    // SIG(0) public key (DNSKEY RR format)
	AuthToken     string `json:"auth_token"`     // Bootstrap token
	Timestamp     string `json:"timestamp"`       // ISO 8601 timestamp
	NotifyAddress string `json:"notify_address"` // Optional: IP:port for NOTIFY
}

// HandleBootstrapUpdate handles bootstrap DNS UPDATE requests
// This is called by the UPDATE handler registration API when a bootstrap UPDATE is detected
func HandleBootstrapUpdate(ctx context.Context, dur *tdns.DnsUpdateRequest, kdcDB *KdcDB, kdcConf *KdcConf) error {
	w := dur.ResponseWriter
	r := dur.Msg
	zone := dur.Qname // Zone is in the question section for UPDATE

	log.Printf("KDC: Bootstrap UPDATE received for zone %s from %s", zone, w.RemoteAddr())

	// Create response message
	m := new(dns.Msg)
	m.SetReply(r)
	
	// Helper function to return error with CHUNK option containing error details
	// hpkePubKey can be nil if we don't have it yet (e.g., decryption failed)
	// nodeID can be empty if we don't know it yet
	returnError := func(rcode int, errorMsg string, nodeID string, hpkePubKey []byte, kdcKeys *KdcHpkeKeys) error {
		m.SetRcode(r, rcode)
		
		// Create error confirmation
		errorConfirmation := edns0.BootstrapConfirmation{
			NodeID:       nodeID,
			Status:       "error",
			ErrorMessage: errorMsg,
			Timestamp:    time.Now().Format(time.RFC3339),
		}
		
		errorJSON, err := json.Marshal(errorConfirmation)
		if err != nil {
			log.Printf("KDC: Failed to marshal error confirmation: %v", err)
			return w.WriteMsg(m)
		}
		
		var encryptedError []byte
		// If we have the node's HPKE pubkey, encrypt the error message
		// Otherwise, send it unencrypted (error messages aren't sensitive)
		if hpkePubKey != nil && len(hpkePubKey) == 32 && kdcKeys != nil {
			// Encrypt using HPKE Auth mode (same as success case)
			encryptedError, err = hpke.EncryptAuth(kdcKeys.PrivateKey, hpkePubKey, errorJSON)
			if err != nil {
				log.Printf("KDC: Failed to encrypt error confirmation: %v (sending unencrypted)", err)
				encryptedError = errorJSON // Fallback to unencrypted
			}
		} else {
			// No node pubkey available, send unencrypted
			encryptedError = errorJSON
		}
		
		chunkOpt, err := edns0.CreateBootstrapConfirmationOption(encryptedError)
		if err != nil {
			log.Printf("KDC: Failed to create error confirmation option: %v", err)
			return w.WriteMsg(m)
		}
		
		if err := edns0.AddChunkOptionToMessage(m, chunkOpt); err != nil {
			log.Printf("KDC: Failed to add error confirmation option: %v", err)
			return w.WriteMsg(m)
		}
		
		log.Printf("KDC: Returning error response: %s", errorMsg)
		return w.WriteMsg(m)
	}

	// Get KDC HPKE keypair early (needed for error responses)
	kdcKeys, err := GetKdcHpkeKeypair(kdcConf.KdcHpkePrivKey)
	if err != nil {
		log.Printf("KDC: Failed to get KDC HPKE keypair: %v", err)
		return returnError(dns.RcodeServerFailure, fmt.Sprintf("KDC internal error: failed to load HPKE keypair: %v", err), "", nil, nil)
	}

	// 1. Check if UPDATE section has exactly one CHUNK record
	if len(r.Ns) != 1 {
		log.Printf("KDC: Bootstrap UPDATE must have exactly one RR in update section, got %d", len(r.Ns))
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Bootstrap UPDATE must have exactly one RR in update section, got %d", len(r.Ns)), "", nil, kdcKeys)
	}

	// 2. Extract CHUNK record
	rr := r.Ns[0]
	if rr.Header().Rrtype != core.TypeCHUNK {
		log.Printf("KDC: Bootstrap UPDATE must contain CHUNK record, got %s", dns.TypeToString[rr.Header().Rrtype])
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Bootstrap UPDATE must contain CHUNK record, got %s", dns.TypeToString[rr.Header().Rrtype]), "", nil, kdcKeys)
	}

	// Check name pattern: should be _bootstrap.{control_zone}
	updateName := rr.Header().Name
	if !strings.HasPrefix(updateName, "_bootstrap.") {
		log.Printf("KDC: Bootstrap UPDATE name must start with '_bootstrap.', got %s", updateName)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Bootstrap UPDATE name must start with '_bootstrap.', got %s", updateName), "", nil, kdcKeys)
	}

	// Extract CHUNK data
	chunkRR, ok := rr.(*dns.PrivateRR)
	if !ok {
		log.Printf("KDC: Failed to cast RR to PrivateRR")
		return returnError(dns.RcodeFormatError, "Failed to parse CHUNK record", "", nil, kdcKeys)
	}

	chunk, ok := chunkRR.Data.(*core.CHUNK)
	if !ok {
		log.Printf("KDC: Failed to cast CHUNK data")
		return returnError(dns.RcodeFormatError, "Failed to parse CHUNK data", "", nil, kdcKeys)
	}

	// Validate CHUNK format: Sequence=0, Total=0 (bootstrap), HMACLen=0
	if chunk.Sequence != 0 || chunk.Total != 0 || chunk.HMACLen != 0 {
		log.Printf("KDC: Invalid CHUNK format for bootstrap: Sequence=%d, Total=%d, HMACLen=%d", chunk.Sequence, chunk.Total, chunk.HMACLen)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Invalid CHUNK format for bootstrap: Sequence=%d, Total=%d, HMACLen=%d (all must be 0)", chunk.Sequence, chunk.Total, chunk.HMACLen), "", nil, kdcKeys)
	}

	// 3. Extract encrypted bootstrap request from CHUNK data
	encryptedData := chunk.Data
	if len(encryptedData) == 0 {
		log.Printf("KDC: CHUNK data is empty")
		return returnError(dns.RcodeFormatError, "CHUNK data is empty", "", nil, kdcKeys)
	}

	// 4. Decrypt bootstrap request using HPKE
	// NOTE: HPKE Auth mode requires the sender's public key for decryption, but we don't have it yet
	// (it's inside the encrypted payload). This is a chicken-and-egg problem.
	// 
	// Options:
	// 1. Use HPKE Base mode for bootstrap (no sender auth) - implemented here
	// 2. Include sender's HPKE pubkey in plaintext (e.g., in CHUNK name or as separate field)
	// 3. Use a two-step bootstrap process
	//
	// TODO: Switch to HPKE Auth mode once we resolve the key distribution issue.
	// For now, we use Base mode which provides encryption but not sender authentication.
	// The token provides authentication instead.

	// Decrypt using HPKE Base mode (since we don't have sender's pubkey for Auth mode)
	// The encrypted data format: [encapsulated_key (32 bytes)][encrypted_data]
	decryptedData, err := hpke.Decrypt(kdcKeys.PrivateKey, nil, encryptedData)
	if err != nil {
		log.Printf("KDC: Failed to decrypt bootstrap request: %v", err)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Failed to decrypt bootstrap request: %v", err), "", nil, kdcKeys)
	}

	log.Printf("KDC: Successfully decrypted bootstrap request (decrypted length: %d)", len(decryptedData))

	// 5. Parse decrypted bootstrap request JSON
	var bootstrapReq BootstrapRequest
	if err := json.Unmarshal(decryptedData, &bootstrapReq); err != nil {
		log.Printf("KDC: Failed to parse bootstrap request JSON: %v", err)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Failed to parse bootstrap request JSON: %v", err), "", nil, kdcKeys)
	}

	// 6. Extract HPKE pubkey from request (needed for error responses)
	var hpkePubKey []byte
	if bootstrapReq.HpkePubKey != "" {
		var err error
		hpkePubKey, err = hex.DecodeString(bootstrapReq.HpkePubKey)
		if err != nil || len(hpkePubKey) != 32 {
			// Invalid HPKE pubkey, but we'll handle that in validation step
			hpkePubKey = nil
		}
	}

	// 7. Validate token
	token, err := kdcDB.ValidateBootstrapToken(bootstrapReq.AuthToken)
	if err != nil {
		log.Printf("KDC: Bootstrap token validation failed: %v", err)
		return returnError(dns.RcodeRefused, fmt.Sprintf("Bootstrap token validation failed: %v", err), "", hpkePubKey, kdcKeys)
	}

	// 8. Validate timestamp (within 5 minutes)
	reqTimestamp, err := time.Parse(time.RFC3339, bootstrapReq.Timestamp)
	if err != nil {
		log.Printf("KDC: Invalid timestamp format: %v", err)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Invalid timestamp format: %v", err), token.NodeID, hpkePubKey, kdcKeys)
	}

	now := time.Now()
	if now.Sub(reqTimestamp) > 5*time.Minute || reqTimestamp.Sub(now) > 5*time.Minute {
		log.Printf("KDC: Bootstrap request timestamp too old or too far in future: %s", bootstrapReq.Timestamp)
		return returnError(dns.RcodeRefused, fmt.Sprintf("Bootstrap request timestamp out of range (must be within 5 minutes): %s", bootstrapReq.Timestamp), token.NodeID, hpkePubKey, kdcKeys)
	}

	// 9. Validate keys
	// HPKE pubkey: already decoded above, but validate it's correct
	if hpkePubKey == nil || len(hpkePubKey) != 32 {
		log.Printf("KDC: Invalid HPKE public key format (length: %d)", len(hpkePubKey))
		return returnError(dns.RcodeFormatError, "Invalid HPKE public key format (must be 32 bytes hex encoded)", token.NodeID, nil, kdcKeys)
	}

	// SIG(0) pubkey: validate DNSKEY format (basic check)
	if bootstrapReq.Sig0PubKey == "" {
		log.Printf("KDC: SIG(0) public key is required")
		return returnError(dns.RcodeFormatError, "SIG(0) public key is required", token.NodeID, hpkePubKey, kdcKeys)
	}

	// 10. Store node with both pubkeys
	nodeID := token.NodeID
	node := &Node{
		ID:             nodeID,
		Name:           nodeID, // Use node ID as name initially
		LongTermPubKey: hpkePubKey,
		Sig0PubKey:     bootstrapReq.Sig0PubKey,
		NotifyAddress:  bootstrapReq.NotifyAddress,
		State:          NodeStateOnline,
		Comment:        "Bootstrap registered",
	}

	// Add node with both pubkeys
	if err := kdcDB.AddNode(node); err != nil {
		log.Printf("KDC: Failed to add node: %v", err)
		return returnError(dns.RcodeServerFailure, fmt.Sprintf("Failed to add node to database: %v", err), nodeID, hpkePubKey, kdcKeys)
	}

	// 11. Mark token as used
	if err := kdcDB.MarkBootstrapTokenUsed(bootstrapReq.AuthToken); err != nil {
		log.Printf("KDC: Failed to mark token as used: %v", err)
		// Node is already created, but token not marked - this is a problem
		// For now, continue but log the error
	}

	log.Printf("KDC: Bootstrap successful for node %s", nodeID)

	// 12. Generate bootstrap confirmation
	// Create confirmation JSON
	confirmation := edns0.BootstrapConfirmation{
		NodeID:        nodeID,
		Status:        "success",
		KdcHpkePubKey: hex.EncodeToString(kdcKeys.PublicKey),
		Timestamp:     time.Now().Format(time.RFC3339),
	}

	confirmationJSON, err := json.Marshal(confirmation)
	if err != nil {
		log.Printf("KDC: Failed to marshal bootstrap confirmation: %v", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	// Encrypt confirmation using HPKE Auth mode
	// KDC's private key (sender authentication), node's HPKE public key (recipient encryption)
	encryptedConfirmation, err := hpke.EncryptAuth(kdcKeys.PrivateKey, hpkePubKey, confirmationJSON)
	if err != nil {
		log.Printf("KDC: Failed to encrypt bootstrap confirmation: %v", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	// Create CHUNK EDNS(0) option with bootstrap confirmation
	chunkOpt, err := edns0.CreateBootstrapConfirmationOption(encryptedConfirmation)
	if err != nil {
		log.Printf("KDC: Failed to create bootstrap confirmation option: %v", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	// Add CHUNK option to response message
	if err := edns0.AddChunkOptionToMessage(m, chunkOpt); err != nil {
		log.Printf("KDC: Failed to add bootstrap confirmation option to message: %v", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	log.Printf("KDC: Bootstrap confirmation generated and attached to response")

	m.SetRcode(r, dns.RcodeSuccess)
	return w.WriteMsg(m)
}

