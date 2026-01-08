/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNS query handler for tdns-kdc
 * Handles MANIFEST, OLDCHUNK, and CHUNK queries
 */

package kdc

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/johanix/tdns/v0.x/tdns/edns0"
	"github.com/miekg/dns"
)

// KdcQueryRequest represents a DNS query request for KDC
// This mirrors DnsQueryRequest from tdns package to avoid circular imports
type KdcQueryRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
	Qtype          uint16
	Options        interface{} // *edns0.MsgOptions (avoiding import)
}

// HandleKdcQuery processes DNS queries for the KDC
// This function is called by QueryHandler when DnsQueryQ is non-nil
func HandleKdcQuery(ctx context.Context, dqr *KdcQueryRequest, kdcDB *KdcDB, conf *KdcConf) error {
	msg := dqr.Msg
	qname := dqr.Qname
	qtype := dqr.Qtype
	w := dqr.ResponseWriter

	log.Printf("KDC: Received query for %s %s from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())
	log.Printf("KDC: Message details - ID: %d, Opcode: %s, Question count: %d, Additional count: %d", 
		msg.MsgHdr.Id, dns.OpcodeToString[msg.Opcode], len(msg.Question), len(msg.Extra))

	// Check for SIG(0) signature in Additional section (but don't enforce initially)
	sig0Validated := false
	sig0SignerName := ""
	sig0KeyID := uint16(0)
	if len(msg.Extra) > 0 {
		for _, rr := range msg.Extra {
			if sig, ok := rr.(*dns.SIG); ok {
				sig0SignerName = sig.RRSIG.SignerName
				sig0KeyID = sig.RRSIG.KeyTag
				log.Printf("KDC: Query has SIG(0) signature from %s (keyid %d)", sig0SignerName, sig0KeyID)

				// TODO: Verify SIG(0) signature against trusted keys
				// For now, we just log it but don't enforce
				// sig0Validated = verifySig0Signature(msg, sig)
				sig0Validated = false // Not enforced initially
				if sig0Validated {
					log.Printf("KDC: SIG(0) signature validated successfully")
				} else {
					log.Printf("KDC: SIG(0) signature not validated (not enforced)")
				}
				break // Only check first SIG RR
			}
		}
	}

	// Create response message
	m := new(dns.Msg)
	m.SetReply(msg)
	m.Authoritative = true

	log.Printf("KDC: Processing query type %s (%d) for %s", dns.TypeToString[qtype], qtype, qname)
	switch qtype {
	case core.TypeMANIFEST:
		log.Printf("KDC: Handling MANIFEST query")
		err := handleMANIFESTQuery(ctx, m, msg, qname, w, kdcDB, conf)
		if err != nil {
			log.Printf("KDC: Error handling MANIFEST: %v", err)
		} else {
			log.Printf("KDC: MANIFEST query handled successfully")
		}
		// Don't return error - we've already sent the response (success or error)
		return nil

	case core.TypeOLDCHUNK:
		log.Printf("KDC: Handling OLDCHUNK query")
		err := handleOLDCHUNKQuery(ctx, m, msg, qname, w, kdcDB, conf)
		if err != nil {
			log.Printf("KDC: Error handling OLDCHUNK: %v", err)
		} else {
			log.Printf("KDC: OLDCHUNK query handled successfully")
		}
		return err

	case core.TypeCHUNK:
		log.Printf("KDC: Handling CHUNK query")
		err := handleCHUNKQuery(ctx, m, msg, qname, w, kdcDB, conf)
		if err != nil {
			log.Printf("KDC: Error handling CHUNK: %v", err)
		} else {
			log.Printf("KDC: CHUNK query handled successfully")
		}
		return err

	default:
		// For other query types, return ErrNotHandled to allow fallthrough to default handler
		log.Printf("KDC: Unsupported query type %s (%d) for %s - returning ErrNotHandled", dns.TypeToString[qtype], qtype, qname)
		return tdns.ErrNotHandled
	}
}

// ParseQnameForMANIFEST extracts nodeid and distributionID from MANIFEST QNAME
// Format: <nodeid><distributionID>.<controlzone>
// Node ID is an FQDN (with trailing dot), so distributionID is concatenated directly after it
func ParseQnameForMANIFEST(qname string, controlZone string) (nodeID, distributionID string, err error) {
	// Remove trailing dot if present
	if len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}

	// Extract control zone labels
	controlZoneClean := controlZone
	if len(controlZoneClean) > 0 && controlZoneClean[len(controlZoneClean)-1] == '.' {
		controlZoneClean = controlZoneClean[:len(controlZoneClean)-1]
	}
	controlLabels := dns.SplitDomainName(controlZoneClean)

	if len(controlLabels) == 0 {
		return "", "", fmt.Errorf("invalid control zone: %s", controlZone)
	}

	// Check that QNAME ends with control zone
	if !strings.HasSuffix(qname, "."+controlZoneClean) && !strings.HasSuffix(qname, controlZoneClean) {
		return "", "", fmt.Errorf("QNAME %s does not end with control zone %s", qname, controlZone)
	}

	// Remove control zone suffix to get <nodeid><distributionID>
	// In DNS, labels are separated by dots, so the format is actually:
	// <nodeid-labels>.<distributionID>.<controlzone>
	// We need to split by dots and find the distribution ID label
	prefix := qname[:len(qname)-len(controlZoneClean)-1] // -1 for the dot before control zone
	
	// Split prefix into labels
	labels := dns.SplitDomainName(prefix)
	if len(labels) == 0 {
		return "", "", fmt.Errorf("invalid MANIFEST QNAME format: %s (no labels found)", qname)
	}
	
	// The distribution ID should be the last label (it's hex)
	// Try the last label first, then work backwards if needed
	found := false
	for i := len(labels) - 1; i >= 0 && !found; i-- {
		candidateDistID := labels[i]
		// Check if this label is a valid hex string (4-16 hex chars)
		if len(candidateDistID) >= 4 && len(candidateDistID) <= 16 {
			if _, err := hex.DecodeString(candidateDistID); err == nil {
				// Valid hex string found - this is the distribution ID
				distributionID = candidateDistID
				// Node ID is all labels before this one
				if i > 0 {
					nodeID = strings.Join(labels[:i], ".") + "."
				} else {
					// Distribution ID is the only label (unusual but possible)
					nodeID = "."
				}
				found = true
				break
			}
		}
	}
	
	if !found {
		return "", "", fmt.Errorf("invalid MANIFEST QNAME format: %s (could not find valid distribution ID in labels: %v)", qname, labels)
	}

	return nodeID, distributionID, nil
}

// ParseQnameForOLDCHUNK extracts chunkid, nodeid, and distributionID from OLDCHUNK QNAME
// Format: <chunkid>.<nodeid><distributionID>.<controlzone>
// Node ID is an FQDN (with trailing dot), so distributionID is concatenated directly after it
func ParseQnameForOLDCHUNK(qname string, controlZone string) (chunkID uint16, nodeID, distributionID string, err error) {
	// Remove trailing dot if present
	if len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}

	labels := dns.SplitDomainName(qname)
	if len(labels) < 3 {
		return 0, "", "", fmt.Errorf("invalid OLDCHUNK QNAME format: %s (need at least chunkid.nodeid+distID.controlzone)", qname)
	}

	// Parse chunk ID (first label)
	chunkIDUint, err := strconv.ParseUint(labels[0], 10, 16)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid chunk ID in QNAME: %s (must be uint16)", labels[0])
	}
	chunkID = uint16(chunkIDUint)

	// Extract control zone labels
	controlZoneClean := controlZone
	if len(controlZoneClean) > 0 && controlZoneClean[len(controlZoneClean)-1] == '.' {
		controlZoneClean = controlZoneClean[:len(controlZoneClean)-1]
	}
	controlLabels := dns.SplitDomainName(controlZoneClean)

	if len(controlLabels) == 0 {
		return 0, "", "", fmt.Errorf("invalid control zone: %s", controlZone)
	}

	// Check that the last N labels match the control zone
	controlStartIdx := len(labels) - len(controlLabels)
	if controlStartIdx < 2 {
		return 0, "", "", fmt.Errorf("invalid OLDCHUNK QNAME format: %s (too few labels)", qname)
	}

	for i := 0; i < len(controlLabels); i++ {
		if labels[controlStartIdx+i] != controlLabels[i] {
			return 0, "", "", fmt.Errorf("QNAME %s does not end with control zone %s", qname, controlZone)
		}
	}

	// After removing control zone, we have: <chunkid>.<nodeid-labels>.<distributionID>
	// Labels from index 1 to controlStartIdx-1 contain <nodeid-labels> and <distributionID>
	// The distribution ID should be the last label (it's hex)
	if controlStartIdx-1 < 1 {
		return 0, "", "", fmt.Errorf("invalid OLDCHUNK QNAME format: %s (missing node ID and distribution ID)", qname)
	}
	prefixLabels := labels[1:controlStartIdx]
	
	// The distribution ID should be the last label in prefixLabels (it's hex)
	// Try the last label first, then work backwards if needed
	found := false
	for i := len(prefixLabels) - 1; i >= 0 && !found; i-- {
		candidateDistID := prefixLabels[i]
		// Check if this label is a valid hex string (4-16 hex chars)
		if len(candidateDistID) >= 4 && len(candidateDistID) <= 16 {
			if _, err := hex.DecodeString(candidateDistID); err == nil {
				// Valid hex string found - this is the distribution ID
				distributionID = candidateDistID
				// Node ID is all labels before this one
				if i > 0 {
					nodeID = strings.Join(prefixLabels[:i], ".") + "."
				} else {
					// Distribution ID is the only label (unusual but possible)
					nodeID = "."
				}
				found = true
				break
			}
		}
	}
	
	if !found {
		return 0, "", "", fmt.Errorf("invalid OLDCHUNK QNAME format: %s (could not find valid distribution ID in labels: %v)", qname, prefixLabels)
	}

	return chunkID, nodeID, distributionID, nil
}

// handleMANIFESTQuery processes MANIFEST queries
// QNAME format: <nodeid>.<distributionID>.<controlzone>
func handleMANIFESTQuery(ctx context.Context, m *dns.Msg, msg *dns.Msg, qname string, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf) error {
	log.Printf("KDC: Processing MANIFEST query for %s", qname)

	// Parse QNAME to extract node ID and distribution ID
	nodeID, distributionID, err := ParseQnameForMANIFEST(qname, conf.ControlZone)
	if err != nil {
		log.Printf("KDC: Error parsing MANIFEST QNAME %s: %v", qname, err)
		m.SetRcode(msg, dns.RcodeFormatError)
		if writeErr := w.WriteMsg(m); writeErr != nil {
			return writeErr
		}
		return fmt.Errorf("failed to parse QNAME: %v", err)
	}

	log.Printf("KDC: MANIFEST query: qname=%s, parsed node-id=%s, distribution-id=%s (length: %d)", qname, nodeID, distributionID, len(distributionID))

	// Get manifest data for this node and distribution
	manifest, err := kdcDB.GetManifestForNode(nodeID, distributionID, conf)
	if err != nil {
		log.Printf("KDC: Error getting manifest for node %s, distribution %s: %v", nodeID, distributionID, err)
		// Check if distribution records exist at all
		records, checkErr := kdcDB.GetDistributionRecordsForDistributionID(distributionID)
		if checkErr == nil {
			if len(records) == 0 {
				log.Printf("KDC: No distribution records found for distribution %s (may have been purged after completion)", distributionID)
				m.SetRcode(msg, dns.RcodeNameError)
			} else {
				log.Printf("KDC: Found %d distribution records for distribution %s, but failed to prepare manifest", len(records), distributionID)
				m.SetRcode(msg, dns.RcodeServerFailure)
			}
		} else {
			log.Printf("KDC: Failed to check distribution records: %v", checkErr)
			m.SetRcode(msg, dns.RcodeServerFailure)
		}
		if writeErr := w.WriteMsg(m); writeErr != nil {
			return writeErr
		}
		return fmt.Errorf("failed to get manifest: %v", err)
	}

	if manifest == nil {
		log.Printf("KDC: No manifest found for node %s, distribution %s (GetManifestForNode returned nil)", nodeID, distributionID)
		m.SetRcode(msg, dns.RcodeNameError)
		if writeErr := w.WriteMsg(m); writeErr != nil {
			return writeErr
		}
		return fmt.Errorf("no manifest found for node %s, distribution %s", nodeID, distributionID)
	}

	// Create MANIFEST RR
	manifestRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: core.TypeMANIFEST,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Data: manifest,
	}

	m.Answer = append(m.Answer, manifestRR)
	m.SetRcode(msg, dns.RcodeSuccess)

	content := "unknown"
	if manifest.Metadata != nil {
		if c, ok := manifest.Metadata["content"].(string); ok {
			content = c
		}
	}
	log.Printf("KDC: Sending MANIFEST response with content=%s, chunk_count=%d", content, manifest.ChunkCount)
	return w.WriteMsg(m)
}

// handleOLDCHUNKQuery processes OLDCHUNK queries
// QNAME format: <chunkid>.<nodeid>.<distributionID>.<controlzone>
func handleOLDCHUNKQuery(ctx context.Context, m *dns.Msg, msg *dns.Msg, qname string, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf) error {
	log.Printf("KDC: Processing OLDCHUNK query for %s", qname)

	// Parse QNAME to extract chunk ID, node ID, and distribution ID
	chunkID, nodeID, distributionID, err := ParseQnameForOLDCHUNK(qname, conf.ControlZone)
	if err != nil {
		log.Printf("KDC: Error parsing OLDCHUNK QNAME %s: %v", qname, err)
		m.SetRcode(msg, dns.RcodeFormatError)
		return w.WriteMsg(m)
	}

	log.Printf("KDC: OLDCHUNK chunk-id=%d, node-id=%s, distribution-id=%s", chunkID, nodeID, distributionID)

	// Get chunk data for this node, distribution, and chunk ID
	chunk, err := kdcDB.GetChunkForNode(nodeID, distributionID, chunkID, conf)
	if err != nil {
		log.Printf("KDC: Error getting chunk %d for node %s, distribution %s: %v", chunkID, nodeID, distributionID, err)
		m.SetRcode(msg, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	if chunk == nil {
		log.Printf("KDC: No chunk %d found for node %s, distribution %s", chunkID, nodeID, distributionID)
		m.SetRcode(msg, dns.RcodeNameError)
		return w.WriteMsg(m)
	}

	// Create OLDCHUNK RR
	chunkRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: core.TypeOLDCHUNK,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Data: chunk,
	}

	m.Answer = append(m.Answer, chunkRR)
	m.SetRcode(msg, dns.RcodeSuccess)

	log.Printf("KDC: Sending OLDCHUNK response with sequence=%d, total=%d, data_len=%d", chunk.Sequence, chunk.Total, len(chunk.Data))
	return w.WriteMsg(m)
}

// handleCHUNKQuery processes CHUNK queries
// QNAME format for manifest: <nodeid>.<distributionID>.<controlzone> (chunkID=0 implied)
// QNAME format for data chunks: <chunkid>.<nodeid>.<distributionID>.<controlzone>
func handleCHUNKQuery(ctx context.Context, m *dns.Msg, msg *dns.Msg, qname string, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf) error {
	log.Printf("KDC: Processing CHUNK query for %s", qname)

	// Try to parse as data chunk first (has chunk ID prefix)
	// If that fails, try parsing as manifest (no chunk ID)
	var chunkID uint16
	var nodeID, distributionID string
	var err error

	// Check if QNAME starts with a number (chunk ID)
	labels := dns.SplitDomainName(qname)
	if len(labels) > 0 {
		// Try to parse first label as chunk ID
		if parsedChunkID, parseErr := strconv.ParseUint(labels[0], 10, 16); parseErr == nil {
			// First label is a number - this is a data chunk query
			chunkID = uint16(parsedChunkID)
			chunkID, nodeID, distributionID, err = ParseQnameForOLDCHUNK(qname, conf.ControlZone)
			if err != nil {
				log.Printf("KDC: Error parsing CHUNK data chunk QNAME %s: %v", qname, err)
				m.SetRcode(msg, dns.RcodeFormatError)
				return w.WriteMsg(m)
			}
			log.Printf("KDC: CHUNK data chunk query: chunk-id=%d, node-id=%s, distribution-id=%s", chunkID, nodeID, distributionID)
		} else {
			// First label is not a number - this is a manifest query
			chunkID = 0
			nodeID, distributionID, err = ParseQnameForMANIFEST(qname, conf.ControlZone)
			if err != nil {
				log.Printf("KDC: Error parsing CHUNK manifest QNAME %s: %v", qname, err)
				m.SetRcode(msg, dns.RcodeFormatError)
				return w.WriteMsg(m)
			}
			log.Printf("KDC: CHUNK manifest query: node-id=%s, distribution-id=%s", nodeID, distributionID)
		}
	} else {
		log.Printf("KDC: Invalid CHUNK QNAME format: %s", qname)
		m.SetRcode(msg, dns.RcodeFormatError)
		return w.WriteMsg(m)
	}

	// Get CHUNK record
	chunk, err := kdcDB.GetCHUNKForNode(nodeID, distributionID, chunkID, conf)
	if err != nil {
		log.Printf("KDC: Error getting CHUNK %d for node %s, distribution %s: %v", chunkID, nodeID, distributionID, err)
		
		errStr := err.Error()
		
		// Check if this is an "out of range" error (chunk doesn't exist)
		if strings.Contains(errStr, "out of range") {
			log.Printf("KDC: CHUNK %d is out of range for distribution %s - returning NXDOMAIN", chunkID, distributionID)
			m.SetRcode(msg, dns.RcodeNameError)
			return w.WriteMsg(m)
		}
		
		// Check if this is a "node not found" error (invalid node ID)
		if strings.Contains(errStr, "node not found") {
			log.Printf("KDC: Node %s not found for distribution %s - returning NXDOMAIN", nodeID, distributionID)
			m.SetRcode(msg, dns.RcodeNameError)
			return w.WriteMsg(m)
		}
		
		// Check if distribution records exist at all
		records, checkErr := kdcDB.GetDistributionRecordsForDistributionID(distributionID)
		if checkErr == nil {
			if len(records) == 0 {
				log.Printf("KDC: No distribution records found for distribution %s (may have been purged after completion)", distributionID)
				m.SetRcode(msg, dns.RcodeNameError)
			} else {
				// Distribution exists but failed to prepare CHUNK - this is a server error
				log.Printf("KDC: Found %d distribution records for distribution %s, but failed to prepare CHUNK: %v", len(records), distributionID, err)
				m.SetRcode(msg, dns.RcodeServerFailure)
			}
		} else {
			log.Printf("KDC: Failed to check distribution records: %v", checkErr)
			m.SetRcode(msg, dns.RcodeServerFailure)
		}
		return w.WriteMsg(m)
	}

	if chunk == nil {
		log.Printf("KDC: No CHUNK %d found for node %s, distribution %s", chunkID, nodeID, distributionID)
		m.SetRcode(msg, dns.RcodeNameError)
		return w.WriteMsg(m)
	}

	// Create CHUNK RR
	chunkRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: core.TypeCHUNK,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Data: chunk,
	}

	m.Answer = append(m.Answer, chunkRR)
	m.SetRcode(msg, dns.RcodeSuccess)

	if chunk.Total == 0 {
		// Manifest chunk
		log.Printf("KDC: Sending CHUNK manifest response (format=%d, hmac_len=%d, data_len=%d)", 
			chunk.Format, chunk.HMACLen, len(chunk.Data))
	} else {
		// Data chunk
		log.Printf("KDC: Sending CHUNK data chunk response (sequence=%d, total=%d, data_len=%d)", 
			chunk.Sequence, chunk.Total, len(chunk.Data))
	}
	return w.WriteMsg(m)
}

// handleConfirmationNotify handles NOTIFY(CHUNK) messages from KRS confirming receipt of keys
// The NOTIFY QNAME format is: <distributionID>.<controlzone>
func handleConfirmationNotify(ctx context.Context, msg *dns.Msg, qname string, qtype uint16, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf) error {
	// Only handle CHUNK NOTIFYs as confirmations
	if qtype != core.TypeCHUNK {
		log.Printf("KDC: Ignoring NOTIFY for non-CHUNK type %s", dns.TypeToString[qtype])
		return nil
	}

	// Extract distributionID from QNAME: <distributionID>.<controlzone>
	controlZoneFQDN := conf.ControlZone
	if !strings.HasSuffix(controlZoneFQDN, ".") {
		controlZoneFQDN += "."
	}

	if !strings.HasSuffix(qname, controlZoneFQDN) {
		log.Printf("KDC: NOTIFY QNAME %s does not match control zone %s", qname, controlZoneFQDN)
		return fmt.Errorf("invalid NOTIFY QNAME format")
	}

	// Extract distributionID (everything before the control zone)
	prefix := strings.TrimSuffix(qname, controlZoneFQDN)
	if strings.HasSuffix(prefix, ".") {
		prefix = strings.TrimSuffix(prefix, ".")
	}
	
	// Get the last label (distributionID)
	labels := strings.Split(prefix, ".")
	distributionID := labels[len(labels)-1]

	log.Printf("KDC: Processing confirmation NOTIFY for distribution %s from %s", distributionID, w.RemoteAddr())

	// Extract node ID from remote address or from NOTIFY message
	// For now, we'll need to identify the node by matching the remote address
	// or by extracting from SIG(0) if present (future)
	// TODO: Extract node ID from SIG(0) signature or from message metadata
	
	// Get distribution records to find which zone/key this is for
	records, err := kdcDB.GetDistributionRecordsForDistributionID(distributionID)
	if err != nil {
		return fmt.Errorf("failed to get distribution records: %v", err)
	}

	if len(records) == 0 {
		log.Printf("KDC: No distribution records found for distribution %s", distributionID)
		return fmt.Errorf("no distribution records found for distribution %s", distributionID)
	}

	// For now, we'll identify the node by matching remote address to node notify addresses
	// This is a temporary solution - in the future, we'll use SIG(0) to identify the node
	remoteAddr := w.RemoteAddr().String()
	// Extract IP:port (remove protocol prefix if present)
	parts := strings.Split(remoteAddr, ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid remote address format: %s", remoteAddr)
	}
	remoteIP := strings.TrimPrefix(parts[0], "[") // Handle IPv6
	remoteIP = strings.TrimSuffix(remoteIP, "]")

	// Find node by matching remote IP to notify address
	allNodes, err := kdcDB.GetAllNodes()
	if err != nil {
		return fmt.Errorf("failed to get nodes: %v", err)
	}

	var confirmedNodeID string
	for _, node := range allNodes {
		if node.NotifyAddress != "" {
			// Extract IP from notify address (format: "IP:port")
			nodeParts := strings.Split(node.NotifyAddress, ":")
			if len(nodeParts) >= 1 {
				nodeIP := nodeParts[0]
				if nodeIP == remoteIP {
					confirmedNodeID = node.ID
					break
				}
			}
		}
	}

	if confirmedNodeID == "" {
		log.Printf("KDC: Warning: Could not identify node from remote address %s, using first node from distribution records", remoteAddr)
		// Fallback: use the node ID from the first distribution record if available
		if records[0].NodeID != "" {
			confirmedNodeID = records[0].NodeID
		} else {
			// If no node ID in record, we can't confirm - this shouldn't happen
			return fmt.Errorf("could not identify confirming node")
		}
	}

	// Extract failed keys from CHUNK EDNS(0) option if present
	failedKeys := make(map[string]bool) // Map of "zone:keyID" -> true
	
	// Check for CHUNK EDNS(0) option in the NOTIFY message
	opt := msg.IsEdns0()
	if opt != nil {
		chunkOpt, found := edns0.ExtractChunkOption(opt)
		if found {
			log.Printf("KDC: Found CHUNK EDNS option in confirmation NOTIFY")
			
			// Parse key status report from CHUNK option
			contentType, report, err := edns0.ParseKeyStatusReport(chunkOpt)
			if err != nil {
				log.Printf("KDC: Warning: Failed to parse key status report from CHUNK option: %v", err)
			} else if contentType == edns0.CHUNKContentTypeKeyStatus && report != nil {
				log.Printf("KDC: Parsed key status report: %d successful, %d failed keys", 
					len(report.SuccessfulKeys), len(report.FailedKeys))
				
				// Build failed keys map
				for _, failedKey := range report.FailedKeys {
					keyKey := fmt.Sprintf("%s:%s", failedKey.ZoneName, failedKey.KeyID)
					failedKeys[keyKey] = true
					log.Printf("KDC: Key %s (zone %s) failed to install: %s", failedKey.KeyID, failedKey.ZoneName, failedKey.Error)
				}
				
				// Log successful keys for debugging
				for _, successKey := range report.SuccessfulKeys {
					log.Printf("KDC: Key %s (zone %s) successfully installed", successKey.KeyID, successKey.ZoneName)
				}
			} else {
				log.Printf("KDC: CHUNK option has unsupported content type: %d", contentType)
			}
		} else {
			log.Printf("KDC: No CHUNK EDNS option in confirmation NOTIFY (assuming all keys succeeded)")
		}
	} else {
		log.Printf("KDC: No EDNS(0) in confirmation NOTIFY (assuming all keys succeeded)")
	}

	// Confirm all keys in the distribution (except those in failedKeys)
	confirmedCount := 0
	for _, record := range records {
		// Skip if this key is in the failed list
		keyKey := fmt.Sprintf("%s:%s", record.ZoneName, record.KeyID)
		if failedKeys[keyKey] {
			log.Printf("KDC: Skipping confirmation for failed key: zone %s, key %s", record.ZoneName, record.KeyID)
			continue
		}

		log.Printf("KDC: Recording confirmation for distribution %s, zone %s, key %s, node %s", 
			distributionID, record.ZoneName, record.KeyID, confirmedNodeID)

		// Record the confirmation for this specific key
		if err := kdcDB.AddDistributionConfirmation(distributionID, record.ZoneName, record.KeyID, confirmedNodeID); err != nil {
			log.Printf("KDC: Warning: Failed to record confirmation for zone %s, key %s: %v", record.ZoneName, record.KeyID, err)
			continue
		}
		confirmedCount++
	}

	log.Printf("KDC: Confirmed %d/%d keys in distribution %s for node %s", confirmedCount, len(records), distributionID, confirmedNodeID)

	// Check if all nodes have confirmed (use first record's zone for compatibility, but function doesn't actually need it)
	allConfirmed, err := kdcDB.CheckAllNodesConfirmed(distributionID, records[0].ZoneName)
	if err != nil {
		log.Printf("KDC: Error checking if all nodes confirmed: %v", err)
		// Don't fail - we've recorded the confirmation
	} else if allConfirmed {
		// All nodes have confirmed - update state for each key in the distribution
		// Collect unique zone/key pairs to avoid duplicate updates
		processedKeys := make(map[string]bool) // Map of "zone:keyID" -> true
		
		for _, record := range records {
			keyKey := fmt.Sprintf("%s:%s", record.ZoneName, record.KeyID)
			if processedKeys[keyKey] {
				continue // Already processed this key
			}
			processedKeys[keyKey] = true
			
			// Get the key to check its type
			key, err := kdcDB.GetDNSSECKeyByID(record.ZoneName, record.KeyID)
			if err != nil {
				log.Printf("KDC: Error getting key %s for zone %s: %v", record.KeyID, record.ZoneName, err)
				continue
			}
			
			var newState KeyState
			if key.KeyType == KeyTypeKSK {
				// KSK transitions from active_dist to active_ce (all confirmations received)
				// State flow: active -> active_dist -> active_ce
				if key.State != KeyStateActiveDist {
					log.Printf("KDC: Warning: KSK %s is in state '%s', expected 'active_dist' for confirmation", record.KeyID, key.State)
				}
				newState = KeyStateActiveCE
				log.Printf("KDC: All nodes have confirmed distribution %s, transitioning KSK %s (zone %s) state from 'active_dist' to 'active_ce'", 
					distributionID, record.KeyID, record.ZoneName)
			} else {
				// ZSK transitions from distributed to edgesigner
				// State flow: standby -> distributed -> edgesigner
				newState = KeyStateEdgeSigner
				log.Printf("KDC: All nodes have confirmed distribution %s, transitioning ZSK %s (zone %s) state from 'distributed' to 'edgesigner'", 
					distributionID, record.KeyID, record.ZoneName)
			}
			
			// Transition key state
			if err := kdcDB.UpdateKeyState(record.ZoneName, record.KeyID, newState); err != nil {
				log.Printf("KDC: Error transitioning key %s (zone %s) state: %v", record.KeyID, record.ZoneName, err)
				// Don't fail - continue with other keys
				continue
			}
			
			log.Printf("KDC: Successfully transitioned key %s (zone %s) to '%s' state", record.KeyID, record.ZoneName, newState)
			
			// Retire old keys in the same state for the same zone and key type
			// This ensures only one key per zone/key-type is in edgesigner/active_ce state
			if err := kdcDB.RetireOldKeysForZone(record.ZoneName, key.KeyType, record.KeyID, newState); err != nil {
				log.Printf("KDC: Warning: Failed to retire old keys for zone %s: %v", record.ZoneName, err)
				// Don't fail - the new key was successfully transitioned
			}
		}
		
		// Mark distribution as complete (only once, after all keys are updated)
		if err := kdcDB.MarkDistributionComplete(distributionID); err != nil {
			log.Printf("KDC: Warning: Failed to mark distribution %s as complete: %v", distributionID, err)
			// Don't fail - the keys were successfully transitioned
		} else {
			log.Printf("KDC: Marked distribution %s as complete", distributionID)
		}
	} else {
		// Get list of confirmed nodes for logging
		confirmedNodes, _ := kdcDB.GetDistributionConfirmations(distributionID)
		activeNodes, _ := kdcDB.GetActiveNodes()
		var targetCount int
		for _, node := range activeNodes {
			if node.NotifyAddress != "" {
				targetCount++
			}
		}
		log.Printf("KDC: Distribution %s: %d/%d nodes confirmed (need all %d)", 
			distributionID, len(confirmedNodes), targetCount, targetCount)
	}

	return nil
}

