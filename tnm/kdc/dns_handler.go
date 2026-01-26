/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNS query handler for tdns-kdc
 * Handles CHUNK queries
 */

package kdc

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"

	tnm "github.com/johanix/tdns-nm/tnm"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
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
func HandleKdcQuery(ctx context.Context, dqr *KdcQueryRequest, kdcDB *KdcDB, conf *tnm.KdcConf) error {
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

// ParseQnameForMANIFEST extracts nodeid and distributionID from CHUNK manifest QNAME
// Format: <nodeid><distributionID>.<controlzone>
// Node ID is an FQDN (with trailing dot), so distributionID is concatenated directly after it
// Used for parsing CHUNK manifest queries (chunkID=0)
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

	// The distribution ID should be the last label (it's hex, from monotonic counter)
	// Try the last label first, then work backwards if needed
	found := false
	for i := len(labels) - 1; i >= 0 && !found; i-- {
		candidateDistID := labels[i]
		// Check if this label is a valid hex string (4-16 hex chars)
		// Distribution IDs are now hex-encoded integers (monotonic counter)
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

// ParseQnameForOLDCHUNK extracts chunkid, nodeid, and distributionID from CHUNK data chunk QNAME
// Format: <chunkid>.<nodeid><distributionID>.<controlzone>
// Node ID is an FQDN (with trailing dot), so distributionID is concatenated directly after it
// Used for parsing CHUNK data chunk queries (chunkID>0)
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

	// The distribution ID should be the last label in prefixLabels (it's hex, from monotonic counter)
	// Try the last label first, then work backwards if needed
	found := false
	for i := len(prefixLabels) - 1; i >= 0 && !found; i-- {
		candidateDistID := prefixLabels[i]
		// Check if this label is a valid hex string (4-16 hex chars)
		// Distribution IDs are now hex-encoded integers (monotonic counter)
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

// handleCHUNKQuery processes CHUNK queries
// QNAME format for manifest: <nodeid>.<distributionID>.<controlzone> (chunkID=0 implied)
// QNAME format for data chunks: <chunkid>.<nodeid>.<distributionID>.<controlzone>
func handleCHUNKQuery(ctx context.Context, m *dns.Msg, msg *dns.Msg, qname string, w dns.ResponseWriter, kdcDB *KdcDB, conf *tnm.KdcConf) error {
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
func handleConfirmationNotify(ctx context.Context, msg *dns.Msg, qname string, qtype uint16, w dns.ResponseWriter, kdcDB *KdcDB, conf *tnm.KdcConf) error {
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

	// Determine content type based on operations in the distribution records
	// This mirrors the logic from prepareChunksForNode()
	hasNodeOps := false // update_components operations
	hasKeyOps := false  // roll_key, delete_key operations
	hasMgmtOps := false // ping operations

	for _, record := range records {
		switch record.Operation {
		case "update_components":
			hasNodeOps = true
		case "roll_key", "delete_key":
			hasKeyOps = true
		case "ping":
			hasMgmtOps = true
		}
	}

	// Determine content type based on operation mix
	var contentType string
	if hasNodeOps && !hasKeyOps && !hasMgmtOps {
		contentType = "node_operations"
	} else if hasKeyOps && !hasNodeOps && !hasMgmtOps {
		contentType = "key_operations"
	} else if hasMgmtOps && !hasNodeOps && !hasKeyOps {
		contentType = "mgmt_operations"
	} else {
		contentType = "mixed_operations"
	}

	// Extract failed keys/components from CHUNK EDNS(0) option if present
	failedKeys := make(map[string]bool)       // Map of "zone:keyID" -> true
	failedComponents := make(map[string]bool) // Map of componentID -> true

	// Check for CHUNK EDNS(0) option in the NOTIFY message
	opt := msg.IsEdns0()
	if opt != nil {
		chunkOpt, found := edns0.ExtractChunkOption(opt)
		if found {
			log.Printf("KDC: Found CHUNK EDNS option in confirmation NOTIFY")

			if contentType == "node_operations" {
				// Parse component status report from CHUNK option
				reportContentType, compReport, err := edns0.ParseComponentStatusReport(chunkOpt)
				if err != nil {
					log.Printf("KDC: Warning: Failed to parse component status report from CHUNK option: %v", err)
				} else if reportContentType == edns0.CHUNKContentTypeComponentStatus && compReport != nil {
					log.Printf("KDC: Parsed component status report: %d successful, %d failed components",
						len(compReport.SuccessfulComponents), len(compReport.FailedComponents))

					// Build failed components map
					for _, failedComp := range compReport.FailedComponents {
						failedComponents[failedComp.ComponentID] = true
						log.Printf("KDC: Component %s failed to install: %s", failedComp.ComponentID, failedComp.Error)
					}

					// Log successful components for debugging
					for _, successComp := range compReport.SuccessfulComponents {
						log.Printf("KDC: Component %s successfully installed", successComp.ComponentID)
					}
				} else {
					log.Printf("KDC: CHUNK option has unsupported content type: %d (expected %d for components)", reportContentType, edns0.CHUNKContentTypeComponentStatus)
				}
			} else if contentType == "key_operations" {
				// Parse key status report from CHUNK option
				reportContentType, report, err := edns0.ParseKeyStatusReport(chunkOpt)
				if err != nil {
					log.Printf("KDC: Warning: Failed to parse key status report from CHUNK option: %v", err)
				} else if reportContentType == edns0.CHUNKContentTypeKeyStatus && report != nil {
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
					log.Printf("KDC: CHUNK option has unsupported content type: %d", reportContentType)
				}
			} else if contentType == "mgmt_operations" {
				// For management operations (ping), no status report is expected
				log.Printf("KDC: Received confirmation for mgmt_operations (ping) - no status report needed")
			}
		} else {
			if contentType == "node_operations" {
				log.Printf("KDC: No CHUNK EDNS option in confirmation NOTIFY (assuming all components succeeded)")
			} else if contentType == "key_operations" {
				log.Printf("KDC: No CHUNK EDNS option in confirmation NOTIFY (assuming all keys succeeded)")
			} else if contentType == "mgmt_operations" {
				log.Printf("KDC: No CHUNK EDNS option in confirmation NOTIFY for mgmt_operations (expected)")
			}
		}
	} else {
		if contentType == "node_operations" {
			log.Printf("KDC: No EDNS(0) in confirmation NOTIFY (assuming all components succeeded)")
		} else if contentType == "key_operations" {
			log.Printf("KDC: No EDNS(0) in confirmation NOTIFY (assuming all keys succeeded)")
		} else if contentType == "mgmt_operations" {
			log.Printf("KDC: No EDNS(0) in confirmation NOTIFY for mgmt_operations (expected)")
		}
	}

	if contentType == "node_operations" {
		// For node_operations distributions, we need to:
		// 1. Record the confirmation
		// 2. Apply the component changes to the DB (sync DB with the intended component list from distribution)
		log.Printf("KDC: Recording node_operations confirmation for distribution %s, node %s",
			distributionID, confirmedNodeID)

		// Get the distribution record to extract the intended component list
		// The distribution record contains the encrypted component list
		// We need to decrypt it to get the intended list, but we don't have the node's private key
		// Instead, we'll get the component list from the chunks handler which reads from DB
		// But wait, that reads from DB which hasn't been updated yet...
		//
		// Actually, we can't decrypt without the private key. So we need a different approach.
		// We'll store the intended component list when creating the distribution, or
		// we can compute it by comparing current DB state with what we know should be there.
		//
		// For now, let's use a simpler approach: when confirmation is received, we'll
		// get the component list from the distribution by decrypting it using the node's public key
		// Wait, we can't decrypt with public key...
		//
		// Actually, the simplest: Store the intended component list in a way we can retrieve it.
		// Or, we can just apply the change we know we made (add/remove componentID).
		// But we don't know which change was made from just the distribution ID.
		//
		// Let me think: When we create the distribution, we know the intended component list.
		// We can store it in the distribution record metadata, or in a separate table.
		// For now, let's store it in the distribution record's encrypted data (which we can't decrypt).
		//
		// Actually, I think the best approach: When confirmation is received, we need to
		// get the intended component list. Since we can't decrypt, we'll need to store it separately.
		// But for now, let's just record the confirmation and mark it complete.
		// The DB update will happen when we can properly track the intended state.
		//
		// Actually wait - we can get the component list from chunks.go which reads from DB.
		// But that's the OLD list. We need the NEW list from the distribution.
		//
		// Let me check if we can get it from the distribution record somehow...

		// For now, let's apply a workaround: Get the current component list from DB,
		// and the intended list should match what's in the distribution.
		// But we can't decrypt the distribution to get the intended list.
		//
		// I think we need to store the intended component list when creating the distribution.
		// Let's add a metadata field or store it in a way we can retrieve it.
		//
		// For now, let's just record the confirmation. The DB update will need to be handled
		// by storing the intended state when creating the distribution.

		// Record the confirmation (using NULL zone_name and key_id for node_components)
		// Use empty strings which will be converted to NULL in the database
		if err := kdcDB.AddDistributionConfirmation(distributionID, "", "", confirmedNodeID); err != nil {
			log.Printf("KDC: Warning: Failed to record component confirmation: %v", err)
			return fmt.Errorf("failed to record component confirmation: %v", err)
		}

		// Apply component changes to DB by syncing with intended component list from distribution
		nodeID, intendedComponents, err := kdcDB.GetDistributionComponentList(distributionID)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get component list for distribution %s: %v", distributionID, err)
			log.Printf("KDC: Component changes will not be applied to DB (distribution may have been created before this feature)")
		} else if nodeID != confirmedNodeID {
			log.Printf("KDC: Warning: Node ID mismatch: distribution is for %s but confirmation is from %s", nodeID, confirmedNodeID)
		} else {
			// Apply the intended component list to the node
			if err := kdcDB.ApplyComponentListToNode(nodeID, intendedComponents); err != nil {
				log.Printf("KDC: Warning: Failed to apply component list to node %s: %v", nodeID, err)
			} else {
				log.Printf("KDC: Successfully applied component list to node %s (%d components)", nodeID, len(intendedComponents))
			}
		}

		log.Printf("KDC: Confirmed node_operations distribution %s for node %s", distributionID, confirmedNodeID)

		// Check if all nodes have confirmed (use empty string for node_operations - zoneName is not used in the query)
		allConfirmed, err := kdcDB.CheckAllNodesConfirmed(distributionID, "")
		if err != nil {
			log.Printf("KDC: Error checking if all nodes confirmed: %v", err)
			// Don't fail - we've recorded the confirmation
		} else if allConfirmed {
			// Mark distribution as complete
			if err := kdcDB.MarkDistributionComplete(distributionID); err != nil {
				log.Printf("KDC: Warning: Failed to mark distribution %s as complete: %v", distributionID, err)
			} else {
				log.Printf("KDC: Marked node_operations distribution %s as complete", distributionID)
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

	// Confirm all operations in the distribution (except those in failedKeys)
	confirmedCount := 0
	for _, record := range records {
		// Handle different operation types
		switch record.Operation {
		case "ping":
			log.Printf("KDC: Recording confirmation for ping operation in distribution %s from node %s",
				distributionID, confirmedNodeID)
			// Record confirmation with empty zone/key for ping (similar to node_operations)
			if err := kdcDB.AddDistributionConfirmation(distributionID, "", "", confirmedNodeID); err != nil {
				log.Printf("KDC: Warning: Failed to record ping confirmation: %v", err)
				continue
			}
			log.Printf("KDC: Ping operation confirmed successfully from node %s", confirmedNodeID)
			confirmedCount++

		case "roll_key":
			// Skip if this key is in the failed list
			keyKey := fmt.Sprintf("%s:%s", record.ZoneName, record.KeyID)
			if failedKeys[keyKey] {
				log.Printf("KDC: Skipping confirmation for failed roll_key: zone %s, key %s", record.ZoneName, record.KeyID)
				continue
			}

			log.Printf("KDC: Recording confirmation for roll_key operation in distribution %s, zone %s, key %s, node %s",
				distributionID, record.ZoneName, record.KeyID, confirmedNodeID)

			// Record the confirmation for this specific key
			if err := kdcDB.AddDistributionConfirmation(distributionID, record.ZoneName, record.KeyID, confirmedNodeID); err != nil {
				log.Printf("KDC: Warning: Failed to record confirmation for zone %s, key %s: %v", record.ZoneName, record.KeyID, err)
				continue
			}
			confirmedCount++

		case "delete_key":
			// Skip if this key is in the failed list
			keyKey := fmt.Sprintf("%s:%s", record.ZoneName, record.KeyID)
			if failedKeys[keyKey] {
				log.Printf("KDC: Skipping confirmation for failed delete_key: zone %s, key %s", record.ZoneName, record.KeyID)
				continue
			}

			log.Printf("KDC: Recording confirmation for delete_key operation in distribution %s, zone %s, key %s, node %s",
				distributionID, record.ZoneName, record.KeyID, confirmedNodeID)

			// Record the confirmation for this specific key deletion
			if err := kdcDB.AddDistributionConfirmation(distributionID, record.ZoneName, record.KeyID, confirmedNodeID); err != nil {
				log.Printf("KDC: Warning: Failed to record confirmation for zone %s, key %s: %v", record.ZoneName, record.KeyID, err)
				continue
			}
			log.Printf("KDC: Delete key operation confirmed - key %s deleted from node %s", record.KeyID, confirmedNodeID)
			confirmedCount++

		default:
			log.Printf("KDC: Warning: Unknown operation type '%s' in distribution %s", record.Operation, distributionID)
		}
	}

	log.Printf("KDC: Confirmed %d/%d operations in distribution %s for node %s", confirmedCount, len(records), distributionID, confirmedNodeID)

	// Check if all nodes have confirmed (use first record's zone for compatibility, but function doesn't actually need it)
	var zoneForCheck string
	if len(records) > 0 && records[0].ZoneName != "" {
		zoneForCheck = records[0].ZoneName
	}
	allConfirmed, err := kdcDB.CheckAllNodesConfirmed(distributionID, zoneForCheck)
	if err != nil {
		log.Printf("KDC: Error checking if all nodes confirmed: %v", err)
		// Don't fail - we've recorded the confirmation
	} else if allConfirmed {
		// All nodes have confirmed - update state for roll_key operations only
		// Collect unique zone/key pairs to avoid duplicate updates
		processedKeys := make(map[string]bool) // Map of "zone:keyID" -> true

		for _, record := range records {
			// Only process roll_key operations for state transitions
			if record.Operation != "roll_key" {
				continue
			}

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
