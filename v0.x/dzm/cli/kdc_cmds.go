/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CLI commands for tdns-kdc management
 */
package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/johanix/dzm/v0.x/dzm/kdc"
	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/johanix/tdns/v0.x/tdns/hpke"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var nodeid, nodename, pubkeyfile string

// KdcCmd removed - commands are now direct children of root in kdc-cli

var KdcZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Manage zones in KDC",
}

var KdcDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage key distributions",
	Long:  `Commands for managing key distributions, including listing distributions, checking their state, marking them as completed, and distributing keys to edge nodes.`,
}

var KdcNodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage edge nodes in KDC",
}

var KdcConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage KDC configuration",
}

var KdcServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage services in KDC",
}

var KdcComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage components in KDC",
}

var KdcNodeEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Manage enrollment tokens and blobs",
	Long:  `Commands for managing enrollment tokens and generating enrollment blobs for node registration.`,
}

var KdcHpkeCmd = &cobra.Command{
	Use:   "hpke",
	Short: "Manage KDC HPKE keypair",
	Long:  `Commands for generating and managing the KDC's HPKE (Hybrid Public Key Encryption) keypair.
The HPKE keypair is required for:
  - Encrypting bootstrap confirmations sent to KRS nodes
  - Decrypting bootstrap requests from KRS nodes

The keypair must be configured in the KDC config file as kdc_hpke_priv_key.`,
}

var kdcHpkeGenerateCmd = &cobra.Command{
	Use:   "generate --outfile <path>",
	Short: "Generate a new HPKE keypair for the KDC",
	Long: `Generate a new HPKE (X25519) keypair for the KDC and save it to a file.

The generated key file will contain:
  - The private key (hex encoded)
  - The public key (for reference)
  - Comments with generation timestamp and usage instructions

The file will be created with permissions 0600 (readable/writable by owner only).

After generating the keypair:
  1. Add the following to your KDC config file (under 'kdc:' section):
     kdc_hpke_priv_key: <path-to-key-file>
  2. Restart the KDC

WARNING: If you generate a NEW keypair, you must regenerate all enrollment blobs
that were created with the old public key, as they will no longer be decryptable.`,
	Run: func(cmd *cobra.Command, args []string) {
		outFile, _ := cmd.Flags().GetString("outfile")
		if outFile == "" {
			log.Fatalf("Error: --outfile is required")
		}

		// Check if file already exists
		if _, err := os.Stat(outFile); err == nil {
			log.Fatalf("Error: File already exists: %s\nUse a different path or remove the existing file first.", outFile)
		}

		// Generate HPKE keypair
		pubKey, privKey, err := hpke.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Error generating HPKE keypair: %v", err)
		}

		// Format key file content
		pubKeyHex := hex.EncodeToString(pubKey)
		privKeyHex := hex.EncodeToString(privKey)
		generatedAt := time.Now().Format(time.RFC3339)

		keyContent := fmt.Sprintf(`# KDC HPKE Private Key (X25519)
# Generated: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
# 
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone. Anyone with access to this key can decrypt
# data encrypted with the corresponding public key.
# This key is used by KDC to decrypt bootstrap requests and encrypt bootstrap confirmations.
#
# Public Key: %s
#
# To use this keypair:
# 1. Add the following to your KDC config file (under 'kdc:' section):
#    kdc_hpke_priv_key: %s
# 2. Restart the KDC
#
# WARNING: If you generate a NEW keypair, you must regenerate all enrollment blobs
# that were created with the old public key, as they will no longer be decryptable.
#
%s
`, generatedAt, pubKeyHex, outFile, privKeyHex)

		// Write key file with secure permissions
		if err := os.WriteFile(outFile, []byte(keyContent), 0600); err != nil {
			log.Fatalf("Error writing key file: %v", err)
		}

		// Get absolute path for display
		absPath, err := filepath.Abs(outFile)
		if err != nil {
			absPath = outFile
		}

		fmt.Printf("HPKE keypair generated successfully!\n\n")
		fmt.Printf("Key file: %s\n", absPath)
		fmt.Printf("Public key: %s\n\n", pubKeyHex)
		fmt.Printf("Next steps:\n")
		fmt.Printf("  1. Add the following to your KDC config file (under 'kdc:' section):\n")
		fmt.Printf("     kdc_hpke_priv_key: %s\n", absPath)
		fmt.Printf("  2. Restart the KDC\n\n")
		fmt.Printf("WARNING: If you generate a NEW keypair, you must regenerate all enrollment blobs\n")
		fmt.Printf("that were created with the old public key, as they will no longer be decryptable.\n")
	},
}

var KdcServiceComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage service-component assignments",
	Long:  `Manage which components belong to which services`,
}

var KdcNodeComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage node-component assignments",
	Long:  `Manage which components are served by which nodes`,
}

var KdcServiceTransactionCmd = &cobra.Command{
	Use:   "tx",
	Short: "Manage service modification transactions",
	Long:  `Transaction-based service modification allows batching multiple component changes and previewing their impact before applying them.`,
}

// Zone commands
var kdcZoneAddCmd = &cobra.Command{
	Use:   "add --zone <zone-name> [--sid <service-id>] [--signing-mode <mode>]",
	Short: "Add a new zone to KDC",
	Long: `Add a new zone to the Key Distribution Center.

Zones are organized using a service-component model:
  - Zones belong to Services (optional)
  - Services consist of Components
  - Components are served by Nodes
  - Zones are assigned to Components

Workflow:
  1. Create Services: "kdc service add --id <id> --name <name>"
  2. Create Components: "kdc component add --id <id> --name <name>"
  3. Assign Components to Services: "kdc service component assign --service-id <id> --component-id <id>"
  4. Assign Zones to Components: "kdc component zone assign --component-id <id> --zone <zone>"
  5. Assign Nodes to Components: "kdc node component assign --node-id <id> --component-id <id>"

Signing Modes:
  - upstream: Zone is signed upstream, no keys distributed
  - central: Zone is signed centrally, no keys distributed (default)
  - edgesign_dyn: ZSK distributed, signs dynamic responses only
  - edgesign_zsk: ZSK distributed, signs all responses
  - edgesign_full: KSK+ZSK distributed, all signing at edge
  - unsigned: No DNSSEC signing

If --sid is not provided, the zone will be created without a service assignment.
This is valid but means the zone won't be part of the service-component model.`,
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Get optional flags
		serviceID, _ := cmd.Flags().GetString("sid")
		signingMode, _ := cmd.Flags().GetString("signing-mode")
		comment, _ := cmd.Flags().GetString("comment")

		// Default signing mode to "central" if not specified
		if signingMode == "" {
			signingMode = "central"
		}

		req := map[string]interface{}{
			"command": "add",
			"zone": map[string]interface{}{
				"name":         tdns.Globals.Zonename,
				"service_id":   serviceID,
				"signing_mode": signingMode,
				"active":       true,
				"comment":      comment,
			},
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcZoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all zones in KDC",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		// Debug: print raw response in verbose mode
		if tdns.Globals.Verbose {
			rawJSON, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Printf("DEBUG: Raw API response:\n%s\n", rawJSON)
		}

		zonesRaw, ok := resp["zones"]
		if !ok {
			fmt.Printf("Error: 'zones' key not found in response\n")
			fmt.Printf("Response keys: %v\n", getMapKeys(resp))
			return
		}

		zones, ok := zonesRaw.([]interface{})
		if !ok {
			fmt.Printf("Error: 'zones' is not an array (got %T)\n", zonesRaw)
			if tdns.Globals.Verbose {
				fmt.Printf("Value: %+v\n", zonesRaw)
			}
			return
		}

		if len(zones) == 0 {
			fmt.Println("No zones configured")
			return
		}

		// Get zone enrichments from response
		enrichmentsRaw, _ := resp["zone_enrichments"]
		enrichments := make(map[string]map[string]interface{})
		if enrichmentsMap, ok := enrichmentsRaw.(map[string]interface{}); ok {
			for k, v := range enrichmentsMap {
				if e, ok := v.(map[string]interface{}); ok {
					enrichments[k] = e
				}
			}
		}

		// Print header - remove ID column, add Service and Components
		fmt.Printf("%-30s %-20s %-30s %-15s %-8s %s\n", "Zone", "Service", "Components", "Signing comp", "Active", "Comment")
		fmt.Println(strings.Repeat("-", 120))

		for i, z := range zones {
			zone, ok := z.(map[string]interface{})
			if !ok {
				fmt.Printf("Warning: zone[%d] is not a map (got %T), skipping\n", i, z)
				continue
			}

			name := getString(zone, "name", "Name")
			active := getBool(zone, "active", "Active")
			comment := getString(zone, "comment", "Comment")

			// Get enrichment data
			serviceID := "(none)"
			componentsStr := "(none)"
			signingModeStr := "(none)"
			var nodeIDs []string

			// Get service_id from zone object itself
			if sid := getString(zone, "service_id"); sid != "" {
				serviceID = sid
			}

			if enrichment, ok := enrichments[name]; ok {
				// Prefer service_id from enrichment if available, otherwise keep zone's service_id
				if sid := getString(enrichment, "service_id"); sid != "" {
					serviceID = sid
				}
				// Get signing component ID for Signing comp column
				if signingCompID := getString(enrichment, "signing_component_id"); signingCompID != "" {
					signingModeStr = signingCompID
				}
				// Get non-signing components for Components column
				if compNames, ok := enrichment["component_names"].([]interface{}); ok {
					compStrs := make([]string, 0, len(compNames))
					for _, cn := range compNames {
						if cs, ok := cn.(string); ok {
							compStrs = append(compStrs, cs)
						}
					}
					if len(compStrs) > 0 {
						componentsStr = strings.Join(compStrs, ", ")
					}
				}
				if tdns.Globals.Verbose {
					if nodes, ok := enrichment["node_ids"].([]interface{}); ok {
						for _, n := range nodes {
							if ns, ok := n.(string); ok {
								nodeIDs = append(nodeIDs, ns)
							}
						}
					}
				}
			}

			activeStr := "yes"
			if !active {
				activeStr = "no"
			}

			fmt.Printf("%-30s %-20s %-30s %-15s %-8s %s\n", 
				name, serviceID, componentsStr, signingModeStr, activeStr, comment)
			
			// Print nodes in verbose mode
			if tdns.Globals.Verbose && len(nodeIDs) > 0 {
				fmt.Printf("  Nodes: %s\n", strings.Join(nodeIDs, ", "))
			}
		}
	},
}

var kdcZoneGetCmd = &cobra.Command{
	Use:   "get --zone <zone-id>",
	Short: "Get zone details from KDC",
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
			"zone_name": tdns.Globals.Zonename,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if zone, ok := resp["zone"].(map[string]interface{}); ok {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(zone)
		} else {
			fmt.Printf("Response: %+v\n", resp)
		}
	},
}

var KdcZoneDnssecCmd = &cobra.Command{
	Use:   "dnssec",
	Short: "Manage DNSSEC keys for a zone",
}

var kdcZoneDnssecListCmd = &cobra.Command{
	Use:   "list [--zone <zone-id>]",
	Short: "List all DNSSEC keys for a zone (or all zones if zone not specified)",
	Run: func(cmd *cobra.Command, args []string) {
		// Zone is optional - if provided, normalize it
		if tdns.Globals.Zonename != "" {
			tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get-keys",
		}
		// Only include zone_name if zone was specified
		if tdns.Globals.Zonename != "" {
			req["zone_name"] = tdns.Globals.Zonename
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		keysRaw, ok := resp["keys"]
		if !ok {
			fmt.Printf("Error: 'keys' key not found in response\n")
			fmt.Printf("Response keys: %v\n", getMapKeys(resp))
			return
		}

		keys, ok := keysRaw.([]interface{})
		if !ok {
			fmt.Printf("Error: 'keys' is not an array (got %T)\n", keysRaw)
			if tdns.Globals.Verbose {
				fmt.Printf("Value: %+v\n", keysRaw)
			}
			return
		}

		if len(keys) == 0 {
			if tdns.Globals.Zonename != "" {
				fmt.Println("No keys configured for this zone")
			} else {
				fmt.Println("No keys configured for any zone")
			}
			return
		}

		var lines []string
		lines = append(lines, "Zone | Key ID | Type | Algorithm | State | Timestamp | Event")

		for i, k := range keys {
			if tdns.Globals.Verbose {
				fmt.Printf("DEBUG: key[%d] type: %T, value: %+v\n", i, k, k)
			}

			key, ok := k.(map[string]interface{})
			if !ok {
				fmt.Printf("Warning: key[%d] is not a map (got %T), skipping\n", i, k)
				continue
			}

			// Get zone name
			zoneID := getString(key, "zone_name", "ZoneName")
			keyID := getString(key, "id", "ID")
			keyType := getString(key, "key_type", "KeyType")
			state := getString(key, "state", "State")
			comment := getString(key, "comment", "Comment")

			// Get algorithm (may be number from JSON or string)
			var algStr string
			if algVal, ok := key["algorithm"]; ok {
				switch v := algVal.(type) {
				case float64:
					// JSON numbers come as float64
					algNum := uint8(v)
					if algName, ok := dns.AlgorithmToString[algNum]; ok {
						algStr = algName
					} else {
						algStr = fmt.Sprintf("%d", algNum)
					}
				case string:
					algStr = v
				default:
					algStr = fmt.Sprintf("%v", v)
				}
			} else {
				algStr = "?"
			}

			// Parse comment into timestamp and event
			// Format is typically "event at timestamp" or just "event"
			var timestamp, event string
			if comment != "" {
				// Try to parse "event at YYYY-MM-DD HH:MM:SS" format
				parts := strings.Split(comment, " at ")
				if len(parts) == 2 {
					event = parts[0]
					timestamp = parts[1]
				} else {
					// No timestamp found, use the whole comment as event
					event = comment
					timestamp = ""
				}
			} else {
				event = ""
				timestamp = ""
			}

			line := fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s", zoneID, keyID, keyType, algStr, state, timestamp, event)
			lines = append(lines, line)
		}

		fmt.Println(columnize.SimpleFormat(lines))
	},
}

var kdcZoneDeleteCmd = &cobra.Command{
	Use:   "delete --zone <zone-id>",
	Short: "Delete a zone from KDC",
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename") // Normalize zone name to FQDN format
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "delete",
			"zone_name": tdns.Globals.Zonename,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Node commands
var kdcNodeAddCmd = &cobra.Command{
	Use:   "add --node <node-id> --name <node-name> --pubkey <pubkey-file>",
	Short: "Add a new edge node to KDC",
	Long:  `Add a new edge node. pubkey-file should contain the HPKE public key (32 bytes, hex or base64 encoded)`,
	// Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		// Note: nodeid, nodename, pubkeyfile are persistent flags (global variables)
		// We validate them here since PrepArgs doesn't handle persistent flags yet
		if nodeid == "" {
			log.Fatalf("Error: --nodeid is required")
		}
		if nodename == "" {
			log.Fatalf("Error: --nodename is required")
		}
		if pubkeyfile == "" {
			log.Fatalf("Error: --pubkeyfile is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Read public key file
		pubkeyData, err := os.ReadFile(pubkeyfile)
		if err != nil {
			log.Fatalf("Error reading public key file: %v", err)
		}

		// Extract key from file (skip comment lines starting with #)
		lines := strings.Split(string(pubkeyData), "\n")
		var keyLines []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				keyLines = append(keyLines, line)
			}
		}
		pubkeyStr := strings.Join(keyLines, "")

		// Decode hex or base64 (try hex first, then base64)
		var pubkey []byte
		
		// Try hex decoding first (64 hex chars = 32 bytes)
		if len(pubkeyStr) == 64 {
			pubkey, err = hex.DecodeString(pubkeyStr)
			if err != nil {
				log.Fatalf("Error decoding hex public key: %v", err)
			}
		} else {
			// Try base64
			pubkey, err = base64.StdEncoding.DecodeString(pubkeyStr)
			if err != nil {
				log.Fatalf("Error decoding base64 public key: %v", err)
			}
		}

		if len(pubkey) != 32 {
			log.Fatalf("Public key must be 32 bytes (X25519), got %d bytes", len(pubkey))
		}

		// Normalize node ID to FQDN
		nodeIDFQDN := dns.Fqdn(nodeid)

		req := map[string]interface{}{
			"command": "add",
			"node": map[string]interface{}{
				"id":               nodeIDFQDN,
				"name":             nodename,
				"long_term_pub_key": pubkey,
				"state":            "online",
				"comment":          "",
			},
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all edge nodes in KDC",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if nodes, ok := resp["nodes"].([]interface{}); ok {
			if len(nodes) == 0 {
				fmt.Println("No nodes configured")
				return
			}
			
			// Build table rows for columnize
			lines := []string{"ID | Name | Notify Address | State | Comment"}
			for _, n := range nodes {
				if node, ok := n.(map[string]interface{}); ok {
					id := fmt.Sprintf("%v", node["id"])
					name := fmt.Sprintf("%v", node["name"])
					notifyAddr := ""
					if addr, ok := node["notify_address"]; ok && addr != nil {
						notifyAddr = fmt.Sprintf("%v", addr)
					}
					state := fmt.Sprintf("%v", node["state"])
					comment := fmt.Sprintf("%v", node["comment"])
					lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s", id, name, notifyAddr, state, comment))
				}
			}
			
			fmt.Println(columnize.SimpleFormat(lines))
		} else {
			fmt.Printf("Response: %+v\n", resp)
		}
	},
}

var kdcNodeGetCmd = &cobra.Command{
	Use:   "get [node-id]",
	Short: "Get node details from KDC",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
			"node_id": args[0],
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if node, ok := resp["node"].(map[string]interface{}); ok {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(node)
		} else {
			fmt.Printf("Response: %+v\n", resp)
		}
	},
}

var kdcNodeUpdateCmd = &cobra.Command{
	Use:   "update --nodeid <node-id> [--name <name>] [--notify-address <address:port>] [--comment <comment>]",
	Short: "Update node details (name, notify address, comment)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid")
		updateNodeIDFQDN := cmd.Flag("nodeid").Value.String()

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Get current node to preserve fields not being updated
		getReq := map[string]interface{}{
			"command": "get",
			"node_id": updateNodeIDFQDN,
		}
		getResp, err := sendKdcRequest(api, "/kdc/node", getReq)
		if err != nil {
			log.Fatalf("Error getting current node: %v", err)
		}
		if getResp["error"] == true {
			log.Fatalf("Error getting current node: %v", getResp["error_msg"])
		}

		nodeMap, ok := getResp["node"].(map[string]interface{})
		if !ok {
			log.Fatalf("Error: invalid node data in response")
		}

		// Update fields if provided
		updateNode := map[string]interface{}{
			"id": updateNodeIDFQDN,
		}

		// Preserve or update name
		if nameFlag := cmd.Flag("name").Value.String(); nameFlag != "" {
			updateNode["name"] = nameFlag
		} else if name, ok := nodeMap["name"]; ok {
			updateNode["name"] = name
		}

		// Preserve or update notify_address
		if notifyAddrFlag := cmd.Flag("notify-address").Value.String(); notifyAddrFlag != "" {
			updateNode["notify_address"] = notifyAddrFlag
		} else if addr, ok := nodeMap["notify_address"]; ok {
			updateNode["notify_address"] = addr
		}

		// Preserve long_term_pub_key (required field)
		// JSON encodes []byte as base64 string, so we need to decode it back to []byte
		if pubkeyVal, ok := nodeMap["long_term_pub_key"]; ok {
			var pubkeyBytes []byte
			if pubkeyStr, ok := pubkeyVal.(string); ok {
				// Decode base64 string back to []byte
				pubkeyBytes, err = base64.StdEncoding.DecodeString(pubkeyStr)
				if err != nil {
					log.Fatalf("Error decoding public key from response: %v", err)
				}
			} else {
				log.Fatalf("Error: public key has unexpected type: %T", pubkeyVal)
			}
			updateNode["long_term_pub_key"] = pubkeyBytes
		} else {
			log.Fatalf("Error: public key not found in node data")
		}

		// Preserve state
		if state, ok := nodeMap["state"]; ok {
			updateNode["state"] = state
		} else {
			updateNode["state"] = "online"
		}

		// Preserve or update comment
		if commentFlag := cmd.Flag("comment").Value.String(); commentFlag != "" {
			updateNode["comment"] = commentFlag
		} else if comment, ok := nodeMap["comment"]; ok {
			updateNode["comment"] = comment
		} else {
			updateNode["comment"] = ""
		}

		req := map[string]interface{}{
			"command": "update",
			"node":    updateNode,
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeSetStateCmd = &cobra.Command{
	Use:   "set-state [node-id] [state]",
	Short: "Set node state (online, offline, compromised, suspended)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "set-state",
			"node_id": args[0],
			"state":   args[1],
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a node from KDC",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid")
		nodeid := cmd.Flag("nodeid").Value.String()

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "delete",
			"node_id": nodeid,
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Zone service command
var kdcZoneServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Change the service for a zone",
	Long:  `Change which service a zone belongs to. The zone will be reassigned to an appropriate component in the new service based on its current signing mode.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename", "service")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		zoneName := cmd.Flag("zone").Value.String()
		serviceName := cmd.Flag("service").Value.String()

		req := map[string]interface{}{
			"command":     "set-service",
			"zone_name":   zoneName,
			"service_name": serviceName,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Zone catalog command
var KdcZoneCatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Manage catalog zone",
	Long:  `Commands for generating and managing the catalog zone used for automatic zone configuration on edge nodes.`,
}

var kdcZoneCatalogGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate catalog zone from zone/service/component data",
	Long: `Generate a catalog zone that lists all zones managed by the KDC with their component groups.
The catalog zone is registered with the DnsEngine and can be served via zone transfers (AXFR/IXFR).

Each zone in the catalog includes:
- NS record mapping a unique identifier to the actual zone name
- TXT records with "group={component_id}" for each component in the zone's service

The catalog zone name must be configured in the KDC config file as 'kdc.catalog_zone'.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Call API to generate catalog zone (must be done in daemon process)
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "generate",
		}

		resp, err := sendKdcRequest(api, "/kdc/catalog", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		catalogZoneName := getString(resp, "zone_name")
		serial := getInt(resp, "serial")
		msg := getString(resp, "msg")

		if msg != "" {
			fmt.Printf("%s\n", msg)
		} else {
			fmt.Printf("✓ Catalog zone '%s' generated successfully\n", catalogZoneName)
		}
		if serial > 0 {
			fmt.Printf("  Serial: %d\n", serial)
		}
		fmt.Printf("  Registered with DnsEngine: ready to serve via zone transfers\n")
	},
}

// Zone component command
var kdcZoneComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Change the component (and signing mode) for a zone",
	Long:  `Change which component a zone is assigned to. This directly changes the zone's signing mode, as signing mode is derived from component assignment.

Available components:
  - sign_upstream: Upstream signed zones (no key distribution)
  - sign_kdc: Centrally signed zones (no key distribution, default)
  - sign_unsigned: Unsigned zones
  - sign_edge_dyn: Edgesigned zones (dynamic responses only)
  - sign_edge_zsk: Edgesigned zones (all responses)
  - sign_edge_full: Fully edgesigned zones (KSK+ZSK)`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename", "component")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		zoneName := cmd.Flag("zone").Value.String()
		componentName := cmd.Flag("component").Value.String()

		req := map[string]interface{}{
			"command":        "set-component",
			"zone_name":      zoneName,
			"component_name": componentName,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Service commands
var kdcServiceAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new service",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		serviceName := cmd.Flag("name").Value.String()
		if serviceName == "" {
			log.Fatalf("Error: --name is required")
		}

		serviceID := cmd.Flag("sid").Value.String()
		if serviceID == "" {
			log.Fatalf("Error: --sid is required")
		}

		comment := cmd.Flag("comment").Value.String()

		req := map[string]interface{}{
			"command": "add",
			"service": map[string]interface{}{
				"id":      serviceID,
				"name":    serviceName,
				"active":  true,
				"comment": comment,
			},
		}

		resp, err := sendKdcRequest(api, "/kdc/service", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all services",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/service", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		servicesRaw, ok := resp["services"]
		if !ok {
			fmt.Println("No services found")
			return
		}

		services, ok := servicesRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: 'services' is not an array")
		}

		if len(services) == 0 {
			fmt.Println("No services configured")
			return
		}

		// Always show components column
		fmt.Printf("%-30s %-30s %-8s %-50s %s\n", "ID", "Name", "Active", "Components", "Comment")
		fmt.Println(strings.Repeat("-", 150))

		for _, s := range services {
			service, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			id := getString(service, "id")
			name := getString(service, "name")
			active := getBool(service, "active")
			comment := getString(service, "comment")
			activeStr := "yes"
			if !active {
				activeStr = "no"
			}
			
			// Always fetch and show components for this service
			componentsReq := map[string]interface{}{
				"command":      "list",
				"service_name": id, // Use ID to look up components
			}
			componentsResp, err := sendKdcRequest(api, "/kdc/service-component", componentsReq)
			componentsList := ""
			if err == nil && componentsResp["error"] != true {
				if assignmentsRaw, ok := componentsResp["assignments"]; ok {
					if assignments, ok := assignmentsRaw.([]interface{}); ok {
						componentIDs := make([]string, 0, len(assignments))
						for _, a := range assignments {
							if assignment, ok := a.(map[string]interface{}); ok {
								compID := getString(assignment, "component_id")
								if compID != "" {
									componentIDs = append(componentIDs, compID)
								}
							}
						}
						if len(componentIDs) > 0 {
							componentsList = strings.Join(componentIDs, ", ")
						} else {
							componentsList = "(none)"
						}
					}
				}
			}
			if componentsList == "" {
				componentsList = "(error fetching)"
			}
			fmt.Printf("%-30s %-30s %-8s %-50s %s\n", id, name, activeStr, componentsList, comment)
		}
	},
}

var kdcServiceDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a service",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		serviceID := cmd.Flag("sid").Value.String()
		if serviceID == "" {
			log.Fatalf("Error: --sid is required")
		}

		req := map[string]interface{}{
			"command":    "delete",
			"service_id": serviceID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceComponentsCmd = &cobra.Command{
	Use:   "components",
	Short: "List components for a service",
	Long:  `List all components that are assigned to a specific service`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		serviceName := cmd.Flag("name").Value.String()
		if serviceName == "" {
			log.Fatalf("Error: --name is required")
		}

		req := map[string]interface{}{
			"command":      "list",
			"service_name": serviceName,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		assignmentsRaw, ok := resp["assignments"]
		if !ok {
			fmt.Printf("Service %s has no components assigned\n", serviceName)
			return
		}

		assignments, ok := assignmentsRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: 'assignments' is not an array")
		}

		if len(assignments) == 0 {
			fmt.Printf("Service %s has no components assigned\n", serviceName)
			return
		}

		fmt.Printf("Components for service %s:\n", serviceName)
		fmt.Printf("%-30s %-8s\n", "Component ID", "Active")
		fmt.Println(strings.Repeat("-", 50))

		for _, a := range assignments {
			assignment, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			componentID := getString(assignment, "component_id")
			active := getBool(assignment, "active")
			activeStr := "yes"
			if !active {
				activeStr = "no"
			}
			fmt.Printf("%-30s %-8s\n", componentID, activeStr)
		}
	},
}

// Component commands
var kdcComponentAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new component",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		componentName := cmd.Flag("name").Value.String()
		if componentName == "" {
			log.Fatalf("Error: --name is required")
		}

		componentID := cmd.Flag("cid").Value.String()
		if componentID == "" {
			log.Fatalf("Error: --cid is required")
		}

		comment := cmd.Flag("comment").Value.String()

		req := map[string]interface{}{
			"command": "add",
			"component": map[string]interface{}{
				"id":      componentID,
				"name":    componentName,
				"active":  true,
				"comment": comment,
			},
		}

		resp, err := sendKdcRequest(api, "/kdc/component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcComponentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all components",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		componentsRaw, ok := resp["components"]
		if !ok {
			fmt.Println("No components found")
			return
		}

		components, ok := componentsRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: 'components' is not an array")
		}

		if len(components) == 0 {
			fmt.Println("No components configured")
			return
		}

		// Build table rows for columnize
		var lines []string
		lines = append(lines, "ID | Name | Active | Comment")

		for _, c := range components {
			component, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			id := getString(component, "id")
			name := getString(component, "name")
			active := getBool(component, "active")
			comment := getString(component, "comment")
			activeStr := "yes"
			if !active {
				activeStr = "no"
			}
			lines = append(lines, fmt.Sprintf("%s | %s | %s | %s", id, name, activeStr, comment))
		}

		fmt.Println(columnize.SimpleFormat(lines))
	},
}

var kdcComponentDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a component",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		componentID := cmd.Flag("cid").Value.String()
		if componentID == "" {
			log.Fatalf("Error: --cid is required")
		}

		req := map[string]interface{}{
			"command":      "delete",
			"component_id": componentID,
		}

		resp, err := sendKdcRequest(api, "/kdc/component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Service-component commands
var kdcServiceComponentAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Assign a component to a service",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "sname", "cname")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		serviceName := cmd.Flag("sname").Value.String()
		componentName := cmd.Flag("cname").Value.String()

		req := map[string]interface{}{
			"command":        "add",
			"service_name":   serviceName,
			"component_name": componentName,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceComponentDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Remove a component from a service",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "sname", "cname")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		serviceName := cmd.Flag("sname").Value.String()
		componentName := cmd.Flag("cname").Value.String()

		req := map[string]interface{}{
			"command":        "delete",
			"service_name":   serviceName,
			"component_name": componentName,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceComponentReplaceCmd = &cobra.Command{
	Use:   "replace",
	Short: "Atomically replace one component with another in a service",
	Long:  `Atomically replaces one component with another in a service. This ensures there's never a state with no signing component when replacing sign_* components. The operation is atomic: if adding the new component fails, the old one remains.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "sname")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		serviceName := cmd.Flag("sname").Value.String()
		oldComponentName := cmd.Flag("old").Value.String()
		newComponentName := cmd.Flag("new").Value.String()

		if oldComponentName == "" || newComponentName == "" {
			log.Fatalf("Error: --old and --new are required")
		}

		req := map[string]interface{}{
			"command":           "replace",
			"service_name":      serviceName,
			"old_component_name": oldComponentName,
			"new_component_name": newComponentName,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Service transaction commands
var kdcServiceTxStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a new service modification transaction",
	Long:  `Creates a new transaction for modifying a service. Returns a transaction token that can be used for subsequent operations.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		serviceID := cmd.Flag("sid").Value.String()
		if serviceID == "" {
			log.Fatalf("Error: --sid is required")
		}
		createdBy := cmd.Flag("created-by").Value.String()
		comment := cmd.Flag("comment").Value.String()

		req := map[string]interface{}{
			"command":    "start",
			"service_id": serviceID,
		}
		if createdBy != "" {
			req["created_by"] = createdBy
		}
		if comment != "" {
			req["comment"] = comment
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		txID := getString(resp, "tx_id")
		if txID != "" {
			fmt.Printf("Transaction started: %s\n", txID)
			fmt.Printf("%s\n", resp["msg"])
		} else {
			fmt.Printf("%s\n", resp["msg"])
		}
	},
}

var kdcServiceTxComponentAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a component to a transaction",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		txID := cmd.Flag("tx").Value.String()
		componentID := cmd.Flag("cid").Value.String()
		if componentID == "" {
			log.Fatalf("Error: --cid is required")
		}

		req := map[string]interface{}{
			"command":      "add-component",
			"tx_id":        txID,
			"component_id": componentID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceTxComponentDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Remove a component from a transaction",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		txID := cmd.Flag("tx").Value.String()
		componentID := cmd.Flag("cid").Value.String()
		if componentID == "" {
			log.Fatalf("Error: --cid is required")
		}

		req := map[string]interface{}{
			"command":      "remove-component",
			"tx_id":        txID,
			"component_id": componentID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceTxViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View the impact of a transaction (dry-run)",
	Long:  `Computes and displays what changes would result from committing the transaction, without actually applying them.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		txID := cmd.Flag("tx").Value.String()

		req := map[string]interface{}{
			"command": "view",
			"tx_id":   txID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		// Display delta report
		if deltaReportRaw, ok := resp["delta_report"]; ok {
			if deltaReport, ok := deltaReportRaw.(map[string]interface{}); ok {
				fmt.Printf("Transaction: %s\n", txID)
				fmt.Printf("Service: %s\n\n", getString(deltaReport, "service_id"))
				
				// Show component changes
				fmt.Printf("Component Changes:\n")
				
				// Original components
				if originalComps, ok := deltaReport["original_components"].([]interface{}); ok {
					compStrs := make([]string, len(originalComps))
					for i, c := range originalComps {
						compStrs[i] = fmt.Sprintf("%v", c)
					}
					if len(compStrs) == 0 {
						fmt.Printf("  Original: (none)\n")
					} else {
						fmt.Printf("  Original: %s\n", strings.Join(compStrs, ", "))
					}
				}
				
				// Updated components
				if updatedComps, ok := deltaReport["updated_components"].([]interface{}); ok {
					compStrs := make([]string, len(updatedComps))
					for i, c := range updatedComps {
						compStrs[i] = fmt.Sprintf("%v", c)
					}
					if len(compStrs) == 0 {
						fmt.Printf("  Updated:  (none)\n")
					} else {
						fmt.Printf("  Updated:  %s\n", strings.Join(compStrs, ", "))
					}
				}
				
				// Delta
				addedComps := []string{}
				if added, ok := deltaReport["added_components"].([]interface{}); ok {
					for _, c := range added {
						addedComps = append(addedComps, fmt.Sprintf("%v", c))
					}
				}
				removedComps := []string{}
				if removed, ok := deltaReport["removed_components"].([]interface{}); ok {
					for _, c := range removed {
						removedComps = append(removedComps, fmt.Sprintf("%v", c))
					}
				}
				
				if len(addedComps) > 0 || len(removedComps) > 0 {
					fmt.Printf("  Delta:\n")
					if len(addedComps) > 0 {
						fmt.Printf("    + Add:    %s\n", strings.Join(addedComps, ", "))
					}
					if len(removedComps) > 0 {
						fmt.Printf("    - Remove: %s\n", strings.Join(removedComps, ", "))
					}
				} else {
					fmt.Printf("  Delta: (no changes)\n")
				}
				
				// Service validation
				fmt.Printf("\nService Validation:\n")
				isValid := getBool(deltaReport, "is_valid")
				if isValid {
					fmt.Printf("  Status: ✓ Valid (has exactly one signing component)\n")
				} else {
					fmt.Printf("  Status: ✗ Invalid\n")
					if validationErrors, ok := deltaReport["validation_errors"].([]interface{}); ok {
						for _, errMsg := range validationErrors {
							fmt.Printf("    Error: %v\n", errMsg)
						}
					}
				}
				
				fmt.Printf("\nImpact Analysis:\n")
				
				// Summary
				if summary, ok := deltaReport["summary"].(map[string]interface{}); ok {
					totalAffected := getInt(summary, "total_zones_affected")
					newlyServed := getInt(summary, "zones_newly_served")
					noLongerServed := getInt(summary, "zones_no_longer_served")
					
					fmt.Printf("  Zones affected: %d\n", totalAffected)
					fmt.Printf("    - Zones newly served: %d\n", newlyServed)
					fmt.Printf("    - Zones no longer served: %d\n", noLongerServed)
					fmt.Printf("  Distributions to create: %v\n", getString(summary, "distributions_to_create"))
					fmt.Printf("  Distributions to revoke: %v\n", getString(summary, "distributions_to_revoke"))
					fmt.Printf("  Total nodes affected: %v\n", getString(summary, "total_nodes_affected"))
					
					// Show warning if no zones affected but service has zones
					if totalAffected == 0 {
						fmt.Printf("\n  Note: No zones are affected by this transaction.\n")
						fmt.Printf("        This may mean:\n")
						fmt.Printf("        - No zones are assigned to this service, OR\n")
						fmt.Printf("        - All nodes already serve other components of this service, OR\n")
						fmt.Printf("        - No nodes serve the components being added/removed\n")
					}
				}
				
				// Zones newly served
				if newlyServed, ok := deltaReport["zones_newly_served"].(map[string]interface{}); ok && len(newlyServed) > 0 {
					fmt.Printf("\nZones newly served:\n")
					for zoneName, nodesRaw := range newlyServed {
						if nodes, ok := nodesRaw.([]interface{}); ok {
							nodeStrs := make([]string, len(nodes))
							for i, n := range nodes {
								nodeStrs[i] = fmt.Sprintf("%v", n)
							}
							fmt.Printf("  - %s → nodes: %s\n", zoneName, strings.Join(nodeStrs, ", "))
						}
					}
				}
				
				// Zones no longer served
				if noLongerServed, ok := deltaReport["zones_no_longer_served"].(map[string]interface{}); ok && len(noLongerServed) > 0 {
					fmt.Printf("\nZones no longer served:\n")
					for zoneName, nodesRaw := range noLongerServed {
						if nodes, ok := nodesRaw.([]interface{}); ok {
							nodeStrs := make([]string, len(nodes))
							for i, n := range nodes {
								nodeStrs[i] = fmt.Sprintf("%v", n)
							}
							fmt.Printf("  - %s → nodes: %s\n", zoneName, strings.Join(nodeStrs, ", "))
						}
					}
				}
			}
		} else {
			fmt.Printf("%s\n", resp["msg"])
		}
	},
}

var kdcServiceTxCommitCmd = &cobra.Command{
	Use:   "commit",
	Short: "Commit a transaction (apply changes)",
	Long:  `Applies all pending changes in the transaction and creates key distributions. Use --dry-run to preview without applying.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		txID := cmd.Flag("tx").Value.String()
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		req := map[string]interface{}{
			"command": "commit",
			"tx_id":   txID,
			"dry_run": dryRun,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		
		// If dry-run, show delta report
		if dryRun {
			if deltaReportRaw, ok := resp["delta_report"]; ok {
				if deltaReport, ok := deltaReportRaw.(map[string]interface{}); ok {
					if summary, ok := deltaReport["summary"].(map[string]interface{}); ok {
						fmt.Printf("\nSummary:\n")
						fmt.Printf("  Zones affected: %v\n", getString(summary, "total_zones_affected"))
						fmt.Printf("  Distributions to create: %v\n", getString(summary, "distributions_to_create"))
					}
				}
			}
		}
	},
}

var kdcServiceTxRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Rollback a transaction (cancel changes)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		txID := cmd.Flag("tx").Value.String()

		req := map[string]interface{}{
			"command": "rollback",
			"tx_id":   txID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceTxStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show transaction status and details",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		txID := cmd.Flag("tx").Value.String()

		req := map[string]interface{}{
			"command": "get",
			"tx_id":   txID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if tx, ok := resp["transaction"].(map[string]interface{}); ok {
			fmt.Printf("Transaction: %s\n", getString(tx, "id"))
			fmt.Printf("Service: %s\n", getString(tx, "service_id"))
			fmt.Printf("State: %s\n", getString(tx, "state"))
			fmt.Printf("Created: %s\n", getString(tx, "created_at"))
			fmt.Printf("Expires: %s\n", getString(tx, "expires_at"))
			if comment := getString(tx, "comment"); comment != "" {
				fmt.Printf("Comment: %s\n", comment)
			}
			
			if changes, ok := tx["changes"].(map[string]interface{}); ok {
				fmt.Printf("\nPending Changes:\n")
				if addComps, ok := changes["add_components"].([]interface{}); ok && len(addComps) > 0 {
					compStrs := make([]string, len(addComps))
					for i, c := range addComps {
						compStrs[i] = fmt.Sprintf("%v", c)
					}
					fmt.Printf("  + Add: %s\n", strings.Join(compStrs, ", "))
				}
				if removeComps, ok := changes["remove_components"].([]interface{}); ok && len(removeComps) > 0 {
					compStrs := make([]string, len(removeComps))
					for i, c := range removeComps {
						compStrs[i] = fmt.Sprintf("%v", c)
					}
					fmt.Printf("  - Remove: %s\n", strings.Join(compStrs, ", "))
				}
				if addComps, ok := changes["add_components"].([]interface{}); ok && len(addComps) == 0 {
					if removeComps, ok := changes["remove_components"].([]interface{}); ok && len(removeComps) == 0 {
						fmt.Printf("  (no changes)\n")
					}
				}
			}
		} else {
			fmt.Printf("%s\n", resp["msg"])
		}
	},
}

var kdcServiceTxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all transactions",
	Long:  `Lists all service modification transactions. Use --state to filter by state (open, committed, rolled_back).`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		stateFilter, _ := cmd.Flags().GetString("state")

		req := map[string]interface{}{
			"command": "list",
		}
		if stateFilter != "" {
			req["state_filter"] = stateFilter
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if transactionsRaw, ok := resp["transactions"]; ok {
			if transactions, ok := transactionsRaw.([]interface{}); ok {
				if len(transactions) == 0 {
					fmt.Printf("No transactions found\n")
					return
				}
				
				fmt.Printf("%-20s %-30s %-12s %-20s %s\n", "Transaction ID", "Service", "State", "Created", "Expires")
				fmt.Println(strings.Repeat("-", 120))
				
				for _, txRaw := range transactions {
					if tx, ok := txRaw.(map[string]interface{}); ok {
						txID := getString(tx, "id")
						serviceID := getString(tx, "service_id")
						state := getString(tx, "state")
						createdAt := getString(tx, "created_at")
						expiresAt := getString(tx, "expires_at")
						
						// Parse and format dates
						if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
							createdAt = t.Format("2006-01-02 15:04:05")
						}
						if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
							expiresAt = t.Format("2006-01-02 15:04:05")
						}
						
						fmt.Printf("%-20s %-30s %-12s %-20s %s\n", txID, serviceID, state, createdAt, expiresAt)
					}
				}
			}
		} else {
			fmt.Printf("%s\n", resp["msg"])
		}
	},
}

var kdcServiceTxCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Cleanup expired transactions",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		req := map[string]interface{}{
			"command": "cleanup",
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceTxComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage components in a transaction",
}

// Node-component commands
var kdcNodeComponentAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Assign a component to a node",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid", "cname")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		// Get nodeid from persistent flag (normalized by PrepArgs)
		nodeID := cmd.Flag("nodeid").Value.String()
		componentName := cmd.Flag("cname").Value.String()

		req := map[string]interface{}{
			"command":        "add",
			"node_id":        nodeID,
			"component_name": componentName,
		}

		resp, err := sendKdcRequest(api, "/kdc/node-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeComponentDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Remove a component from a node",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid", "cname")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		// Get nodeid from persistent flag (normalized by PrepArgs)
		nodeID := cmd.Flag("nodeid").Value.String()
		componentName := cmd.Flag("cname").Value.String()

		req := map[string]interface{}{
			"command":        "delete",
			"node_id":        nodeID,
			"component_name": componentName,
		}

		resp, err := sendKdcRequest(api, "/kdc/node-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeComponentListCmd = &cobra.Command{
	Use:   "list [--nodeid <node-id>]",
	Short: "List node-component assignments",
	Long:  `List all node-component assignments. If --nodeid is provided, shows components for that node only. Otherwise, shows all nodes and their assigned components.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		req := map[string]interface{}{
			"command": "list",
		}

		// Check if nodeid is provided (optional)
		nodeIDFlag := cmd.Flag("nodeid")
		if nodeIDFlag != nil && nodeIDFlag.Value.String() != "" {
			PrepArgs(cmd, "nodeid")
			nodeID := cmd.Flag("nodeid").Value.String()
			req["node_id"] = nodeID
		}

		resp, err := sendKdcRequest(api, "/kdc/node-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		assignmentsRaw, ok := resp["assignments"]
		if !ok {
			if nodeIDFlag != nil && nodeIDFlag.Value.String() != "" {
				fmt.Printf("Node %s has no components assigned\n", nodeIDFlag.Value.String())
			} else {
				fmt.Printf("No node-component assignments found\n")
			}
			return
		}

		assignments, ok := assignmentsRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: 'assignments' is not an array")
		}

		if len(assignments) == 0 {
			if nodeIDFlag != nil && nodeIDFlag.Value.String() != "" {
				fmt.Printf("Node %s has no components assigned\n", nodeIDFlag.Value.String())
			} else {
				fmt.Printf("No node-component assignments found\n")
			}
			return
		}

		// Group assignments by node
		nodeAssignments := make(map[string][]string)
		for _, a := range assignments {
			assignment, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			nodeID := getString(assignment, "node_id")
			componentID := getString(assignment, "component_id")
			if nodeID != "" && componentID != "" {
				nodeAssignments[nodeID] = append(nodeAssignments[nodeID], componentID)
			}
		}

		if nodeIDFlag != nil && nodeIDFlag.Value.String() != "" {
			// Single node: show detailed component list
			nodeID := nodeIDFlag.Value.String()
			fmt.Printf("Components for node %s:\n", nodeID)
			fmt.Printf("%-30s %-8s\n", "Component ID", "Active")
			fmt.Println(strings.Repeat("-", 50))
			for _, a := range assignments {
				assignment, ok := a.(map[string]interface{})
				if !ok {
					continue
				}
				componentID := getString(assignment, "component_id")
				active := getBool(assignment, "active")
				activeStr := "yes"
				if !active {
					activeStr = "no"
				}
				fmt.Printf("%-30s %-8s\n", componentID, activeStr)
			}
		} else {
			// All nodes: show one line per node with components
			fmt.Printf("%-30s %s\n", "Node ID", "Components")
			fmt.Println(strings.Repeat("-", 80))
			
			// Sort nodes for consistent output
			var nodeIDs []string
			for nodeID := range nodeAssignments {
				nodeIDs = append(nodeIDs, nodeID)
			}
			sort.Strings(nodeIDs)
			
			for _, nodeID := range nodeIDs {
				components := nodeAssignments[nodeID]
				componentsStr := strings.Join(components, ", ")
				if componentsStr == "" {
					componentsStr = "(none)"
				}
				fmt.Printf("%-30s %s\n", nodeID, componentsStr)
			}
		}
	},
}

var KdcDebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug utilities for KDC",
}

var KdcDebugDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage test distributions",
	Long:  `Commands for creating, listing, and deleting test distributions.`,
}

var kdcDebugDistribGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Create a test distribution with clear_text or encrypted_text content",
	Long:  `Creates a persistent test distribution that can be queried by KRS. The distribution will contain text read from a file (or default lorem ipsum if no file specified) that will be chunked and distributed. Use --content-type to choose 'clear_text' (default) or 'encrypted_text' (HPKE encrypted).`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid", "distid")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}
		// Removed getCommandContext - no longer needed

		distributionID := cmd.Flag("distid").Value.String()
		nodeIDFQDN := cmd.Flag("nodeid").Value.String()
		testTextFile := cmd.Flag("file").Value.String()

		var testText string
		if testTextFile != "" {
			// Read from file
			data, err := os.ReadFile(testTextFile)
			if err != nil {
				log.Fatalf("Error reading file %s: %v", testTextFile, err)
			}
			testText = string(data)
		}

		contentType := cmd.Flag("content-type").Value.String()
		if contentType == "" {
			contentType = "clear_text" // Default
		}
		if contentType != "clear_text" && contentType != "encrypted_text" {
			log.Fatalf("Error: --content-type must be 'clear_text' or 'encrypted_text' (got: %s)", contentType)
		}

		req := map[string]interface{}{
			"command":        "test-distribution",
			"distribution_id": distributionID,
			"node_id":        nodeIDFQDN,
			"content_type":   contentType,
		}
		if testText != "" {
			req["test_text"] = testText
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("Test distribution created successfully\n")
		fmt.Printf("  Distribution ID: %s\n", resp["distribution_id"])
		fmt.Printf("  Node ID: %s\n", nodeIDFQDN)
		if chunkCount, ok := resp["chunk_count"].(float64); ok {
			fmt.Printf("  Chunk count: %.0f\n", chunkCount)
		}
		fmt.Printf("  Message: %s\n", resp["msg"])
	},
}

var kdcDebugDistribListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all distribution IDs",
	Long:  `Lists all distribution IDs (both test and real) currently stored in the KDC.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list-distributions",
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		
		// Try to get distribution_infos first (new format with node info)
		if distInfosRaw, ok := resp["distribution_infos"].([]interface{}); ok {
			if len(distInfosRaw) > 0 {
				fmt.Printf("\nDistribution IDs:\n")
				for _, distInfoRaw := range distInfosRaw {
					if distInfo, ok := distInfoRaw.(map[string]interface{}); ok {
						distID, _ := distInfo["distribution_id"].(string)
						nodesRaw, _ := distInfo["nodes"].([]interface{})
						nodes := make([]string, 0, len(nodesRaw))
						for _, nodeRaw := range nodesRaw {
							if node, ok := nodeRaw.(string); ok {
								nodes = append(nodes, node)
							}
						}
						if len(nodes) > 0 {
							fmt.Printf("  - %s (applies to nodes %s)\n", distID, strings.Join(nodes, ", "))
						} else {
							fmt.Printf("  - %s\n", distID)
						}
					}
				}
			}
		} else if distributions, ok := resp["distributions"].([]interface{}); ok {
			// Fallback to old format (backward compatibility)
			if len(distributions) > 0 {
				fmt.Printf("\nDistribution IDs:\n")
				for _, distID := range distributions {
					if id, ok := distID.(string); ok {
						fmt.Printf("  - %s\n", id)
					}
				}
			}
		}
	},
}

var kdcDebugDistribDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a distribution by ID",
	Long:  `Deletes a distribution (both from database and cache) by its distribution ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "distid")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		distributionID := cmd.Flag("distid").Value.String()

		req := map[string]interface{}{
			"command":        "delete-distribution",
			"distribution_id": distributionID,
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcDebugSetChunkSizeCmd = &cobra.Command{
	Use:   "set-chunk-size",
	Short: "Set the maximum chunk size for new distributions",
	Long:  `Sets the maximum chunk size (in bytes) for OLDCHUNK records. This only affects new distributions created after this change. Existing distributions are not affected.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		chunkSizeStr := cmd.Flag("size").Value.String()
		if chunkSizeStr == "" {
			log.Fatalf("Error: --size is required")
		}

		var chunkSize int
		if _, err := fmt.Sscanf(chunkSizeStr, "%d", &chunkSize); err != nil {
			log.Fatalf("Error: invalid chunk size: %v", err)
		}

		if chunkSize <= 0 {
			log.Fatalf("Error: chunk size must be greater than 0")
		}

		req := map[string]interface{}{
			"command":   "set-chunk-size",
			"chunk_size": chunkSize,
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		if size, ok := resp["chunk_size"].(float64); ok {
			fmt.Printf("  Current chunk size: %.0f bytes\n", size)
		}
	},
}

var kdcDebugGetChunkSizeCmd = &cobra.Command{
	Use:   "get-chunk-size",
	Short: "Get the current maximum chunk size",
	Long:  `Gets the current maximum chunk size (in bytes) for OLDCHUNK records.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get-chunk-size",
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		if size, ok := resp["chunk_size"].(float64); ok {
			fmt.Printf("  Current chunk size: %.0f bytes\n", size)
		}
	},
}

var kdcDebugHpkeEncryptCmd = &cobra.Command{
	Use:   "hpke-encrypt --zone <zone-id> --keyid <key-id> --nodeid <node-id> [--output <file>]",
	Short: "Test HPKE encryption of a DNSSEC key for a node",
	Long:  `Encrypts a DNSSEC key's private key material using HPKE with a node's long-term public key. This is a test/debug command.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		keyID := cmd.Flag("keyid").Value.String()
		nodeID := cmd.Flag("nodeid").Value.String()
		outputFile := cmd.Flag("output").Value.String()

		if keyID == "" {
			log.Fatalf("Error: --keyid is required")
		}
		if nodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}

		// Request encryption via API
		req := map[string]interface{}{
			"command": "encrypt-key",
			"zone_name": tdns.Globals.Zonename,
			"key_id":  keyID,
			"node_id": nodeID,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		// Extract encrypted data
		encryptedKeyRaw, ok := resp["encrypted_key"]
		if !ok {
			log.Fatalf("Error: 'encrypted_key' not found in response")
		}

		ephemeralPubKeyRaw, ok := resp["ephemeral_pub_key"]
		if !ok {
			log.Fatalf("Error: 'ephemeral_pub_key' not found in response")
		}

		distributionID := getString(resp, "distribution_id", "DistributionID")

		// Convert to []byte (assuming base64 encoding from JSON)
		var encryptedKey, ephemeralPubKey []byte
		if encStr, ok := encryptedKeyRaw.(string); ok {
			encryptedKey, err = base64.StdEncoding.DecodeString(encStr)
			if err != nil {
				log.Fatalf("Error decoding encrypted_key: %v", err)
			}
		} else if encBytes, ok := encryptedKeyRaw.([]byte); ok {
			encryptedKey = encBytes
		} else {
			log.Fatalf("Error: encrypted_key has unexpected type: %T", encryptedKeyRaw)
		}

		if ephemStr, ok := ephemeralPubKeyRaw.(string); ok {
			ephemeralPubKey, err = base64.StdEncoding.DecodeString(ephemStr)
			if err != nil {
				log.Fatalf("Error decoding ephemeral_pub_key: %v", err)
			}
		} else if ephemBytes, ok := ephemeralPubKeyRaw.([]byte); ok {
			ephemeralPubKey = ephemBytes
		} else {
			log.Fatalf("Error: ephemeral_pub_key has unexpected type: %T", ephemeralPubKeyRaw)
		}

		// Output results
		fmt.Printf("Encryption successful!\n")
		fmt.Printf("Distribution ID: %s\n", distributionID)
		fmt.Printf("Encrypted key size: %d bytes\n", len(encryptedKey))
		fmt.Printf("Ephemeral public key size: %d bytes\n", len(ephemeralPubKey))
		fmt.Printf("Ephemeral public key (hex): %x\n", ephemeralPubKey)

		if outputFile != "" {
			// Write encrypted key to file
			output := fmt.Sprintf("# HPKE-encrypted DNSSEC key\n")
			output += fmt.Sprintf("# Distribution ID: %s\n", distributionID)
			output += fmt.Sprintf("# Zone: %s\n", tdns.Globals.Zonename)
			output += fmt.Sprintf("# Key ID: %s\n", keyID)
			output += fmt.Sprintf("# Node ID: %s\n", nodeID)
			output += fmt.Sprintf("# Encrypted at: %s\n", time.Now().Format(time.RFC3339))
			output += fmt.Sprintf("# Ephemeral public key (hex): %x\n", ephemeralPubKey)
			output += fmt.Sprintf("# Encrypted key (base64):\n")
			output += base64.StdEncoding.EncodeToString(encryptedKey) + "\n"

			if err := os.WriteFile(outputFile, []byte(output), 0600); err != nil {
				log.Fatalf("Error writing output file: %v", err)
			}
			fmt.Printf("\nEncrypted key written to: %s\n", outputFile)
		}
	},
}

var kdcDebugHpkeGenerateCmd = &cobra.Command{
	Use:   "hpke-generate [prefix]",
	Short: "Generate an HPKE keypair for testing",
	Long:  `Generates an HPKE keypair and writes the public key to {prefix}.publickey and private key to {prefix}.privatekey (both hex encoded).`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefix := args[0]
		pubKeyFile := prefix + ".publickey"
		privKeyFile := prefix + ".privatekey"
		
		// Generate HPKE keypair
		pubKey, privKey, err := hpke.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Error generating HPKE keypair: %v", err)
		}

		// Format keys as hex
		pubKeyHex := fmt.Sprintf("%x", pubKey)
		privKeyHex := fmt.Sprintf("%x", privKey)

		// Create public key file with comments
		pubKeyContent := fmt.Sprintf(`# HPKE Public Key (X25519)
# Generated: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
# 
# This is the public key for HPKE (Hybrid Public Key Encryption).
# It can be safely shared and used to encrypt data for the holder of the corresponding private key.
#
%s
`, time.Now().Format(time.RFC3339), pubKeyHex)

		// Create private key file with comments
		privKeyContent := fmt.Sprintf(`# HPKE Private Key (X25519)
# Generated: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
# 
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone. Anyone with access to this key can decrypt
# data encrypted with the corresponding public key.
#
%s
`, time.Now().Format(time.RFC3339), privKeyHex)

		// Write public key file (readable by owner and group, not others)
		if err := os.WriteFile(pubKeyFile, []byte(pubKeyContent), 0644); err != nil {
			log.Fatalf("Error writing public key to file: %v", err)
		}

		// Write private key file (readable only by owner)
		if err := os.WriteFile(privKeyFile, []byte(privKeyContent), 0600); err != nil {
			log.Fatalf("Error writing private key to file: %v", err)
		}

		fmt.Printf("HPKE keypair generated successfully:\n")
		fmt.Printf("  Public key:  %s\n", pubKeyFile)
		fmt.Printf("  Private key: %s\n", privKeyFile)
		fmt.Printf("\nTo add this as a node, use:\n")
		fmt.Printf("  tdns-cli kdc node add --nodeid <node-id> --nodename <node-name> --pubkeyfile %s\n", pubKeyFile)
	},
}

var kdcDebugHpkeDecryptCmd = &cobra.Command{
	Use:   "hpke-decrypt --encrypted-file <file> --private-key-file <file>",
	Short: "Test HPKE decryption of an encrypted DNSSEC key",
	Long:  `Decrypts an HPKE-encrypted DNSSEC key file using a node's private key. This is a test/debug command.`,
	Run: func(cmd *cobra.Command, args []string) {
		encryptedFile := cmd.Flag("encrypted-file").Value.String()
		privateKeyFile := cmd.Flag("private-key-file").Value.String()

		if encryptedFile == "" {
			log.Fatalf("Error: --encrypted-file is required")
		}
		if privateKeyFile == "" {
			log.Fatalf("Error: --private-key-file is required")
		}

		// Read encrypted key file
		encryptedData, err := os.ReadFile(encryptedFile)
		if err != nil {
			log.Fatalf("Error reading encrypted file: %v", err)
		}

		// Parse the encrypted file (it has comments and base64 data)
		lines := strings.Split(string(encryptedData), "\n")
		var encryptedKeyBase64 string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "Encrypted key (base64):") {
				// The base64 data should be on the next line
				continue
			} else if len(line) > 50 {
				// Likely the base64 encrypted key
				encryptedKeyBase64 = line
			}
		}

		if encryptedKeyBase64 == "" {
			log.Fatalf("Error: could not find encrypted key in file")
		}

		// Decode base64 encrypted key
		encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyBase64)
		if err != nil {
			log.Fatalf("Error decoding base64 encrypted key: %v", err)
		}

		// Read private key file
		privateKeyData, err := os.ReadFile(privateKeyFile)
		if err != nil {
			log.Fatalf("Error reading private key file: %v", err)
		}

		// Parse private key (skip comments, decode hex)
		privKeyLines := strings.Split(string(privateKeyData), "\n")
		var privKeyHex string
		for _, line := range privKeyLines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				privKeyHex += line
			}
		}

		if privKeyHex == "" {
			log.Fatalf("Error: could not find private key in file")
		}

		// Decode hex private key
		privateKey, err := hex.DecodeString(privKeyHex)
		if err != nil {
			log.Fatalf("Error decoding hex private key: %v", err)
		}

		if len(privateKey) != 32 {
			log.Fatalf("Error: private key must be 32 bytes (got %d)", len(privateKey))
		}

		// Decrypt using HPKE
		// Note: HPKE Base mode extracts ephemeral key from ciphertext, so we don't need ephemeralPubKeyHex
		plaintext, err := hpke.Decrypt(privateKey, nil, encryptedKey)
		if err != nil {
			log.Fatalf("Error decrypting: %v", err)
		}

		fmt.Printf("Decryption successful!\n")
		fmt.Printf("Decrypted key size: %d bytes\n", len(plaintext))
		fmt.Printf("\nDecrypted private key (PEM format):\n")
		fmt.Printf("%s\n", string(plaintext))
	},
}

var kdcZoneDnssecGenerateCmd = &cobra.Command{
	Use:   "generate --zone <zone-id> --type <KSK|ZSK|CSK> [--algorithm <alg>] [--comment <comment>]",
	Short: "Generate a DNSSEC key for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		keyType := cmd.Flag("type").Value.String()
		if keyType == "" {
			keyType = "ZSK" // Default
		}
		if keyType != "KSK" && keyType != "ZSK" && keyType != "CSK" {
			log.Fatalf("Error: key type must be KSK, ZSK, or CSK (got: %s)", keyType)
		}

		algorithmStr := cmd.Flag("algorithm").Value.String()
		var algorithm uint8
		if algorithmStr != "" {
			var algNum int
			if _, err := fmt.Sscanf(algorithmStr, "%d", &algNum); err != nil {
				// Try to parse as algorithm name
				if algNumVal, ok := dns.StringToAlgorithm[strings.ToUpper(algorithmStr)]; ok {
					algorithm = algNumVal
				} else {
					log.Fatalf("Error: invalid algorithm: %s", algorithmStr)
				}
			} else {
				algorithm = uint8(algNum)
			}
		}
		// If algorithm is 0, API will use default (ED25519)

		req := map[string]interface{}{
			"command": "generate-key",
			"zone_name": tdns.Globals.Zonename,
			"key_type": keyType,
		}
		if algorithm != 0 {
			req["algorithm"] = algorithm
		}
		if comment := cmd.Flag("comment").Value.String(); comment != "" {
			req["comment"] = comment
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Config commands
var kdcConfigGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get KDC configuration",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
		}

		resp, err := sendKdcRequest(api, "/kdc/config", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		configRaw, ok := resp["config"]
		if !ok {
			fmt.Printf("Error: 'config' key not found in response\n")
			return
		}

		config, ok := configRaw.(map[string]interface{})
		if !ok {
			fmt.Printf("Error: 'config' is not an object (got %T)\n", configRaw)
			return
		}

		// Pretty print the config
		configJSON, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling config: %v\n", err)
			return
		}
		fmt.Printf("%s\n", string(configJSON))
	},
}

var kdcDistribSingleCmd = &cobra.Command{
	Use:   "single --zone <zone-id> --keyid <key-id>",
	Short: "Trigger distribution of a specific standby ZSK to all nodes",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename")
		zoneName := cmd.Flag("zone").Value.String()
		keyid := cmd.Flag("keyid").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "distrib-single",
			"zone_name": zoneName,
			"key_id":  keyid,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcDistribMultiCmd = &cobra.Command{
	Use:   "multi [zone1] [zone2] ...",
	Short: "Distribute standby ZSK keys for one or more zones (auto-selects standby keys)",
	Long:  `Distributes standby ZSK keys for the specified zones. For each zone, automatically selects a standby ZSK and distributes it to all active nodes.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Normalize zone names to FQDNs
		zones := make([]string, len(args))
		for i, zone := range args {
			zones[i] = dns.Fqdn(zone)
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "distrib-multi",
			"zones":   zones,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		// Always show the summary message
		if msg, ok := resp["msg"].(string); ok && msg != "" {
			fmt.Printf("%s\n", msg)
		}

		// Always display detailed results, even if there are errors
		if resultsRaw, ok := resp["results"]; ok {
			if results, ok := resultsRaw.([]interface{}); ok {
				if len(results) > 0 {
					fmt.Printf("\nDetailed results:\n")
				for _, result := range results {
					if resultMap, ok := result.(map[string]interface{}); ok {
						zoneID := getString(resultMap, "zone_name", "ZoneName")
						status := getString(resultMap, "status", "Status")
						msg := getString(resultMap, "msg", "Msg")
						if status == "success" {
							fmt.Printf("  ✓ %s: %s\n", zoneID, msg)
						} else {
							fmt.Printf("  ✗ %s: %s\n", zoneID, msg)
						}
					}
				}
				}
			}
		}

		// If there was an error and no successful distributions, exit with error
		if resp["error"] == true {
			if resultsRaw, ok := resp["results"]; ok {
				if results, ok := resultsRaw.([]interface{}); ok {
					hasSuccess := false
					for _, result := range results {
						if resultMap, ok := result.(map[string]interface{}); ok {
							if status := getString(resultMap, "status", "Status"); status == "success" {
								hasSuccess = true
								break
							}
						}
					}
					if !hasSuccess {
						if errorMsg, ok := resp["error_msg"].(string); ok {
							log.Fatalf("Error: %s", errorMsg)
						} else {
							log.Fatalf("Error: Failed to distribute keys for all zones")
						}
					}
				}
			} else {
				if errorMsg, ok := resp["error_msg"].(string); ok {
					log.Fatalf("Error: %s", errorMsg)
				} else {
					log.Fatalf("Error: Distribution failed")
				}
			}
		}
	},
}

var kdcZoneTransitionCmd = &cobra.Command{
	Use:   "transition --zone <zone-id> --keyid <key-id>",
	Short: "Transition a key state (created->published or standby->active, auto-detected)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		keyid := cmd.Flag("keyid").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "transition",
			"zone_name": tdns.Globals.Zonename,
			"key_id":  keyid,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcZoneDnssecHashCmd = &cobra.Command{
	Use:   "hash --zone <zone-id> --keyid <key-id>",
	Short: "Compute SHA-256 hash of a key's private key material",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		keyid := cmd.Flag("keyid").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "hash",
			"zone_name": tdns.Globals.Zonename,
			"key_id":  keyid,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		hash := getString(resp, "msg", "Msg")
		if hash == "" {
			log.Fatalf("Error: hash not found in response")
		}

		fmt.Printf("Key Hash (SHA-256): %s\n", hash)
	},
}

var kdcZoneDnssecDeleteCmd = &cobra.Command{
	Use:   "delete --zone <zone-id> --keyid <key-id>",
	Short: "Delete a DNSSEC key",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		keyid := cmd.Flag("keyid").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "delete-key",
			"zone_name": tdns.Globals.Zonename,
			"key_id":  keyid,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcZoneDnssecPurgeCmd = &cobra.Command{
	Use:   "purge [--zone <zone-id>] [--force]",
	Short: "Delete all DNSSEC keys in 'removed' state",
	Long:  `Delete all DNSSEC keys that are in the 'removed' state. If --zone is specified, only keys for that zone are purged. Otherwise, keys for all zones are purged. Use --force to also delete keys in 'distributed' state.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Zone is optional - if provided, normalize it
		zoneName := ""
		if tdns.Globals.Zonename != "" {
			zoneName = dns.Fqdn(tdns.Globals.Zonename)
		}

		// Check for --force flag
		force, _ := cmd.Flags().GetBool("force")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "purge-keys",
			"force":   force,
		}
		if zoneName != "" {
			req["zone_name"] = zoneName
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

func init() {
	kdcZoneDnssecPurgeCmd.Flags().Bool("force", false, "Also delete keys in 'distributed' state")
}

var kdcDistribListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all ongoing distributions",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		
		// Check for verbose flag
		verbose := false
		if v, err := cmd.Flags().GetBool("verbose"); err == nil {
			verbose = v
		}
		
		// Try to get summaries (new format)
		if summariesRaw, ok := resp["summaries"].([]interface{}); ok && len(summariesRaw) > 0 {
			if verbose {
				// Verbose mode: show full multiline information
				fmt.Println("\nDistributions:")
				for _, sRaw := range summariesRaw {
					if s, ok := sRaw.(map[string]interface{}); ok {
						distID := getString(s, "distribution_id")
						fmt.Printf("\n  Distribution ID: %s\n", distID)
						
						if nodes, ok := s["nodes"].([]interface{}); ok {
							nodeStrs := make([]string, len(nodes))
							for i, n := range nodes {
								nodeStrs[i] = fmt.Sprintf("%v", n)
							}
							fmt.Printf("    Nodes: %s\n", strings.Join(nodeStrs, ", "))
						}
						
						if zones, ok := s["zones"].([]interface{}); ok {
							zoneStrs := make([]string, len(zones))
							for i, z := range zones {
								zoneStrs[i] = fmt.Sprintf("%v", z)
							}
							fmt.Printf("    Zones: %s\n", strings.Join(zoneStrs, ", "))
						}
						
						zskCount := 0
						if z, ok := s["zsk_count"].(float64); ok {
							zskCount = int(z)
						}
						kskCount := 0
						if k, ok := s["ksk_count"].(float64); ok {
							kskCount = int(k)
						}
						fmt.Printf("    Keys: %d ZSK, %d KSK\n", zskCount, kskCount)
						
						if keys, ok := s["keys"].(map[string]interface{}); ok {
							fmt.Printf("    Key Details:\n")
							for zone, keyID := range keys {
								fmt.Printf("      %s: key %v\n", zone, keyID)
							}
						}
						
						if completedAt, ok := s["completed_at"].(string); ok && completedAt != "" {
							// Parse and format the datetime nicely
							if t, err := time.Parse(time.RFC3339, completedAt); err == nil {
								fmt.Printf("    Completed: %s\n", t.Format("2006-01-02 15:04:05"))
							} else {
								fmt.Printf("    Completed: %s\n", completedAt)
							}
						} else {
							allConfirmed := false
							if a, ok := s["all_confirmed"].(bool); ok {
								allConfirmed = a
							}
							if allConfirmed {
								fmt.Printf("    Status: All nodes confirmed\n")
							} else {
								// Show confirmed and pending nodes
								confirmedNodes := []string{}
								if c, ok := s["confirmed_nodes"].([]interface{}); ok {
									for _, n := range c {
										confirmedNodes = append(confirmedNodes, fmt.Sprintf("%v", n))
									}
								}
								pendingNodes := []string{}
								if p, ok := s["pending_nodes"].([]interface{}); ok {
									for _, n := range p {
										pendingNodes = append(pendingNodes, fmt.Sprintf("%v", n))
									}
								}
								
								if len(confirmedNodes) > 0 {
									fmt.Printf("    Confirmed nodes: %s\n", strings.Join(confirmedNodes, ", "))
								}
								if len(pendingNodes) > 0 {
									fmt.Printf("    Pending nodes: %s\n", strings.Join(pendingNodes, ", "))
								} else {
									fmt.Printf("    Status: Pending confirmations\n")
								}
							}
						}
					}
				}
			} else {
				// Default mode: show tabular format
				// Get control zone from config for building QNAMEs
				controlZone := "kdc." // Default
				configResp, configErr := sendKdcRequest(api, "/kdc/config", map[string]interface{}{"command": "get"})
				if configErr == nil {
					if config, ok := configResp["config"].(map[string]interface{}); ok {
						if cz, ok := config["control_zone"].(string); ok && cz != "" {
							controlZone = cz
							if !strings.HasSuffix(controlZone, ".") {
								controlZone = controlZone + "."
							}
						}
					}
				}
				
				var rows []string
				rows = append(rows, "Id | State | Time | Node | Contents | Query")
				
				for _, sRaw := range summariesRaw {
					if s, ok := sRaw.(map[string]interface{}); ok {
						distID := getString(s, "distribution_id")
						if distID == "" {
							continue
						}
						
						// Get node
						nodeStr := ""
						nodeIDForQuery := ""
						if nodes, ok := s["nodes"].([]interface{}); ok && len(nodes) > 0 {
							nodeList := make([]string, len(nodes))
							for i, n := range nodes {
								nodeList[i] = fmt.Sprintf("%v", n)
							}
							nodeStr = nodeList[0]
							nodeIDForQuery = nodeList[0]
							if len(nodeList) > 1 {
								nodeStr = fmt.Sprintf("%s (+%d)", nodeStr, len(nodeList)-1)
							}
						}
						
						// Build MANIFEST QNAME: <nodeid><distributionID>.<controlzone>
						queryStr := ""
						if nodeIDForQuery != "" && distID != "" {
							// Ensure node ID is FQDN (with trailing dot)
							nodeIDFQDN := nodeIDForQuery
							if !strings.HasSuffix(nodeIDFQDN, ".") {
								nodeIDFQDN = nodeIDFQDN + "."
							}
							// Ensure control zone has trailing dot
							controlZoneFQDN := controlZone
							if !strings.HasSuffix(controlZoneFQDN, ".") {
								controlZoneFQDN = controlZoneFQDN + "."
							}
							// QNAME format: <nodeid><distributionID>.<controlzone>
							// Remove trailing dot from control zone for concatenation, then add it back
							controlZoneClean := strings.TrimSuffix(controlZoneFQDN, ".")
							queryStr = fmt.Sprintf("%s%s.%s. MANIFEST", nodeIDFQDN, distID, controlZoneClean)
						}
						
						// Get state and time
						state := "ongoing"
						timeStr := ""
						if completedAt, ok := s["completed_at"].(string); ok && completedAt != "" {
							state = "completed"
							if t, err := time.Parse(time.RFC3339, completedAt); err == nil {
								timeStr = t.Format("2006-01-02 15:04:05")
							} else {
								timeStr = completedAt
							}
						} else {
							// Use creation time for ongoing distributions
							if createdAt, ok := s["created_at"].(string); ok && createdAt != "" {
								if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
									timeStr = t.Format("2006-01-02 15:04:05")
								} else {
									timeStr = createdAt
								}
							}
						}
						
						// Build contents string
						zskCount := 0
						if z, ok := s["zsk_count"].(float64); ok {
							zskCount = int(z)
						}
						kskCount := 0
						if k, ok := s["ksk_count"].(float64); ok {
							kskCount = int(k)
						}
						
						keyTypeStr := ""
						if zskCount > 0 && kskCount > 0 {
							keyTypeStr = fmt.Sprintf("%d ZSK and %d KSK", zskCount, kskCount)
						} else if zskCount > 0 {
							keyTypeStr = fmt.Sprintf("%d ZSK", zskCount)
						} else if kskCount > 0 {
							keyTypeStr = fmt.Sprintf("%d KSK", kskCount)
						}
						
						zoneStr := ""
						zoneCount := 0
						if zones, ok := s["zones"].([]interface{}); ok {
							zoneList := make([]string, len(zones))
							for i, z := range zones {
								zoneList[i] = fmt.Sprintf("%v", z)
							}
							zoneCount = len(zoneList)
							if zoneCount > 0 {
								zoneStr = strings.Join(zoneList, ", ")
								if zoneCount > 3 {
									zoneStr = strings.Join(zoneList[:3], ", ") + fmt.Sprintf(" (+%d more)", zoneCount-3)
								}
							}
						}
						
						contents := ""
						if zoneCount > 0 {
							contents = fmt.Sprintf("%s keys for %d zone(s), including %s", keyTypeStr, zoneCount, zoneStr)
						} else {
							contents = keyTypeStr + " keys"
						}
						
						rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s | %s", distID, state, timeStr, nodeStr, contents, queryStr))
					}
				}
				
				if len(rows) > 1 {
					output := columnize.SimpleFormat(rows)
					fmt.Println(output)
				}
			}
		} else if dists, ok := resp["distributions"].([]interface{}); ok {
			// Fallback to old format
			if len(dists) == 0 {
				fmt.Println("No distributions found")
			} else {
				fmt.Println("\nDistribution IDs:")
				for _, dist := range dists {
					fmt.Printf("  %s\n", dist)
				}
			}
		}
	},
}

var kdcDistribPurgeCmd = &cobra.Command{
	Use:   "purge [--force]",
	Short: "Delete distributions",
	Long:  "Delete distributions from the database. By default, only completed distributions are deleted. Use --force to delete ALL distributions regardless of status.",
	Run: func(cmd *cobra.Command, args []string) {
		force, _ := cmd.Flags().GetBool("force")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		reqBody := map[string]interface{}{
			"command": "purge",
			"force":   force,
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", reqBody)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if msg, ok := resp["msg"].(string); ok {
			fmt.Println(msg)
		} else if errorMsg, ok := resp["error_msg"].(string); ok {
			fmt.Printf("Error: %s\n", errorMsg)
			os.Exit(1)
		}
	},
}

var kdcDistribStateCmd = &cobra.Command{
	Use:   "state --distid <distribution-id>",
	Short: "Show detailed state of a distribution",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "distid")
		distID := cmd.Flag("distid").Value.String()

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":        "state",
			"distribution_id": distID,
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n\n", resp["msg"])
		
		if stateRaw, ok := resp["state"]; ok {
			if state, ok := stateRaw.(map[string]interface{}); ok {
				fmt.Printf("Distribution ID: %s\n", getString(state, "distribution_id", "DistributionID"))
				fmt.Printf("Zone: %s\n", getString(state, "zone_name", "ZoneName"))
				fmt.Printf("Key ID: %s\n", getString(state, "key_id", "KeyID"))
				fmt.Printf("Key State: %s\n", getString(state, "key_state", "KeyState"))
				fmt.Printf("Created At: %s\n", getString(state, "created_at", "CreatedAt"))
				fmt.Printf("All Confirmed: %v\n\n", getBool(state, "all_confirmed", "AllConfirmed"))
				
				if confirmedNodes, ok := state["confirmed_nodes"].([]interface{}); ok {
					fmt.Printf("Confirmed Nodes (%d):\n", len(confirmedNodes))
					for _, node := range confirmedNodes {
						fmt.Printf("  - %s\n", node)
					}
				}
				
				if pendingNodes, ok := state["pending_nodes"].([]interface{}); ok {
					fmt.Printf("\nPending Nodes (%d):\n", len(pendingNodes))
					if len(pendingNodes) == 0 {
						fmt.Println("  (none - all confirmed)")
					} else {
						for _, node := range pendingNodes {
							fmt.Printf("  - %s\n", node)
						}
					}
				}
			}
		}
	},
}

var kdcDistribCompletedCmd = &cobra.Command{
	Use:   "completed --distid <distribution-id>",
	Short: "Force mark a distribution as completed (even if nodes haven't confirmed)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "distid")
		distID := cmd.Flag("distid").Value.String()

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":        "completed",
			"distribution_id": distID,
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcZoneSetStateCmd = &cobra.Command{
	Use:   "setstate --zone <zone-id> --keyid <key-id> --state <state>",
	Short: "Set a key to any state (debug command)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		keyid := cmd.Flag("keyid").Value.String()
		newState := cmd.Flag("state").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}
		if newState == "" {
			log.Fatalf("Error: --state is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":  "setstate",
			"zone_id":  tdns.Globals.Zonename,
			"key_id":   keyid,
			"new_state": newState,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Helper function to get KDC config file path from CLI config
func getKdcConfigPath() (string, error) {
	clientKey := getClientKey()
	if clientKey == "" {
		return "", fmt.Errorf("no client key set")
	}
	
	// Get API details for this client
	apiDetails := getApiDetailsByClientKey(clientKey)
	if apiDetails == nil {
		return "", fmt.Errorf("API details not found for %s", clientKey)
	}
	
	var configPath string
	var source string
	
	// Check if config path is specified
	if path, ok := apiDetails["config"].(string); ok && path != "" {
		configPath = path
		source = "CLI config"
	} else {
		// Fallback: try default KDC config file location
		defaultPath := tdns.DefaultKdcCfgFile
		if _, err := os.Stat(defaultPath); err == nil {
			configPath = defaultPath
			source = "default location"
		} else {
			return "", fmt.Errorf("KDC config file not specified in CLI config and default path %s not found", defaultPath)
		}
	}
	
	// Log config file usage in debug mode
	if tdns.Globals.Debug || tdns.Globals.Verbose {
		fmt.Fprintf(os.Stderr, "Using KDC config file (%s): %s\n", source, configPath)
	}
	
	return configPath, nil
}

// Helper function to load KDC config from file
func loadKdcConfigFromFile(configPath string) (*kdc.KdcConf, error) {
	// Read config file
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read KDC config file %s: %v", configPath, err)
	}
	
	// The KDC config file has the kdc section nested, so we need to unmarshal into a wrapper
	type KdcConfigWrapper struct {
		Kdc kdc.KdcConf `yaml:"kdc"`
	}
	
	var wrapper KdcConfigWrapper
	if err := yaml.Unmarshal(configData, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unmarshal KDC config: %v", err)
	}
	
	kdcConf := wrapper.Kdc
	
	// Validate that database config is present
	if kdcConf.Database.Type == "" {
		return nil, fmt.Errorf("database type not specified in KDC config file %s (expected under 'kdc.database.type')", configPath)
	}
	if kdcConf.Database.DSN == "" {
		return nil, fmt.Errorf("database DSN not specified in KDC config file %s (expected under 'kdc.database.dsn')", configPath)
	}
	
	if tdns.Globals.Debug {
		fmt.Fprintf(os.Stderr, "KDC config loaded: database type=%s, control_zone=%s\n", 
			kdcConf.Database.Type, kdcConf.ControlZone)
	}
	
	return &kdcConf, nil
}

// Helper function to get KDC database connection from config (fallback only)
// This is used when API is unavailable. Normal operations should use the API.
func getKdcDB() (*kdc.KdcDB, error) {
	// Get config file path
	configPath, err := getKdcConfigPath()
	if err != nil {
		return nil, err
	}
	
	// Load KDC config from file
	kdcConf, err := loadKdcConfigFromFile(configPath)
	if err != nil {
		return nil, err
	}
	
	// Create database connection
	kdcDB, err := kdc.NewKdcDB(kdcConf.Database.Type, kdcConf.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KDC database: %v", err)
	}
	
	return kdcDB, nil
}

// Helper function to call enrollment API with fallback to direct DB access
func callEnrollAPI(command string, reqData map[string]interface{}) (map[string]interface{}, error) {
	// Try API first
	api, err := getApiClient(false) // Don't die on error, we'll fallback
	if err == nil && api != nil {
		if tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "Attempting enrollment API call: %s\n", command)
		}
		resp, err := sendKdcRequest(api, "/kdc/bootstrap", reqData)
		if err == nil {
			if tdns.Globals.Debug {
				fmt.Fprintf(os.Stderr, "Enrollment API call successful\n")
			}
			return resp, nil
		}
		// API failed, fallback to direct DB
		if tdns.Globals.Verbose || tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "Warning: API call failed (%v), falling back to direct database access\n", err)
		}
	} else {
		if tdns.Globals.Verbose || tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "Warning: API client unavailable (%v), using direct database access\n", err)
		}
	}
	
	// Fallback: direct database access
	if tdns.Globals.Debug {
		fmt.Fprintf(os.Stderr, "Using direct database access for enrollment operation: %s\n", command)
	}
	return callEnrollDB(command, reqData)
}

// Helper function to call enrollment operations via direct database access
func callEnrollDB(command string, reqData map[string]interface{}) (map[string]interface{}, error) {
	// Get KDC config path and load config (for debug output)
	configPath, err := getKdcConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get KDC config path: %v", err)
	}
	
	// Load KDC config from file
	kdcConf, err := loadKdcConfigFromFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load KDC config: %v", err)
	}
	
	// Create database connection
	kdcDB, err := kdc.NewKdcDB(kdcConf.Database.Type, kdcConf.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}
	defer kdcDB.DB.Close()
	
	result := make(map[string]interface{})
	result["time"] = time.Now()
	
	switch command {
	case "generate":
		nodeID, _ := reqData["node_id"].(string)
		if nodeID == "" {
			result["error"] = true
			result["error_msg"] = "node_id is required"
			return result, nil
		}
		
		// Check if node already exists and is active
		existingNode, err := kdcDB.GetNode(nodeID)
		if err == nil {
			// Node exists - check if it's in an active state
			if existingNode.State == kdc.NodeStateOnline {
				result["error"] = true
				result["error_msg"] = fmt.Sprintf("Node %s already exists and is online. Cannot generate enrollment blob for an active node. Delete the node first (kdc-cli node delete --nodeid %s) or set it to a non-active state (suspended/offline) before re-enrolling.", nodeID, nodeID)
				return result, nil
			}
			// Node exists but is not online (offline, suspended, compromised) - allow re-enrollment
			// This is intentional - nodes in these states may need to re-enroll
		}
		// If node doesn't exist (err != nil), that's fine - it's a new node
		
		// Check if token already exists
		status, err := kdcDB.GetBootstrapTokenStatus(nodeID)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		if status != "not_found" {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("Enrollment token already exists for node %s (status: %s)", nodeID, status)
			return result, nil
		}
		
		// Generate token
		token, err := kdcDB.GenerateBootstrapToken(nodeID)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		
		result["token"] = token
		result["msg"] = fmt.Sprintf("Enrollment token generated for node: %s", nodeID)
		
		// Generate enrollment blob content (CLI will write the file)
		kdcConf, err := getKdcConfig()
		if err != nil {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("Failed to load KDC config: %v", err)
			return result, nil
		}
		
		blobContent, err := kdc.GenerateBootstrapBlobContent(nodeID, token, kdcConf)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		
		result["blob_content"] = blobContent
		
	case "activate":
		nodeID, _ := reqData["node_id"].(string)
		if nodeID == "" {
			result["error"] = true
			result["error_msg"] = "node_id is required"
			return result, nil
		}
		
		expirationStr, _ := reqData["expiration_window"].(string)
		expirationWindow := 5 * time.Minute
		if expirationStr != "" {
			var err error
			expirationWindow, err = time.ParseDuration(expirationStr)
			if err != nil {
				result["error"] = true
				result["error_msg"] = fmt.Sprintf("Invalid expiration_window format: %v", err)
				return result, nil
			}
		}
		
		// Check token status
		status, err := kdcDB.GetBootstrapTokenStatus(nodeID)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		if status == "not_found" {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("No enrollment token found for node %s", nodeID)
			return result, nil
		}
		if status == "active" {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("Enrollment token for node %s is already activated", nodeID)
			return result, nil
		}
		if status == "completed" {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("Enrollment token for node %s has already been used", nodeID)
			return result, nil
		}
		
		err = kdcDB.ActivateBootstrapToken(nodeID, expirationWindow)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		
		result["msg"] = fmt.Sprintf("Enrollment token activated for node: %s", nodeID)
		
	case "list":
		tokens, err := kdcDB.ListBootstrapTokens()
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		result["tokens"] = tokens
		result["msg"] = fmt.Sprintf("Found %d bootstrap token(s)", len(tokens))
		
	case "status":
		nodeID, _ := reqData["node_id"].(string)
		if nodeID == "" {
			result["error"] = true
			result["error_msg"] = "node_id is required"
			return result, nil
		}
		
		status, err := kdcDB.GetBootstrapTokenStatus(nodeID)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		
		result["status"] = status
		if status != "not_found" {
			tokens, err := kdcDB.ListBootstrapTokens()
			if err == nil {
				for _, t := range tokens {
					if t.NodeID == nodeID {
						result["token"] = t
						break
					}
				}
			}
		}
		
	case "purge":
		deleteFiles, _ := reqData["delete_files"].(bool)
		count, err := kdcDB.PurgeBootstrapTokens()
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		
		result["count"] = count
		result["msg"] = fmt.Sprintf("Purged %d bootstrap token(s)", count)
		
		if deleteFiles && count > 0 {
			tokens, _ := kdcDB.ListBootstrapTokens()
			deletedFiles := 0
			for _, token := range tokens {
				status, _ := kdcDB.GetBootstrapTokenStatus(token.NodeID)
				if status == "expired" || status == "completed" {
					blobFile := fmt.Sprintf("%s.enroll", token.NodeID)
					if err := os.Remove(blobFile); err == nil {
						deletedFiles++
					}
				}
			}
			if deletedFiles > 0 {
				result["msg"] = fmt.Sprintf("%s, deleted %d blob file(s)", result["msg"], deletedFiles)
			}
		}
		
	default:
		result["error"] = true
		result["error_msg"] = fmt.Sprintf("Unknown command: %s", command)
		return result, nil
	}
	
	return result, nil
}

// Helper function to get KDC config from file
func getKdcConfig() (*kdc.KdcConf, error) {
	// Get config file path
	configPath, err := getKdcConfigPath()
	if err != nil {
		return nil, err
	}
	
	// Load KDC config from file
	return loadKdcConfigFromFile(configPath)
}

// Enrollment commands
var kdcNodeEnrollGenerateCmd = &cobra.Command{
	Use:   "generate --nodeid <nodeid> --outdir <directory> [--comment <comment>]",
	Short: "Generate an enrollment token and blob file",
	Long: `Generate an enrollment token for a node and create an enrollment blob file.
The enrollment blob contains the token, node ID, KDC HPKE public key, enrollment address, and control zone.
The blob is base64-encoded JSON written to {nodeid}.enroll file in the specified output directory.
The output directory must exist.`,
	Run: func(cmd *cobra.Command, args []string) {
		nodeID, _ := cmd.Flags().GetString("nodeid")
		if nodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}
		// Ensure node ID is FQDN
		nodeID = dns.Fqdn(nodeID)
		
		outDir, _ := cmd.Flags().GetString("outdir")
		if outDir == "" {
			log.Fatalf("Error: --outdir is required")
		}
		
		// Verify output directory exists
		info, err := os.Stat(outDir)
		if err != nil {
			log.Fatalf("Error: Output directory does not exist or is not accessible: %v", err)
		}
		if !info.IsDir() {
			log.Fatalf("Error: Output path is not a directory: %s", outDir)
		}
		
		comment, _ := cmd.Flags().GetString("comment")
		
		// Call API (with fallback to DB)
		// Note: outdir is not sent to API - CLI writes the file locally
		req := map[string]interface{}{
			"command": "generate",
			"node_id": nodeID,
		}
		if comment != "" {
			req["comment"] = comment
		}
		
		resp, err := callEnrollAPI("generate", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		
		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}
		
		// Extract token from response
		tokenRaw, ok := resp["token"]
		if !ok {
			log.Fatalf("Error: No token in response")
		}
		
		// Convert token to BootstrapToken struct
		tokenJSON, _ := json.Marshal(tokenRaw)
		var token kdc.BootstrapToken
		if err := json.Unmarshal(tokenJSON, &token); err != nil {
			log.Fatalf("Error parsing token: %v", err)
		}
		
		// Extract blob content and write to file
		blobContent := getString(resp, "blob_content")
		if blobContent == "" {
			// Fallback to old blob_path for backward compatibility
			blobPath := getString(resp, "blob_path")
			if blobPath != "" {
				fmt.Printf("Enrollment token generated for node: %s\n", nodeID)
				fmt.Printf("Token ID: %s\n", token.TokenID)
				fmt.Printf("Enrollment blob written to: %s\n", blobPath)
				return
			}
			log.Fatalf("Error: No blob content in response")
		}
		
		// Write blob file to specified directory with comment header
		// Remove trailing dot from FQDN for filename
		nodeIDForFile := strings.TrimSuffix(nodeID, ".")
		filename := filepath.Join(outDir, fmt.Sprintf("%s.enroll", nodeIDForFile))
		var fileContent []byte
		// Add comment line with timestamp
		generatedAt := time.Now().Format("2006-01-02 15:04:05")
		commentLine := fmt.Sprintf("# enrollment package for node \"%s\" generated at %s\n", nodeID, generatedAt)
		fileContent = append(fileContent, []byte(commentLine)...)
		// Add base64 content
		fileContent = append(fileContent, []byte(blobContent)...)
		fileContent = append(fileContent, '\n') // Add newline at end
		if err := os.WriteFile(filename, fileContent, 0644); err != nil {
			log.Fatalf("Error writing enrollment blob file: %v", err)
		}
		
		// Get absolute path for display
		absPath, err := filepath.Abs(filename)
		if err != nil {
			absPath = filename
		}
		
		fmt.Printf("Enrollment token generated for node: %s\n", nodeID)
		fmt.Printf("Token ID: %s\n", token.TokenID)
		fmt.Printf("Enrollment blob written to: %s\n", absPath)
	},
}

var kdcNodeEnrollActivateCmd = &cobra.Command{
	Use:   "activate --nodeid <nodeid> [--expiration <duration>]",
	Short: "Activate an enrollment token",
	Long: `Activate an enrollment token for a node. This sets the activation timestamp and expiration time.
The expiration window defaults to 5 minutes if not specified.`,
	Run: func(cmd *cobra.Command, args []string) {
		nodeID, _ := cmd.Flags().GetString("nodeid")
		if nodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}
		// Ensure node ID is FQDN
		nodeID = dns.Fqdn(nodeID)
		
		expirationStr, _ := cmd.Flags().GetString("expiration")
		if expirationStr == "" {
			expirationStr = "5m" // Default
		}
		
		// Call API (with fallback to DB)
		req := map[string]interface{}{
			"command":           "activate",
			"node_id":           nodeID,
			"expiration_window": expirationStr,
		}
		
		resp, err := callEnrollAPI("activate", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		
		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}
		
		fmt.Printf("Enrollment token activated for node: %s\n", nodeID)
		fmt.Printf("Expiration window: %s\n", expirationStr)
	},
}

var kdcNodeEnrollListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all enrollment tokens",
	Long:  `List all enrollment tokens with their status, node ID, creation time, and expiration time.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Call API (with fallback to DB)
		req := map[string]interface{}{
			"command": "list",
		}
		
		resp, err := callEnrollAPI("list", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		
		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}
		
		// Extract tokens from response
		tokensRaw, ok := resp["tokens"]
		if !ok {
			fmt.Println("No enrollment tokens found")
			return
		}
		
		tokensArray, ok := tokensRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: Invalid tokens format in response")
		}
		
		if len(tokensArray) == 0 {
			fmt.Println("No enrollment tokens found")
			return
		}
		
		// Convert to BootstrapToken structs
		var tokens []*kdc.BootstrapToken
		for _, tokenRaw := range tokensArray {
			tokenJSON, _ := json.Marshal(tokenRaw)
			var token kdc.BootstrapToken
			if err := json.Unmarshal(tokenJSON, &token); err == nil {
				tokens = append(tokens, &token)
			}
		}
		
		// Display tokens in a table (similar to dnssec key listing)
		var lines []string
		lines = append(lines, "Node ID | Token ID | Status | Timestamp | Event")
		
		for _, token := range tokens {
			// Calculate status from token fields
			var status string
			if token.Used {
				status = "completed"
			} else if !token.Activated {
				status = "generated"
			} else if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
				status = "expired"
			} else {
				status = "active"
			}
			
			// Determine timestamp and event based on current state
			var timestamp, event string
			if token.Used && token.UsedAt != nil {
				// Token was used - show when it was used
				timestamp = token.UsedAt.Format("2006-01-02 15:04:05")
				event = "enrollment completed"
			} else if status == "expired" && token.ExpiresAt != nil {
				// Token expired - show expiration time
				timestamp = token.ExpiresAt.Format("2006-01-02 15:04:05")
				event = "expired"
			} else if token.Activated && token.ActivatedAt != nil {
				// Token is active - show when it was activated and expiration time
				timestamp = token.ActivatedAt.Format("2006-01-02 15:04:05")
				if token.ExpiresAt != nil {
					expiresStr := token.ExpiresAt.Format("2006-01-02 15:04:05")
					event = fmt.Sprintf("activated (expires at %s)", expiresStr)
				} else {
					event = "activated"
				}
			} else {
				// Token is generated but not activated - show creation time
				timestamp = token.CreatedAt.Format("2006-01-02 15:04:05")
				event = "generated enrollment package"
			}
			
			tokenIDDisplay := token.TokenID
			if len(tokenIDDisplay) > 8 {
				tokenIDDisplay = tokenIDDisplay[:8] + "..."
			}
			
			line := fmt.Sprintf("%s | %s | %s | %s | %s",
				token.NodeID, tokenIDDisplay, status, timestamp, event)
			lines = append(lines, line)
		}
		
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

var kdcNodeEnrollPurgeCmd = &cobra.Command{
	Use:   "purge [--files]",
	Short: "Purge expired and completed enrollment tokens",
	Long: `Delete enrollment tokens with status "expired" or "completed".
Use --files to also delete associated enrollment blob files.`,
	Run: func(cmd *cobra.Command, args []string) {
		deleteFiles, _ := cmd.Flags().GetBool("files")
		
		// Call API (with fallback to DB)
		req := map[string]interface{}{
			"command":      "purge",
			"delete_files": deleteFiles,
		}
		
		resp, err := callEnrollAPI("purge", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		
		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}
		
		msg := getString(resp, "msg")
		if msg != "" {
			fmt.Printf("%s\n", msg)
		} else {
			count := getInt(resp, "count")
			fmt.Printf("Purged %d enrollment token(s)\n", count)
		}
	},
}

var kdcNodeEnrollStatusCmd = &cobra.Command{
	Use:   "status --nodeid <nodeid>",
	Short: "Show detailed status of an enrollment token",
	Long:  `Show detailed status information for a specific enrollment token.`,
	Run: func(cmd *cobra.Command, args []string) {
		nodeID, _ := cmd.Flags().GetString("nodeid")
		if nodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}
		// Ensure node ID is FQDN
		nodeID = dns.Fqdn(nodeID)
		
		// Call API (with fallback to DB)
		req := map[string]interface{}{
			"command": "status",
			"node_id": nodeID,
		}
		
		resp, err := callEnrollAPI("status", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		
		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}
		
		status := getString(resp, "status")
		if status == "not_found" {
			fmt.Printf("No enrollment token found for node: %s\n", nodeID)
			return
		}
		
		// Extract token from response
		tokenRaw, ok := resp["token"]
		if !ok {
			fmt.Printf("Enrollment Token Status for Node: %s\n", nodeID)
			fmt.Printf("  Status: %s\n", status)
			return
		}
		
		// Convert token to BootstrapToken struct
		tokenJSON, _ := json.Marshal(tokenRaw)
		var token kdc.BootstrapToken
		if err := json.Unmarshal(tokenJSON, &token); err != nil {
			log.Fatalf("Error parsing token: %v", err)
		}
		
		// Display detailed status
		fmt.Printf("Bootstrap Token Status for Node: %s\n", nodeID)
		fmt.Printf("  Status: %s\n", status)
		fmt.Printf("  Token ID: %s\n", token.TokenID)
		fmt.Printf("  Created: %s\n", token.CreatedAt.Format(time.RFC3339))
		if token.ActivatedAt != nil {
			fmt.Printf("  Activated: %s\n", token.ActivatedAt.Format(time.RFC3339))
		}
		if token.ExpiresAt != nil {
			fmt.Printf("  Expires: %s\n", token.ExpiresAt.Format(time.RFC3339))
			if time.Now().After(*token.ExpiresAt) {
				fmt.Printf("  Expired: Yes\n")
			} else {
				remaining := time.Until(*token.ExpiresAt)
				fmt.Printf("  Time remaining: %s\n", remaining)
			}
		}
		fmt.Printf("  Used: %v\n", token.Used)
		if token.UsedAt != nil {
			fmt.Printf("  Used at: %s\n", token.UsedAt.Format(time.RFC3339))
		}
		if token.Comment != "" {
			fmt.Printf("  Comment: %s\n", token.Comment)
		}
	},
}

func init() {
	KdcZoneDnssecCmd.AddCommand(kdcZoneDnssecListCmd, kdcZoneDnssecGenerateCmd, kdcZoneDnssecDeleteCmd, kdcZoneDnssecHashCmd, kdcZoneDnssecPurgeCmd)
	KdcZoneCmd.AddCommand(kdcZoneAddCmd, kdcZoneListCmd, kdcZoneGetCmd, KdcZoneDnssecCmd, kdcZoneDeleteCmd,
		kdcZoneTransitionCmd, kdcZoneSetStateCmd, kdcZoneServiceCmd, kdcZoneComponentCmd, KdcZoneCatalogCmd)
	KdcZoneCatalogCmd.AddCommand(kdcZoneCatalogGenerateCmd)
	KdcDistribCmd.AddCommand(kdcDistribListCmd, kdcDistribStateCmd, kdcDistribCompletedCmd, kdcDistribSingleCmd, kdcDistribMultiCmd, kdcDistribPurgeCmd)
	KdcNodeComponentCmd.AddCommand(kdcNodeComponentAddCmd, kdcNodeComponentDeleteCmd, kdcNodeComponentListCmd)
	KdcDebugDistribCmd.AddCommand(kdcDebugDistribGenerateCmd, kdcDebugDistribListCmd, kdcDebugDistribDeleteCmd)
	KdcDebugCmd.AddCommand(kdcDebugHpkeGenerateCmd, kdcDebugHpkeEncryptCmd, kdcDebugHpkeDecryptCmd, 
		KdcDebugDistribCmd, kdcDebugSetChunkSizeCmd, kdcDebugGetChunkSizeCmd)
	KdcConfigCmd.AddCommand(kdcConfigGetCmd)
	KdcServiceCmd.AddCommand(kdcServiceAddCmd, kdcServiceListCmd, kdcServiceDeleteCmd, kdcServiceComponentsCmd, KdcServiceComponentCmd, KdcServiceTransactionCmd)
	KdcServiceComponentCmd.AddCommand(kdcServiceComponentAddCmd, kdcServiceComponentDeleteCmd, kdcServiceComponentReplaceCmd)
	KdcServiceTransactionCmd.AddCommand(kdcServiceTxStartCmd, kdcServiceTxViewCmd, kdcServiceTxCommitCmd, kdcServiceTxRollbackCmd, kdcServiceTxStatusCmd, kdcServiceTxListCmd, kdcServiceTxCleanupCmd, kdcServiceTxComponentCmd)
	kdcServiceTxComponentCmd.AddCommand(kdcServiceTxComponentAddCmd, kdcServiceTxComponentDeleteCmd)
	KdcComponentCmd.AddCommand(kdcComponentAddCmd, kdcComponentListCmd, kdcComponentDeleteCmd)
	KdcNodeCmd.AddCommand(kdcNodeAddCmd, kdcNodeListCmd, kdcNodeGetCmd, kdcNodeUpdateCmd, kdcNodeSetStateCmd, kdcNodeDeleteCmd, KdcNodeComponentCmd, KdcNodeEnrollCmd)
	KdcNodeEnrollCmd.AddCommand(kdcNodeEnrollGenerateCmd, kdcNodeEnrollActivateCmd, kdcNodeEnrollListCmd, kdcNodeEnrollPurgeCmd, kdcNodeEnrollStatusCmd)
	KdcHpkeCmd.AddCommand(kdcHpkeGenerateCmd)
	// Commands are added directly to root in main.go, not via KdcCmd

	kdcNodeEnrollGenerateCmd.Flags().String("nodeid", "", "Node ID")
	kdcNodeEnrollGenerateCmd.MarkFlagRequired("nodeid")
	kdcNodeEnrollGenerateCmd.Flags().String("outdir", "", "Output directory (must exist)")
	kdcNodeEnrollGenerateCmd.MarkFlagRequired("outdir")
	kdcNodeEnrollGenerateCmd.Flags().String("comment", "", "Optional comment")
	
	kdcNodeEnrollActivateCmd.Flags().String("nodeid", "", "Node ID")
	kdcNodeEnrollActivateCmd.MarkFlagRequired("nodeid")
	kdcNodeEnrollActivateCmd.Flags().String("expiration", "", "Expiration window (e.g., 5m, 1h)")
	
	kdcNodeEnrollPurgeCmd.Flags().Bool("files", false, "Also delete enrollment blob files")
	
	kdcNodeEnrollStatusCmd.Flags().String("nodeid", "", "Node ID")
	kdcNodeEnrollStatusCmd.MarkFlagRequired("nodeid")

	// HPKE command flags
	kdcHpkeGenerateCmd.Flags().String("outfile", "", "Output file path for HPKE private key (required)")
	kdcHpkeGenerateCmd.MarkFlagRequired("outfile")
	
	kdcDistribSingleCmd.Flags().StringP("keyid", "k", "", "Key ID (must be a ZSK in standby state)")
	kdcDistribSingleCmd.MarkFlagRequired("keyid")
	
	kdcDistribStateCmd.Flags().String("distid", "", "Distribution ID")
	kdcDistribStateCmd.MarkFlagRequired("distid")
	
	kdcDistribCompletedCmd.Flags().String("distid", "", "Distribution ID")
	kdcDistribCompletedCmd.MarkFlagRequired("distid")
	
	kdcDistribPurgeCmd.Flags().Bool("force", false, "Delete ALL distributions (not just completed ones)")
	
	kdcZoneTransitionCmd.Flags().StringP("keyid", "k", "", "Key ID (transition auto-detected: created->published or standby->active)")
	kdcZoneTransitionCmd.MarkFlagRequired("keyid")
	
	kdcZoneDnssecDeleteCmd.Flags().StringP("keyid", "k", "", "Key ID to delete")
	kdcZoneDnssecDeleteCmd.MarkFlagRequired("keyid")

	kdcZoneDnssecHashCmd.Flags().StringP("keyid", "k", "", "Key ID")
	kdcZoneDnssecHashCmd.MarkFlagRequired("keyid")
	
	kdcZoneSetStateCmd.Flags().StringP("keyid", "k", "", "Key ID")
	kdcZoneSetStateCmd.Flags().StringP("state", "s", "", "New state")
	kdcZoneSetStateCmd.MarkFlagRequired("keyid")
	kdcZoneSetStateCmd.MarkFlagRequired("state")

	// Zone add command flags
	kdcZoneAddCmd.Flags().String("sid", "", "Service ID this zone belongs to (optional)")
	kdcZoneAddCmd.Flags().String("comment", "", "Comment for this zone")
	
	// Zone service command flags
	kdcZoneServiceCmd.Flags().StringP("zone", "z", "", "Zone name")
	kdcZoneServiceCmd.Flags().StringP("service", "s", "", "Service ID or name")
	kdcZoneServiceCmd.MarkFlagRequired("zone")
	kdcZoneServiceCmd.MarkFlagRequired("service")
	
	// Zone component command flags
	kdcZoneComponentCmd.Flags().StringP("zone", "z", "", "Zone name")
	kdcZoneComponentCmd.Flags().StringP("component", "c", "", "Component ID or name")
	kdcZoneComponentCmd.MarkFlagRequired("zone")
	kdcZoneComponentCmd.MarkFlagRequired("component")
	
	// Service command flags
	kdcServiceAddCmd.Flags().String("sid", "", "Service ID")
	kdcServiceAddCmd.Flags().StringP("name", "n", "", "Service name")
	kdcServiceAddCmd.Flags().String("comment", "", "Comment")
	kdcServiceAddCmd.MarkFlagRequired("name")
	kdcServiceAddCmd.MarkFlagRequired("sid")
	kdcServiceDeleteCmd.Flags().String("sid", "", "Service ID")
	kdcServiceDeleteCmd.MarkFlagRequired("sid")
	kdcServiceComponentsCmd.Flags().StringP("name", "n", "", "Service name")
	kdcServiceComponentsCmd.MarkFlagRequired("name")
	
	// Component command flags
	kdcComponentAddCmd.Flags().String("cid", "", "Component ID")
	kdcComponentAddCmd.Flags().StringP("name", "n", "", "Component name")
	kdcComponentAddCmd.Flags().String("comment", "", "Comment")
	kdcComponentAddCmd.MarkFlagRequired("name")
	kdcComponentAddCmd.MarkFlagRequired("cid")
	kdcComponentDeleteCmd.Flags().String("cid", "", "Component ID")
	kdcComponentDeleteCmd.MarkFlagRequired("cid")
	
	// Service-component command flags
	kdcServiceComponentAddCmd.Flags().StringP("sname", "s", "", "Service name")
	kdcServiceComponentAddCmd.Flags().StringP("cname", "c", "", "Component name")
	kdcServiceComponentAddCmd.MarkFlagRequired("sname")
	kdcServiceComponentAddCmd.MarkFlagRequired("cname")
	kdcServiceComponentDeleteCmd.Flags().StringP("sname", "s", "", "Service name")
	kdcServiceComponentDeleteCmd.Flags().StringP("cname", "c", "", "Component name")
	kdcServiceComponentDeleteCmd.MarkFlagRequired("sname")
	kdcServiceComponentDeleteCmd.MarkFlagRequired("cname")
	
	kdcServiceComponentReplaceCmd.Flags().StringP("sname", "s", "", "Service name")
	kdcServiceComponentReplaceCmd.Flags().String("old", "", "Old component ID or name")
	kdcServiceComponentReplaceCmd.Flags().String("new", "", "New component ID or name")
	kdcServiceComponentReplaceCmd.MarkFlagRequired("sname")
	kdcServiceComponentReplaceCmd.MarkFlagRequired("old")
	kdcServiceComponentReplaceCmd.MarkFlagRequired("new")
	
	// Node-component command flags
	// Note: nodeid is a persistent flag on KdcNodeCmd, so we don't need to define it here
	kdcNodeComponentAddCmd.Flags().StringP("cname", "c", "", "Component name")
	kdcNodeComponentAddCmd.MarkFlagRequired("cname")
	kdcNodeComponentDeleteCmd.Flags().StringP("cname", "c", "", "Component name")
	kdcNodeComponentDeleteCmd.MarkFlagRequired("cname")
	// kdcNodeComponentListCmd uses persistent nodeid flag, no additional flags needed

	KdcNodeCmd.PersistentFlags().StringVarP(&nodeid, "nodeid", "n", "", "node id")
	KdcNodeCmd.PersistentFlags().StringVarP(&nodename, "nodename", "N", "", "node name")
	KdcNodeCmd.PersistentFlags().StringVarP(&pubkeyfile, "pubkeyfile", "p", "", "public key file")
	
	kdcNodeUpdateCmd.Flags().StringP("nodeid", "n", "", "Node ID (required)")
	kdcNodeUpdateCmd.MarkFlagRequired("nodeid")
	kdcNodeUpdateCmd.Flags().StringP("name", "", "", "Node name")
	kdcNodeUpdateCmd.Flags().StringP("notify-address", "a", "", "Notify address:port (e.g., 192.0.2.1:53)")
	kdcNodeUpdateCmd.Flags().StringP("comment", "c", "", "Comment")

	kdcZoneDnssecGenerateCmd.Flags().StringP("type", "t", "ZSK", "Key type: KSK, ZSK, or CSK")
	kdcZoneDnssecGenerateCmd.Flags().StringP("algorithm", "a", "", "DNSSEC algorithm (number or name, e.g., 15 or ED25519)")
	kdcZoneDnssecGenerateCmd.Flags().StringP("comment", "c", "", "Optional comment for the key")

	kdcDebugHpkeEncryptCmd.Flags().StringP("keyid", "k", "", "DNSSEC key ID to encrypt")
	kdcDebugHpkeEncryptCmd.Flags().StringP("nodeid", "n", "", "Node ID to encrypt for")
	kdcDebugHpkeEncryptCmd.Flags().StringP("output", "o", "", "Output file for encrypted key (optional)")
	kdcDebugHpkeEncryptCmd.MarkFlagRequired("keyid")
	kdcDebugHpkeEncryptCmd.MarkFlagRequired("nodeid")

	kdcDebugHpkeDecryptCmd.Flags().StringP("encrypted-file", "e", "", "File containing encrypted key")
	kdcDebugHpkeDecryptCmd.Flags().StringP("private-key-file", "p", "", "File containing node's HPKE private key (hex)")
	kdcDebugHpkeDecryptCmd.MarkFlagRequired("encrypted-file")
	kdcDebugHpkeDecryptCmd.MarkFlagRequired("private-key-file")

	kdcDebugDistribGenerateCmd.Flags().String("distid", "", "Distribution ID (hex, e.g., a1b2)")
	kdcDebugDistribGenerateCmd.Flags().StringP("nodeid", "n", "", "Node ID")
	kdcDebugDistribGenerateCmd.Flags().StringP("file", "f", "", "File containing text (if not provided, uses default lorem ipsum)")
	kdcDebugDistribGenerateCmd.Flags().StringP("content-type", "t", "clear_text", "Content type: 'clear_text' or 'encrypted_text' (default: clear_text)")
	kdcDebugDistribGenerateCmd.MarkFlagRequired("distid")
	kdcDebugDistribGenerateCmd.MarkFlagRequired("nodeid")

	kdcDebugDistribDeleteCmd.Flags().String("distid", "", "Distribution ID to delete")
	kdcDebugDistribDeleteCmd.MarkFlagRequired("distid")

	kdcDebugSetChunkSizeCmd.Flags().StringP("size", "s", "", "Chunk size in bytes")
	kdcDebugSetChunkSizeCmd.MarkFlagRequired("size")
	
	// Service transaction command flags
	kdcServiceTxStartCmd.Flags().String("sid", "", "Service ID")
	kdcServiceTxStartCmd.Flags().String("created-by", "", "User/process that created the transaction")
	kdcServiceTxStartCmd.Flags().String("comment", "", "Optional comment/description")
	kdcServiceTxStartCmd.MarkFlagRequired("sid")
	
	kdcServiceTxComponentAddCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxComponentAddCmd.Flags().String("cid", "", "Component ID")
	kdcServiceTxComponentAddCmd.MarkFlagRequired("tx")
	kdcServiceTxComponentAddCmd.MarkFlagRequired("cid")
	
	kdcServiceTxComponentDeleteCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxComponentDeleteCmd.Flags().String("cid", "", "Component ID")
	kdcServiceTxComponentDeleteCmd.MarkFlagRequired("tx")
	kdcServiceTxComponentDeleteCmd.MarkFlagRequired("cid")
	
	kdcServiceTxViewCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxViewCmd.MarkFlagRequired("tx")
	
	kdcServiceTxCommitCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxCommitCmd.Flags().Bool("dry-run", false, "Preview changes without applying them")
	kdcServiceTxCommitCmd.MarkFlagRequired("tx")
	
	kdcServiceTxRollbackCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxRollbackCmd.MarkFlagRequired("tx")
	
	kdcServiceTxStatusCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxStatusCmd.MarkFlagRequired("tx")
	
	kdcServiceTxListCmd.Flags().String("state", "", "Filter by state (open, committed, rolled_back)")
}

// sendKdcRequest sends a JSON POST request to the KDC API
func sendKdcRequest(api *tdns.ApiClient, endpoint string, data interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}

	bytebuf := new(bytes.Buffer)
	if err := json.NewEncoder(bytebuf).Encode(data); err != nil {
		return nil, fmt.Errorf("error encoding request: %v", err)
	}

	if tdns.Globals.Debug {
		fmt.Fprintf(os.Stderr, "DEBUG: Sending POST request to %s\n", endpoint)
		reqJSON, _ := json.MarshalIndent(data, "", "  ")
		fmt.Fprintf(os.Stderr, "DEBUG: Request body: %s\n", reqJSON)
	}

	status, buf, err := api.Post(endpoint, bytebuf.Bytes())
	if err != nil {
		if tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "DEBUG: API POST error: %v\n", err)
		}
		return nil, fmt.Errorf("error from API POST: %v", err)
	}

	// Only print status if it's not 200 (success) - useful for debugging errors
	if status != 200 {
		if tdns.Globals.Verbose || tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "DEBUG: API returned status: %d\n", status)
			if tdns.Globals.Debug {
				fmt.Fprintf(os.Stderr, "DEBUG: Response body: %s\n", string(buf))
			}
		}
	}

	if err := json.Unmarshal(buf, &result); err != nil {
		if tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "DEBUG: JSON decode error: %v\n", err)
			fmt.Fprintf(os.Stderr, "DEBUG: Response body: %s\n", string(buf))
		}
		fmt.Printf("Request: URL: %s, Body: %s\n", endpoint, string(bytebuf.Bytes()))
		fmt.Printf("Response causing error: %s\n", string(buf))
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	if tdns.Globals.Debug {
		fmt.Fprintf(os.Stderr, "DEBUG: API response decoded successfully\n")
	}

	return result, nil
}

// Helper functions for extracting values from JSON maps
func getString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

func getBool(m map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			switch val := v.(type) {
			case bool:
				return val
			case string:
				return val == "true" || val == "1"
			case float64:
				return val != 0
			case int:
				return val != 0
			}
		}
	}
	return false
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return 0
}

