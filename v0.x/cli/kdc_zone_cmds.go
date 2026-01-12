/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC zone CLI commands
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var KdcZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Manage zones in KDC",
}

var KdcZoneDnssecCmd = &cobra.Command{
	Use:   "dnssec",
	Short: "Manage DNSSEC keys for a zone",
}

var KdcZoneCatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Manage catalog zone",
	Long:  `Commands for generating and managing the catalog zone used for automatic zone configuration on edge nodes.`,
}

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

		// Build table rows for columnize
		var rows []string
		rows = append(rows, "Zone | Service | Components | Signing comp | Active | Comment")

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

			rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s | %s", 
				name, serviceID, componentsStr, signingModeStr, activeStr, comment))
			
			// Print nodes in verbose mode
			if tdns.Globals.Verbose && len(nodeIDs) > 0 {
				rows = append(rows, fmt.Sprintf("  Nodes: %s", strings.Join(nodeIDs, ", ")))
			}
		}
		
		if len(rows) > 1 {
			fmt.Println(columnize.SimpleFormat(rows))
		}
	},
}

var kdcZoneGetCmd = &cobra.Command{
	Use:   "get --zone <zone-id>",
	Short: "Get zone details from KDC",
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

var kdcZoneDeleteCmd = &cobra.Command{
	Use:   "delete --zone <zone-id>",
	Short: "Delete a zone from KDC",
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

func init() {
	KdcZoneDnssecCmd.AddCommand(kdcZoneDnssecListCmd, kdcZoneDnssecGenerateCmd, kdcZoneDnssecDeleteCmd, kdcZoneDnssecHashCmd, kdcZoneDnssecPurgeCmd)
	KdcZoneCatalogCmd.AddCommand(kdcZoneCatalogGenerateCmd)
	KdcZoneCmd.AddCommand(kdcZoneAddCmd, kdcZoneListCmd, kdcZoneGetCmd, KdcZoneDnssecCmd, kdcZoneDeleteCmd,
		kdcZoneTransitionCmd, kdcZoneSetStateCmd, kdcZoneServiceCmd, kdcZoneComponentCmd, KdcZoneCatalogCmd)
	
	kdcZoneDnssecPurgeCmd.Flags().Bool("force", false, "Also delete keys in 'distributed' state")
	
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

	kdcZoneDnssecGenerateCmd.Flags().StringP("type", "t", "ZSK", "Key type: KSK, ZSK, or CSK")
	kdcZoneDnssecGenerateCmd.Flags().StringP("algorithm", "a", "", "DNSSEC algorithm (number or name, e.g., 15 or ED25519)")
	kdcZoneDnssecGenerateCmd.Flags().StringP("comment", "c", "", "Optional comment for the key")
}
