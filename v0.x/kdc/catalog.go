/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Catalog zone generation for tdns-kdc
 */

package kdc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/johanix/tdns/v0.x"
	"github.com/miekg/dns"
)

// GenerateCatalogZone generates a catalog zone from zone/service/component data
// and registers it with the TDNS DnsEngine as a ZoneData structure
// catalogZoneName: The name of the catalog zone (e.g., "catalog.example.com.")
// dnsEngineAddresses: List of addresses (IP:port) that DnsEngine listens on
// Returns: The ZoneData structure for the catalog zone, error
func (kdc *KdcDB) GenerateCatalogZone(catalogZoneName string, dnsEngineAddresses []string) (*tdns.ZoneData, error) {
	if !dns.IsFqdn(catalogZoneName) {
		catalogZoneName = dns.Fqdn(catalogZoneName)
	}

	// Get all active zones
	zones, err := kdc.GetAllZones()
	if err != nil {
		return nil, fmt.Errorf("failed to get zones: %v", err)
	}

	// Filter to only active zones
	activeZones := make([]*Zone, 0)
	for _, zone := range zones {
		if zone.Active {
			activeZones = append(activeZones, zone)
		}
	}

	// Generate zone file content as string first
	var zoneContent strings.Builder
	if len(activeZones) == 0 {
		log.Printf("KDC: No active zones found for catalog zone generation")
		// Generate empty catalog zone with just SOA
		zoneContent.WriteString(generateEmptyCatalogZoneContent(catalogZoneName, dnsEngineAddresses))
	} else {
		// Build catalog zone content

	// Add header comment
	zoneContent.WriteString(fmt.Sprintf("; Catalog zone: %s\n", catalogZoneName))
	zoneContent.WriteString(fmt.Sprintf("; Generated at: %s\n", time.Now().Format(time.RFC3339)))
	zoneContent.WriteString("; This zone lists all zones managed by the KDC with their component groups\n")
	zoneContent.WriteString(";\n")

	// Generate SOA record
	soaSerial := uint32(time.Now().Unix())
	nsName := fmt.Sprintf("ns.%s", catalogZoneName)
	soa := fmt.Sprintf("%s\t%d\tIN\tSOA\t%s\tadmin.%s\t(\n", 
		catalogZoneName, 3600, nsName, catalogZoneName)
	soa += fmt.Sprintf("\t\t%d\t; serial\n", soaSerial)
	soa += fmt.Sprintf("\t\t%d\t; refresh (1 hour)\n", 3600)
	soa += fmt.Sprintf("\t\t%d\t; retry (30 minutes)\n", 1800)
	soa += fmt.Sprintf("\t\t%d\t; expire (2 weeks)\n", 1209600)
	soa += fmt.Sprintf("\t\t%d\t; minimum (1 day)\n", 86400)
	soa += "\t\t)\n"
	zoneContent.WriteString(soa)
	zoneContent.WriteString("\n")

	// Add NS record for the catalog zone apex
	zoneContent.WriteString(fmt.Sprintf("%s\t%d\tIN\tNS\t%s\n", 
		catalogZoneName, 3600, nsName))

	// Extract IP addresses from DnsEngine addresses and create glue records
	var v4Addrs, v6Addrs []string
	for _, addr := range dnsEngineAddresses {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// If SplitHostPort fails, try parsing as IP directly
			if ip := net.ParseIP(addr); ip != nil {
				host = addr
			} else {
				log.Printf("KDC: Warning: Failed to parse DnsEngine address '%s': %v", addr, err)
				continue
			}
		}
		
		ip := net.ParseIP(host)
		if ip == nil {
			log.Printf("KDC: Warning: DnsEngine address '%s' is not an IP address, skipping glue record", host)
			continue
		}
		
		if ip.To4() != nil {
			// IPv4 address
			v4Addrs = append(v4Addrs, ip.String())
		} else {
			// IPv6 address
			v6Addrs = append(v6Addrs, ip.String())
		}
	}

	// Add A records (IPv4 glue)
	for _, ip := range v4Addrs {
		zoneContent.WriteString(fmt.Sprintf("%s\t%d\tIN\tA\t%s\n", 
			nsName, 3600, ip))
	}

	// Add AAAA records (IPv6 glue)
	for _, ip := range v6Addrs {
		zoneContent.WriteString(fmt.Sprintf("%s\t%d\tIN\tAAAA\t%s\n", 
			nsName, 3600, ip))
	}

	zoneContent.WriteString("\n")

	// Collect zone-to-groups mapping
	zoneGroups := make(map[string][]string) // zone identifier -> list of component IDs

	// First pass: collect all zones and their groups
	for _, zone := range activeZones {
		// Generate unique identifier for this zone in the catalog
		// Use SHA256 hash of zone name (first 16 hex chars = 8 bytes = 64 bits)
		hash := sha256.Sum256([]byte(zone.Name))
		identifier := hex.EncodeToString(hash[:8]) // First 8 bytes as hex

		// Get components for this zone's service
		var components []string
		if zone.ServiceID != "" {
			components, err = kdc.GetComponentsForService(zone.ServiceID)
			if err != nil {
				log.Printf("KDC: Warning: Failed to get components for service %s (zone %s): %v", 
					zone.ServiceID, zone.Name, err)
				// Continue with empty components list
				components = []string{}
			}
		}

		// Filter to only active components (GetComponentsForService already filters by active=1)
		// But we'll sort them for consistent output
		sort.Strings(components)

		// Store groups for this zone
		zoneGroups[identifier] = components
	}

	// Second pass: generate PTR records for zones
	// Format: {opaque id}.zones.{catalog zone}. PTR {zone name}
	for _, zone := range activeZones {
		hash := sha256.Sum256([]byte(zone.Name))
		identifier := hex.EncodeToString(hash[:8])
		zonePtrName := fmt.Sprintf("%s.zones.%s", identifier, catalogZoneName)
		zoneContent.WriteString(fmt.Sprintf("%s\t0\tIN\tPTR\t%s\n", 
			zonePtrName, zone.Name))
	}

	zoneContent.WriteString("\n")

	// Third pass: generate zone-group membership PTR records
	// Format: {opaque id}.zones.{catalog} PTR group.{groupname}.groups.{catalog}.
	for _, zone := range activeZones {
		hash := sha256.Sum256([]byte(zone.Name))
		identifier := hex.EncodeToString(hash[:8])
		components := zoneGroups[identifier]

		for _, componentID := range components {
			zonePtrName := fmt.Sprintf("%s.zones.%s", identifier, catalogZoneName)
			groupTarget := fmt.Sprintf("group.%s.groups.%s", componentID, catalogZoneName)
			zoneContent.WriteString(fmt.Sprintf("%s\t0\tIN\tPTR\t%s\n", 
				zonePtrName, groupTarget))
		}
	}
	}

	// Create ZoneData structure
	zd := &tdns.ZoneData{
		ZoneName:  catalogZoneName,
		ZoneStore: tdns.MapZone,
		Logger:    log.Default(),
		ZoneType:  tdns.Primary,
		Options:   map[tdns.ZoneOption]bool{tdns.OptAutomaticZone: true},
	}

	// Parse zone data from string
	log.Printf("KDC: Reading catalog zone data for zone '%s'", catalogZoneName)
	_, _, err = zd.ReadZoneData(zoneContent.String(), false)
	if err != nil {
		return nil, fmt.Errorf("failed to read catalog zone data: %v", err)
	}

	// Set serial number (use current time as Unix timestamp)
	zd.CurrentSerial = uint32(time.Now().Unix())
	zd.IncomingSerial = zd.CurrentSerial
	zd.Ready = true

	// Register with TDNS Zones map so DnsEngine can serve it
	tdns.Zones.Set(catalogZoneName, zd)
	log.Printf("KDC: Catalog zone '%s' registered with DnsEngine", catalogZoneName)

	return zd, nil
}

// generateEmptyCatalogZoneContent generates an empty catalog zone content with just SOA
func generateEmptyCatalogZoneContent(catalogZoneName string, dnsEngineAddresses []string) string {
	var zoneContent strings.Builder

	zoneContent.WriteString(fmt.Sprintf("; Catalog zone: %s\n", catalogZoneName))
	zoneContent.WriteString(fmt.Sprintf("; Generated at: %s\n", time.Now().Format(time.RFC3339)))
	zoneContent.WriteString("; No active zones found\n")
	zoneContent.WriteString(";\n")

	soaSerial := uint32(time.Now().Unix())
	nsName := fmt.Sprintf("ns.%s", catalogZoneName)
	soa := fmt.Sprintf("%s\t%d\tIN\tSOA\t%s\tadmin.%s\t(\n", 
		catalogZoneName, 3600, nsName, catalogZoneName)
	soa += fmt.Sprintf("\t\t%d\t; serial\n", soaSerial)
	soa += fmt.Sprintf("\t\t%d\t; refresh (1 hour)\n", 3600)
	soa += fmt.Sprintf("\t\t%d\t; retry (30 minutes)\n", 1800)
	soa += fmt.Sprintf("\t\t%d\t; expire (2 weeks)\n", 1209600)
	soa += fmt.Sprintf("\t\t%d\t; minimum (1 day)\n", 86400)
	soa += "\t\t)\n"

	zoneContent.WriteString(soa)
	zoneContent.WriteString("\n")

	// Add NS record for the catalog zone apex
	zoneContent.WriteString(fmt.Sprintf("%s\t%d\tIN\tNS\t%s\n", 
		catalogZoneName, 3600, nsName))

	// Extract IP addresses from DnsEngine addresses and create glue records
	var v4Addrs, v6Addrs []string
	for _, addr := range dnsEngineAddresses {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// If SplitHostPort fails, try parsing as IP directly
			if ip := net.ParseIP(addr); ip != nil {
				host = addr
			} else {
				log.Printf("KDC: Warning: Failed to parse DnsEngine address '%s': %v", addr, err)
				continue
			}
		}
		
		ip := net.ParseIP(host)
		if ip == nil {
			log.Printf("KDC: Warning: DnsEngine address '%s' is not an IP address, skipping glue record", host)
			continue
		}
		
		if ip.To4() != nil {
			// IPv4 address
			v4Addrs = append(v4Addrs, ip.String())
		} else {
			// IPv6 address
			v6Addrs = append(v6Addrs, ip.String())
		}
	}

	// Add A records (IPv4 glue)
	for _, ip := range v4Addrs {
		zoneContent.WriteString(fmt.Sprintf("%s\t%d\tIN\tA\t%s\n", 
			nsName, 3600, ip))
	}

	// Add AAAA records (IPv6 glue)
	for _, ip := range v6Addrs {
		zoneContent.WriteString(fmt.Sprintf("%s\t%d\tIN\tAAAA\t%s\n", 
			nsName, 3600, ip))
	}

	return zoneContent.String()
}

