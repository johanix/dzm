/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared catalog zone utilities for RFC 9432 compliant catalog zone generation
 * This file contains shared utilities that can be used by both KDC and future KRS implementations
 * KDC-specific functions are in tnm/kdc/catalog.go
 */

package tnm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// AddVersionRecord adds the RFC 9432 required version TXT record to a catalog zone
// This is a shared utility function that can be used by both KDC and KRS
func AddVersionRecord(zd *tdns.ZoneData, catalogZoneName string) error {
	versionOwner := fmt.Sprintf("version.%s", catalogZoneName)
	versionTxtStr := fmt.Sprintf("%s 0 IN TXT \"2\"", versionOwner)
	versionTxt, err := dns.NewRR(versionTxtStr)
	if err != nil {
		return fmt.Errorf("failed to create version TXT record: %v", err)
	}

	// Get or create OwnerData for version owner
	ownerData, exists := zd.Data.Get(versionOwner)
	if !exists {
		ownerData = tdns.OwnerData{
			Name:    versionOwner,
			RRtypes: tdns.NewRRTypeStore(),
		}
	}

	// Create or update TXT RRset
	rrset := core.RRset{
		Name:   versionOwner,
		RRtype: dns.TypeTXT,
		Class:  dns.ClassINET,
		RRs:    []dns.RR{versionTxt},
	}
	ownerData.RRtypes.Set(dns.TypeTXT, rrset)
	zd.Data.Set(versionOwner, ownerData)

	return nil
}

// GenerateZoneHash generates a SHA256 hash of the zone name (first 16 hex chars)
// This matches the implementation in tdns/v2/catalog.go:generateZoneHash()
// Since generateZoneHash is not exported from tdns/v2, we implement it here
// This ensures consistency with tdns catalog zone parsing
// This is a shared utility function that can be used by both KDC and KRS
func GenerateZoneHash(zoneName string) string {
	h := sha256.New()
	h.Write([]byte(zoneName))
	hash := hex.EncodeToString(h.Sum(nil))
	return hash[:16] // Use first 16 characters as opaque ID
}
