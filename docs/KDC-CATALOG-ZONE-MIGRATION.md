# KDC Catalog Zone Migration Plan

**Date:** 2025-01-16  
**Status:** Planning  
**Goal:** Migrate KDC's catalog zone implementation to use the RFC 9432 compliant `tdns/v2` catalog zone functionality

## Overview

The KDC currently has its own catalog zone generation implementation in `tnm/kdc/catalog.go` that predates the RFC 9432 compliant implementation in `tdns/v2`. This plan outlines the migration to leverage the native `tdns` catalog zone support while maintaining KDC's "component" terminology for user-facing aspects.

## Current State

### KDC Implementation (`tnm/kdc/catalog.go`)
- Generates catalog zones using non-RFC 9432 format:
  - Uses PTR records for group associations (should be TXT)
  - Missing `version.{catalog}. IN TXT "2"` record
  - Uses custom SHA256 hash generation (first 8 bytes as hex)
  - Creates zones manually with `ZoneData` structure
  - Uses `ns.{catalog}` with glue records (should use `invalid.` for autozones)

### tdns/v2 Implementation
- RFC 9432 compliant:
  - `version.{catalog}. IN TXT "2"` record
  - `group.{uniqueid}.zones.{catalog}. IN TXT "group1" "group2"` for groups
  - `{uniqueid}.zones.{catalog}. IN PTR {zonename}` for zone names
  - Uses `invalid.` as NS record for autozones
  - `generateZoneHash()` function for opaque IDs
  - `CreateAutoZone()` for zone creation
  - `regenerateCatalogZone()` pattern for updates

## Migration Strategy

### 1. Create New `tnm/catalog.go`

**Location:** `tdns-nm/tnm/catalog.go` (new file, not moved from `tnm/kdc/`)

**Purpose:**
- Contains both KDC-specific wrapper functions (component→group translation)
- Contains shared catalog zone utilities for future KRS use
- Acts as the coordination layer between KDC and `tdns/v2` catalog functions

**Key Functions:**

#### 1.1 Core Generation Function
```go
// GenerateCatalogZone generates an RFC 9432 compliant catalog zone from KDC data
// This is the main entry point for catalog zone generation
func GenerateCatalogZone(
    kdcDB *kdc.KdcDB,
    catalogZoneName string,
    dnsEngineAddresses []string,
    tdnsZones *tdns.ZonesMap,
) (*tdns.ZoneData, error)
```

**Responsibilities:**
- Query KDC database for active zones and components
- Translate component IDs to group names (1:1 mapping at API boundary)
- Use `tdns.CreateAutoZone()` to create the catalog zone
- Add `version.{catalog}. IN TXT "2"` record
- Generate zone records using `tdns.generateZoneHash()` for opaque IDs
- Generate PTR records for zone names
- Generate TXT records for group associations (RFC 9432 format)
- Register zone with `tdns.Zones` map
- Set `OptCatalogZone` option
- Use `invalid.` for NS record (via `CreateAutoZone` with empty addrs)

#### 1.2 Zone Hash Generation
- Use `tdns.generateZoneHash()` function directly (no wrapper needed)
- This ensures consistency with `tdns` implementation

#### 1.3 Component-to-Group Translation
- At API boundary: translate "component" terminology to "group" for internal `tdns` calls
- User-facing output: keep "component" terminology
- Translation is 1:1 (component ID → group name)

#### 1.4 Zone Filtering
- Filter zones: only include zones where `zone.Active == true`
- Filter components: only include components where `active=1` (via `GetComponentsForService()`)
- Start with these filters only; additional filters can be added later if needed

#### 1.5 Error Handling
- Return errors to caller
- Set error state on catalog zone using `zd.SetError(ConfigError, errorMsg)`
- Log errors appropriately

### 2. Update API Handler (`tnm/kdc/api.go`)

**Function:** `APIKdcCatalog`

**Changes:**
- Make it a thin wrapper around `tnm/catalog.go` functions
- Handle HTTP request/response
- Call `tnm.GenerateCatalogZone()` for "generate" command
- Translate component terminology in responses (keep "component" in user-facing output)

**Structure:**
```go
func APIKdcCatalog(kdcDB *KdcDB, kdcConf *tnm.KdcConf) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Parse request
        // Call tnm.GenerateCatalogZone() or other tnm/catalog.go functions
        // Return response with "component" terminology
    }
}
```

### 3. Auto-Initialization on Startup

**Location:** New function in `tnm/kdc/` or `tnm/catalog.go`, called from `cmd/tdns-kdc/main.go`

**Function:**
```go
// InitializeCatalogZone checks if catalog zone is configured and generates it on startup
func InitializeCatalogZone(
    ctx context.Context,
    kdcDB *kdc.KdcDB,
    kdcConf *tnm.KdcConf,
    tdnsConf *tdns.Config,
) error
```

**Behavior:**
- Check if `kdcConf.CatalogZone` is configured
- If configured:
  - Check if zone exists in `tdns.Zones`
  - If not exists: create using `tdns.CreateAutoZone()` + `OptCatalogZone` + version record
  - Generate catalog zone content using `GenerateCatalogZone()`
  - Register with `tdns.Zones`
- If error: return error (caller handles)

**Integration:**
- Call from `startKdc()` function in `cmd/tdns-kdc/main.go`
- After KDC database initialization
- Before starting engines

### 4. Explicit "generate" Command

**Current State:** KDC already has explicit "generate" command via `APIKdcCatalog`

**Future:** Automatic regeneration will be added later (not in this migration)

**Implementation:**
- Keep existing `APIKdcCatalog` endpoint
- Update to call `tnm.GenerateCatalogZone()`
- Maintain same API contract

### 5. Zone Creation Details

**Using `tdns.CreateAutoZone()`:**
- Call with catalog zone name and empty `addrs` slice (to get `invalid.` NS)
- After creation:
  - Set `zd.Options[tdns.OptCatalogZone] = true`
  - Add `version.{catalog}. IN TXT "2"` record
  - Generate member zone records

**NS Record:**
- Use `invalid.` for autozones (via `CreateAutoZone` with empty addrs)
- This matches RFC 9432 recommendation

### 6. Record Generation Pattern

**Follow `tdns/v2/apihandler_catalog.go:regenerateCatalogZone()` pattern:**

1. Remove existing zone records (if regenerating):
   ```go
   zoneSuffix := fmt.Sprintf(".zones.%s", catalogZoneName)
   for owner := range zd.Data.IterBuffered() {
       if strings.HasSuffix(owner.Key, zoneSuffix) {
           zd.Data.Remove(owner.Key)
       }
   }
   ```

2. Generate PTR records for zones:
   ```go
   ownerName := fmt.Sprintf("%s.zones.%s", hash, catalogZoneName)
   ptrStr := fmt.Sprintf("%s 0 IN PTR %s", ownerName, zoneName)
   ```

3. Generate TXT records for groups:
   ```go
   groupOwnerName := fmt.Sprintf("group.%s.zones.%s", hash, catalogZoneName)
   txtRR := &dns.TXT{
       Hdr: dns.RR_Header{...},
       Txt: []string{"group1", "group2", ...}, // All groups in single TXT
   }
   ```

4. Bump SOA serial:
   ```go
   zd.BumpSerial()
   ```

### 7. File Structure

```
tdns-nm/
├── tnm/
│   ├── catalog.go          # NEW: Shared catalog utilities + KDC wrappers
│   └── kdc/
│       ├── catalog.go      # DELETE: Old implementation
│       ├── api.go          # UPDATE: Thin wrapper calling tnm/catalog.go
│       └── ...
└── cmd/
    └── tdns-kdc/
        └── main.go         # UPDATE: Call InitializeCatalogZone()
```

## Implementation Steps

### Phase 1: Create `tnm/catalog.go`
1. Create new `tnm/catalog.go` file
2. Implement `GenerateCatalogZone()` function:
   - Query KDC database for active zones
   - Query components for each zone's service
   - Filter to active components only
   - Use `tdns.CreateAutoZone()` to create zone
   - Add version TXT record
   - Generate zone and group records (RFC 9432 format)
   - Use `tdns.generateZoneHash()` for opaque IDs
   - Register with `tdns.Zones`
3. Implement `InitializeCatalogZone()` function
4. Add helper functions as needed

### Phase 2: Update API Handler
1. Update `tnm/kdc/api.go:APIKdcCatalog()`:
   - Remove direct `GenerateCatalogZone()` call
   - Call `tnm.GenerateCatalogZone()` instead
   - Keep "component" terminology in responses
2. Test API endpoint

### Phase 3: Add Auto-Initialization
1. Add `InitializeCatalogZone()` call to `cmd/tdns-kdc/main.go:startKdc()`
2. Place after database initialization, before engine start
3. Handle errors appropriately
4. Test startup behavior

### Phase 4: Cleanup
1. Delete `tnm/kdc/catalog.go` (old implementation)
2. Update any remaining references
3. Test full catalog zone lifecycle

## Testing Checklist

- [ ] Catalog zone generation via API works
- [ ] Generated catalog zone is RFC 9432 compliant:
  - [ ] Has `version.{catalog}. IN TXT "2"` record
  - [ ] Uses TXT records for groups (not PTR)
  - [ ] Uses PTR records for zone names
  - [ ] Uses `invalid.` for NS record
- [ ] Auto-initialization on startup works
- [ ] Only active zones and components are included
- [ ] Error handling works (returns errors, sets error state)
- [ ] User-facing output uses "component" terminology
- [ ] Zone can be queried via DNS
- [ ] Zone can be transferred via AXFR

## Terminology Mapping

| KDC Term (User-Facing) | Internal tdns Term | Notes |
|------------------------|---------------------|-------|
| component | group | 1:1 mapping, translate at API boundary |
| component ID | group name | Same value, different terminology |

## Error Handling

- **Database errors:** Return error to caller, log error
- **Zone creation errors:** Return error, set `zd.SetError(ConfigError, msg)`
- **Record generation errors:** Log warning, continue with other records
- **Startup initialization errors:** Return error from `startKdc()`, prevent startup

## Future Enhancements (Not in This Migration)

- Automatic catalog zone regeneration on zone/component changes
- KRS catalog zone client support (will also use `tnm/catalog.go`)
- Additional filtering options for zones/components

## Additional Features (Post-Migration)

### Feature 1: Notify Addresses Management

**Requirement:** Support for adding, removing, and listing notify addresses for catalog zones. Since catalog zones are dynamically created via the API, we need API and CLI support for managing notify addresses.

**Implementation:**

#### 1.1 API Endpoints
Add new commands to `APIKdcCatalog`:
- `notify-add`: Add a notify address to a catalog zone
- `notify-remove`: Remove a notify address from a catalog zone
- `notify-list`: List all notify addresses for a catalog zone

**API Request Format:**
```json
{
  "command": "notify-add",
  "catalog": "catalog.example.com.",
  "address": "192.0.2.1:53"
}
```

**Implementation Details:**
- Store notify addresses in `zd.Downstreams` field (ZoneData.Downstreams)
- Validate address format (IP:port)
- Ensure addresses are unique (no duplicates)
- Update zone immediately (no regeneration needed)
- Use existing `tdns` notify mechanism (`zd.Downstreams`)

#### 1.2 CLI Commands
Add to `kdc-cli`:
- `kdc-cli catalog notify add --cat <catalog> --addr <IP:port>`
- `kdc-cli catalog notify remove --cat <catalog> --addr <IP:port>`
- `kdc-cli catalog notify list --cat <catalog>`

#### 1.3 Persistence
- Notify addresses should be persisted (see Feature 2: Persistence)
- When loading catalog zone from disk, restore notify addresses

### Feature 2: Persistence

**Requirement:** Catalog zones and dynamically configured zones need to be persisted to disk for recovery across restarts. This includes:
1. Writing zone files to disk
2. Generating YAML config for dynamically configured zones
3. Loading zones from disk on startup

**Configuration:**

Add new configuration section to `tdns` config (e.g., `tdns-auth.yaml`):
```yaml
dynamiczones:
  storage: persistent  # or "memory" (default: "memory")
  configfile: /etc/tdns/dynamic-zones.yaml  # Absolute path to dynamic config file
  zonedirectory: /var/lib/tdns/zones  # Absolute path to zone file directory
```

**Field Descriptions:**
- `storage`: `memory` (default) or `persistent`
  - `memory`: Zones only exist in memory, lost on restart
  - `persistent`: Zones are saved to disk and loaded on startup
- `configfile`: Absolute path to YAML file where dynamic zone configs are stored
  - Server must have write access to this file
  - File format matches existing zone config format
  - Server may create file if it doesn't exist
- `zonedirectory`: Absolute path to directory where zone files are written
  - Server must have write access to this directory
  - Server may create directory if it doesn't exist
  - Zone files use standard zone file format

#### 2.1 Zone File Persistence

**For Catalog Zones (Primary):**
- When `storage: persistent`:
  - After catalog zone generation/update, write zone file to `{zonedirectory}/{catalog-zone-name}.zone`
  - Use `zd.WriteZoneFile()` or equivalent to write zone data
  - Include all records (SOA, version TXT, PTR, group TXT records)

**For Member Zones (Secondary, from catalog):**
- When `storage: persistent`:
  - After auto-configuration from catalog, write zone file to `{zonedirectory}/{member-zone-name}.zone`
  - Write zone file after successful zone transfer (when zone data is available)
  - Update zone file on subsequent transfers

#### 2.2 Dynamic Config File Generation

**Format:**
The dynamic config file should follow the same format as the main zone config file:
```yaml
zones:
  - name: catalog.example.com.
    zonefile: /var/lib/tdns/zones/catalog.example.com.zone
    type: primary
    store: map
    options: [catalog-zone]
    notify: [ "192.0.2.1:53", "192.0.2.2:53" ]
    # ... other fields as needed

  - name: example.com.
    zonefile: /var/lib/tdns/zones/example.com.zone
    type: secondary
    store: map
    primary: 192.0.2.10:53
    options: [automatic-zone]
    source_catalog: catalog.example.com.
    # ... other fields as needed
```

**Implementation:**
- Generate config entry when zone is created/configured
- Update config entry when zone properties change (e.g., notify addresses)
- Remove config entry when zone is deleted
- Use atomic writes (write to temp file, then rename) to avoid corruption
- Merge dynamic config with main config at startup (if supported) or load separately

#### 2.3 Loading on Startup

**For Catalog Zones:**
1. Check if catalog zone exists in `tdns.Zones`
2. If not and `storage: persistent`:
   - Check if zone file exists in `zonedirectory`
   - If exists, load zone from file using `zd.ReadZoneFile()`
   - Load notify addresses from dynamic config file
   - Register with `tdns.Zones`
   - Mark as catalog zone (`OptCatalogZone`)

**For Member Zones (Secondary):**
1. On startup, load dynamic config file
2. For each zone in dynamic config:
   - Check if zone file exists
   - If exists, load zone from file
   - Register with `tdns.Zones`
   - If `type: secondary` and `primary` is set, trigger zone transfer
   - Restore `SourceCatalog` field

**Load Order:**
1. Load main config file (static zones)
2. Load dynamic config file (dynamic zones)
3. Initialize catalog zones (if configured)
4. Process catalog zones to auto-configure member zones

#### 2.4 File Management

**Zone Files:**
- Write zone files atomically (write to temp, then rename)
- Use standard zone file format
- Include all zone data (RRs, RRSIGs if signed)

**Config File:**
- Use YAML format matching main config
- Write atomically (write to temp, then rename)
- Include all zone metadata (type, store, options, notify, etc.)
- Track `SourceCatalog` for member zones

**Error Handling:**
- If zone file is corrupted, log error and skip loading that zone
- If config file is corrupted, log error and start with empty dynamic config
- If directory doesn't exist, create it with appropriate permissions
- If file write fails, log error but continue operation (zone remains in memory)

#### 2.5 Integration Points

**In `tnm/kdc/catalog.go:GenerateCatalogZone()`:**
- After successful generation, if `storage: persistent`:
  - Write zone file to `zonedirectory`
  - Update/add entry in dynamic config file

**In `tdns/v2/catalog.go:AutoConfigureZonesFromCatalog()`:**
- After successful zone creation, if `storage: persistent`:
  - Write zone file to `zonedirectory` (after first transfer)
  - Add entry to dynamic config file

**In `cmd/tdns-kdc/main.go:startKdc()`:**
- Before initializing catalog zone:
  - Load dynamic config file (if exists)
  - Load zone files for zones in dynamic config
  - Register zones with `tdns.Zones`

**In `tdns/v2/main_initfuncs.go:MainInit()`:**
- After loading main config:
  - Check `dynamiczones.storage` setting
  - If `persistent`, load dynamic config file
  - Load zone files for dynamic zones

#### 2.6 Configuration Validation

- Validate that `configfile` path is absolute
- Validate that `zonedirectory` path is absolute
- Validate that paths exist or can be created
- Validate file/directory permissions (read/write access)
- If validation fails, log error and fall back to `memory` mode

#### 2.7 Migration Considerations

- Existing catalog zones in memory will be lost on restart until persistence is enabled
- After enabling persistence, existing zones should be saved manually (via API) or regenerated
- Dynamic config file can be manually edited (server will overwrite on next change)
- Zone files can be manually edited (server will overwrite on next update)

## Dependencies

- `github.com/johanix/tdns/v2` - For catalog zone functions
- `github.com/miekg/dns` - For DNS record creation
- KDC database access via `*kdc.KdcDB`
- `tdns.Zones` map for zone registration

## Notes

- No backward compatibility needed (no installed base)
- KDC retains "component" terminology for all user-facing output
- Implementation uses "group" internally when calling `tdns` functions
- Translation happens at the API boundary in `tnm/catalog.go`
- `tnm/catalog.go` is designed to be shared with future KRS catalog support
