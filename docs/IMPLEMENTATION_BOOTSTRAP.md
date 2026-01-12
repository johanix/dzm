# Implementation Plan: Node Bootstrap Process

## Overview

This document outlines the step-by-step implementation plan for the node bootstrap process. Steps are ordered to build incrementally, with each step building on previous work.

## Prerequisites

- Existing KDC database schema
- Existing KRS codebase
- HPKE library (Cloudflare CIRCL) with Auth mode support
- DNS UPDATE handling infrastructure in KDC

## Implementation Steps

### Step 1: Database Schema Updates

**Goal**: Add bootstrap tokens table and update nodes table

**Tasks**:
1. Create `bootstrap_tokens` table migration:
   - `token_id` (PRIMARY KEY)
   - `token_value` (UNIQUE)
   - `node_id`
   - `created_at`
   - `activated_at` (NULL until activated)
   - `expires_at` (NULL until activated)
   - `activated` (BOOLEAN)
   - `used` (BOOLEAN)
   - `used_at` (NULL until used)
   - `created_by` (optional)
   - `comment` (optional)
   - Indexes on: `token_value`, `node_id`, `expires_at`, `activated`, `used`

2. Add `sig0_pubkey` column to `nodes` table:
   - TEXT column for storing SIG(0) public key (DNSKEY format)
   - Index if needed for lookups

3. Add database migration functions:
   - `MigrateBootstrapTokensTable()`
   - `MigrateNodesTableAddSig0Pubkey()`

**Files to Create/Modify**:
- `tdns-nm/v0.x/kdc/db.go` - Add migration functions
- `tdns-nm/v0.x/kdc/db_migrations.go` - Add bootstrap tokens migration

**Testing**:
- Verify table creation
- Verify indexes created
- Test migration rollback

---

### Step 2: KDC HPKE Keypair Management

**Goal**: Ensure KDC has HPKE keypair and can retrieve pubkey

**Tasks**:
1. Add KDC HPKE keypair generation:
   - Generate if not exists
   - Store private key securely (file or config)
   - Store public key in config or database

2. Add config fields:
   - `KdcHpkePrivKey` (path to private key file)
   - `KdcHpkePubKey` (public key bytes or path)
   - `KdcBootstrapAddress` (IP:port for bootstrap requests)

3. Add functions:
   - `GetKdcHpkeKeypair()` - Load or generate KDC HPKE keys
   - `GetKdcHpkePubKey()` - Get public key for bootstrap blob

**Files to Create/Modify**:
- `tdns-nm/v0.x/kdc/config.go` - Add HPKE key config fields
- `tdns-nm/v0.x/kdc/keygen.go` or new `hpke_keys.go` - KDC HPKE key management

**Testing**:
- Generate KDC HPKE keypair
- Verify keypair is valid
- Test key retrieval

---

### Step 3: HPKE Auth Mode Support

**Goal**: Add HPKE Auth mode encryption/decryption functions

**Tasks**:
1. Add `EncryptAuth()` function:
   - Takes sender private key, recipient public key, plaintext
   - Uses HPKE Auth mode (`SetupAuth`)
   - Returns ciphertext + encapsulated key

2. Add `DecryptAuth()` function:
   - Takes recipient private key, sender public key, ciphertext
   - Uses HPKE Auth mode (`SetupAuth`)
   - Returns plaintext

3. Update HPKE wrapper:
   - Add Auth mode functions to `hpke_wrapper.go`
   - Test with existing HPKE test infrastructure

**Files to Create/Modify**:
- `tdns/v0.x/tdns/hpke/hpke_wrapper.go` - Add `EncryptAuth()` and `DecryptAuth()`

**Testing**:
- Test Auth mode encryption/decryption
- Verify sender authentication works
- Test with X25519 keys

---

### Step 4: Bootstrap Token Database Operations

**Goal**: Implement database operations for bootstrap tokens

**Tasks**:
1. Add token generation:
   - `GenerateBootstrapToken(nodeID string) (*BootstrapToken, error)`
   - Generate cryptographically random token (32+ bytes)
   - Store in database with `activated = false`

2. Add token activation:
   - `ActivateBootstrapToken(nodeID string, expirationWindow time.Duration) error`
   - Set `activated = true`
   - Set `activated_at = now`
   - Set `expires_at = now + expirationWindow`

3. Add token validation:
   - `ValidateBootstrapToken(tokenValue string) (*BootstrapToken, error)`
   - Check token exists, is activated, not expired, not used

4. Add token status:
   - `GetBootstrapTokenStatus(nodeID string) (string, error)`
   - Calculate status: generated/active/expired/completed

5. Add token listing:
   - `ListBootstrapTokens() ([]*BootstrapToken, error)`
   - Return all tokens with calculated status

6. Add token purge:
   - `PurgeBootstrapTokens() error`
   - Delete tokens with status "expired" or "completed"

7. Add token marking as used:
   - `MarkBootstrapTokenUsed(tokenValue string) error`
   - Set `used = true`, `used_at = now`

**Files to Create/Modify**:
- `tdns-nm/v0.x/kdc/db.go` - Add bootstrap token functions
- `tdns-nm/v0.x/kdc/structs.go` - Add `BootstrapToken` struct

**Testing**:
- Test token generation
- Test token activation
- Test token validation
- Test status calculation
- Test purge operation

---

### Step 5: Bootstrap Blob Generation (KDC CLI)

**Goal**: Implement `kdc-cli bootstrap generate` command

**Tasks**:
1. Create bootstrap blob structure:
   - JSON with: token, node_id, kdc_hpke_pubkey, kdc_bootstrap_address, control_zone
   - Base64 encode JSON
   - Write to `{nodeid}.bootstrap` file

2. Implement CLI command:
   - `kdc-cli bootstrap generate --nodeid <nodeid> [--comment <comment>]`
   - Generate token via database function
   - Create bootstrap blob JSON
   - Write to file
   - Print file path

3. Add error handling:
   - Check if token already exists for node ID
   - Validate node ID format
   - Handle file write errors

**Files to Create/Modify**:
- `tdns-nm/v0.x/cli/kdc_cmds.go` - Add bootstrap generate command
- `tdns-nm/v0.x/kdc/bootstrap.go` - Add bootstrap blob generation logic (new file)

**Testing**:
- Generate bootstrap blob
- Verify file contents
- Verify token stored in database
- Test with invalid node ID

---

### Step 6: Bootstrap Activation (KDC CLI)

**Goal**: Implement `kdc-cli bootstrap activate` command

**Tasks**:
1. Implement CLI command:
   - `kdc-cli bootstrap activate --nodeid <nodeid>`
   - Call database activation function
   - Set expiration window (configurable, default 5 minutes)

2. Add validation:
   - Check token exists
   - Check token not already activated
   - Check token not already used

3. Add success/error messages

**Files to Create/Modify**:
- `tdns-nm/v0.x/cli/kdc_cmds.go` - Add bootstrap activate command

**Testing**:
- Activate bootstrap token
- Verify activation timestamp set
- Verify expiration timestamp set
- Test double activation (should fail)
- Test activation of non-existent token

---

### Step 7: Bootstrap List and Purge (KDC CLI)

**Goal**: Implement `kdc-cli bootstrap list` and `purge` commands

**Tasks**:
1. Implement list command:
   - `kdc-cli bootstrap list`
   - Query all tokens from database
   - Calculate status for each
   - Display formatted table

2. Implement purge command:
   - `kdc-cli bootstrap purge`
   - Delete tokens with status "expired" or "completed"
   - Optionally delete bootstrap blob files
   - Show count of purged tokens

3. Add status command:
   - `kdc-cli bootstrap status --nodeid <nodeid>`
   - Show detailed status for specific token

**Files to Create/Modify**:
- `tdns-nm/v0.x/cli/kdc_cmds.go` - Add list, purge, status commands

**Testing**:
- List tokens with various statuses
- Purge expired/completed tokens
- Verify tokens deleted from database
- Test status command

---

### Step 8: Bootstrap DNS UPDATE Handler (KDC)

**Goal**: Handle bootstrap DNS UPDATE requests

**Tasks**:
1. Add bootstrap UPDATE handler:
   - Detect bootstrap UPDATE (name `_bootstrap.{control_zone}`)
   - Extract CHUNK record from UPDATE
   - Extract encrypted bootstrap request from CHUNK data
   - Accept UPDATE in good faith (can't verify SIG(0) yet)

2. Implement bootstrap processing:
   - Decrypt bootstrap request using HPKE Auth mode
   - Validate token (exists, activated, not expired, not used)
   - Validate timestamp (recent, within 5 minutes)
   - Validate keys (HPKE pubkey valid, SIG(0) pubkey valid)

3. Store node:
   - Create node record with both pubkeys
   - Set state to "online"
   - Mark token as used

4. Generate confirmation:
   - Create confirmation JSON
   - Encrypt using HPKE Auth mode
   - Create CHUNK EDNS(0) option
   - Attach to UPDATE response

5. Error handling:
   - Rollback transaction on validation failure
   - Return appropriate DNS RCODE
   - Log errors

**Files to Create/Modify**:
- `tdns-nm/v0.x/kdc/dns_handler.go` - Add bootstrap UPDATE handler
- `tdns-nm/v0.x/kdc/bootstrap.go` - Add bootstrap processing logic

**Testing**:
- Send bootstrap UPDATE
- Verify decryption works
- Verify token validation
- Verify node stored correctly
- Test with invalid token (should fail)
- Test with expired token (should fail)
- Verify confirmation in response

---

### Step 9: CHUNK EDNS(0) Option Content Types

**Goal**: Add bootstrap confirmation content type

**Tasks**:
1. Add content type constant:
   - `CHUNKContentTypeBootstrapConfirmation = 2` (in `edns0_chunk.go`)

2. Add bootstrap confirmation structures:
   - `BootstrapConfirmation` struct
   - Helper functions for creating/parsing

3. Update CHUNK option creation:
   - `CreateBootstrapConfirmationOption()` function

**Files to Create/Modify**:
- `tdns/v0.x/tdns/edns0/edns0_chunk.go` - Add bootstrap confirmation content type

**Testing**:
- Create bootstrap confirmation option
- Parse bootstrap confirmation option
- Verify content type handling

---

### Step 10: KRS Bootstrap Client

**Goal**: Implement `krs-cli bootstrap` command

**Tasks**:
1. Parse bootstrap blob file:
   - Read `{nodeid}.bootstrap` file
   - Base64 decode JSON
   - Extract: token, node_id, kdc_hpke_pubkey, kdc_bootstrap_address, control_zone

2. Generate keypairs:
   - HPKE keypair (X25519)
   - SIG(0) keypair (Ed25519)
   - Store private keys securely

3. Create bootstrap request:
   - JSON with: hpke_pubkey, sig0_pubkey, auth_token, timestamp, notify_address
   - Encrypt using HPKE Auth mode

4. Create CHUNK record:
   - Format: JSON
   - Sequence: 0, Total: 0 (bootstrap)
   - Data: Encrypted bootstrap request

5. Create DNS UPDATE:
   - Zone: control_zone (from blob)
   - Name: `_bootstrap.{control_zone}`
   - RR Type: CHUNK
   - Sign with SIG(0)

6. Send UPDATE to KDC:
   - Use `kdc_bootstrap_address` from blob
   - Send DNS UPDATE message

7. Process response:
   - Extract CHUNK EDNS(0) option
   - Decrypt confirmation
   - Validate node_id matches
   - Store KDC HPKE pubkey

8. Generate KRS config:
   - Create config file with:
     - Node ID
     - Control zone
     - KDC address
     - Database path
     - Key storage paths

**Files to Create/Modify**:
- `tdns-nm/v0.x/cli/krs_cmds.go` - Add bootstrap command
- `tdns-nm/v0.x/krs/bootstrap.go` - Add bootstrap client logic (new file)

**Testing**:
- Parse bootstrap blob file
- Generate keypairs
- Create and encrypt bootstrap request
- Send DNS UPDATE
- Receive and decrypt confirmation
- Generate config file
- Test with invalid blob file
- Test with expired token

---

### Step 11: Integration Testing

**Goal**: End-to-end bootstrap flow testing

**Tasks**:
1. Full bootstrap flow test:
   - Generate bootstrap blob
   - Activate bootstrap
   - Run KRS bootstrap
   - Verify node registered in KDC
   - Verify KRS config generated

2. Error scenario testing:
   - Invalid token
   - Expired token
   - Already used token
   - Invalid keys
   - Network errors

3. Edge case testing:
   - Bootstrap blob file corruption
   - Clock skew (timestamp validation)
   - Concurrent bootstrap attempts

**Files to Create/Modify**:
- `tdns-nm/v0.x/kdc/bootstrap_test.go` - Integration tests
- `tdns-nm/v0.x/krs/bootstrap_test.go` - Integration tests

**Testing**:
- Run full bootstrap flow
- Test all error scenarios
- Test edge cases

---

### Step 12: Documentation and Cleanup

**Goal**: Finalize implementation

**Tasks**:
1. Update documentation:
   - CLI command documentation
   - Bootstrap blob format documentation
   - Error message documentation

2. Code cleanup:
   - Remove debug logging
   - Add comments
   - Format code

3. Configuration examples:
   - Sample bootstrap blob file
   - Sample KRS config after bootstrap

**Files to Create/Modify**:
- Update README files
- Add example files
- Code comments

---

## Implementation Order Summary

1. **Database Schema** (Step 1)
2. **KDC HPKE Keys** (Step 2)
3. **HPKE Auth Mode** (Step 3)
4. **Token DB Operations** (Step 4)
5. **Bootstrap Blob Generation** (Step 5)
6. **Bootstrap Activation** (Step 6)
7. **Bootstrap List/Purge** (Step 7)
8. **DNS UPDATE Handler** (Step 8)
9. **CHUNK EDNS(0) Content Types** (Step 9)
10. **KRS Bootstrap Client** (Step 10)
11. **Integration Testing** (Step 11)
12. **Documentation** (Step 12)

## Dependencies

- Steps 1-4 can be done in parallel (database, keys, HPKE, token ops)
- Step 5 depends on Steps 1, 2, 4
- Step 6 depends on Step 4
- Step 7 depends on Step 4
- Step 8 depends on Steps 3, 4, 9
- Step 9 can be done independently
- Step 10 depends on Steps 3, 9
- Steps 11-12 depend on all previous steps

## Estimated Effort

- Steps 1-4: Foundation (2-3 days)
- Steps 5-7: CLI commands (1-2 days)
- Step 8: DNS handler (2-3 days)
- Step 9: EDNS(0) content type (0.5 days)
- Step 10: KRS client (2-3 days)
- Steps 11-12: Testing and docs (1-2 days)

**Total**: ~9-14 days of development time

