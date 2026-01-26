# CHUNK Payload Structure: HPKE vs JOSE

## Overview

This document describes in detail the differences in CHUNK payload content between HPKE and JOSE encryption backends. Both use the same CHUNK manifest structure, but the encrypted payload format differs significantly.

## Common Structure (Both HPKE and JOSE)

**CHUNK Manifest (Total=0):**
- Format: JSON (FormatJSON=1)
- HMAC: SHA-256 HMAC (32 bytes) calculated using node's HPKE public key
- Metadata: JSON object containing:
  - `content`: Content type (e.g., "mgmt_operations", "key_operations")
  - `distribution_id`: Distribution identifier
  - `node_id`: Target node identifier
  - `crypto`: **"hpke"** or **"jose"** (indicates which backend was used)
  - `timestamp`: Unix timestamp for replay protection
  - `distribution_ttl`: TTL for the distribution
  - `retire_time`: Time after which chunks can be retired
  - Additional fields based on content type (zone_count, key_count, operation_count, etc.)
- Payload: Base64-encoded encrypted data (inline if small, or split into chunks)

**CHUNK Data Chunks (Total>0):**
- Format: Same as manifest (FormatJSON=1)
- HMAC: None (HMACLen=0)
- Data: Base64-encoded chunk of the encrypted payload

---

## HPKE Payload Structure

### Encryption Process

1. **Plaintext**: JSON array of `DistributionEntry` objects (operations like roll_key, ping, etc.)
2. **HPKE Encryption**: Uses X25519 HPKE Base mode
   - Generates ephemeral keypair internally
   - Encapsulates shared secret using recipient's long-term public key
   - Encrypts plaintext using AES-128-GCM (or similar)
3. **Ciphertext Format**: `<encapsulated_key (32 bytes)><encrypted_data>`
   - `encapsulated_key`: Ephemeral public key (X25519, 32 bytes)
   - `encrypted_data`: AES-GCM encrypted data with authentication tag

### Transport Format

```text
base64(<ephemeral_pub_key (32 bytes)><encapsulated_key (32 bytes)><encrypted_data>)
```

**Note:** The ephemeral public key appears twice:
- **First 32 bytes**: Explicit ephemeral public key (for compatibility)
- **Next 32 bytes**: Encapsulated key (same value, part of HPKE ciphertext)
- **Remaining bytes**: Encrypted data with authentication tag

### Example Structure

```text
Raw bytes: [32-byte ephemeral][32-byte encapsulated][variable encrypted data]
Base64:    "Q0ZyaENxNGlaRGhrelJDNUpiaFZXY3A4bXhEUkRrM2FIdjc0YzNsTDZ5SkhqbFlsRUszaGZjdHlBUEVIb29yWUxaaXJ3YThrem9nRXBteFhsZ1BQRFc0Z0lvTFZFNW5vTkx4aTg1YjdISXp6c2QwVjFaNGpxZXlUV1UzWHhvVU94S211MFJpS2k0N3kwUUNSZVpId3E1Z0djOEsvS2NON1Z3KzlOTzdRSFJZOXJKK2h4SlBRMStBZWhHYng0Mkp2aWs2bU9ySFFhYXZFMWRHYm80V0pycGZGYjlvTjZBTVdOR25oRmQ2dmQ2ejVyUUx5MDlNMXArb3M4MFIyK3duMVRZL09ES01s"
```

### Decryption Process

1. Decode base64
2. Skip first 32 bytes (duplicate ephemeral)
3. Pass remaining bytes to `hpke.Decrypt()` which expects: `<encapsulated_key><encrypted_data>`
4. HPKE extracts the encapsulated key and decrypts

---

## JOSE Payload Structure

### Encryption Process

1. **Plaintext**: Same JSON array of `DistributionEntry` objects
2. **JOSE Encryption**: Uses JWE (JSON Web Encryption) with:
   - Key Agreement: ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral-Static)
   - Encryption: A256GCM (AES-256 in Galois/Counter Mode)
   - Curve: P-256 (secp256r1)
3. **Ciphertext Format**: JWE Compact Serialization
   - Format: `header.encrypted_key.iv.ciphertext.tag` (5 parts, dot-separated)
   - Each part is base64url-encoded

### JWE Structure

```text
header.encrypted_key.iv.ciphertext.tag
```

Where:
- **`header`**: Base64url-encoded JSON containing:
  - `alg`: "ECDH-ES" (key agreement algorithm)
  - `enc`: "A256GCM" (encryption algorithm)
  - `epk`: Ephemeral public key as JWK (JSON Web Key) - **This is where the ephemeral key is embedded!**
- **`encrypted_key`**: Base64url-encoded encrypted content encryption key (CEK)
  - For ECDH-ES, this may be empty (direct key agreement)
- **`iv`**: Base64url-encoded initialization vector (12 bytes for AES-GCM)
- **`ciphertext`**: Base64url-encoded encrypted data
- **`tag`**: Base64url-encoded authentication tag (16 bytes for AES-GCM)

### Transport Format

```text
base64(JWE_compact_serialization)
```

The JWE compact serialization is already a string (dot-separated), which is then base64-encoded for transport.

### Decryption Process

1. Decode base64 to get JWE compact serialization string
2. Parse the 5 parts (split by dots)
3. Decode each part from base64url
4. Extract ephemeral key from `header.epk` (JWK format)
5. Use JOSE library to decrypt using recipient's private key

---

## Key Differences Summary

| Aspect | HPKE | JOSE |
|--------|------|------|
| **Ephemeral key location** | Explicitly prepended (32 bytes) + embedded in ciphertext | Embedded in JWE header as JWK (JSON) |
| **Ephemeral key format** | Raw 32-byte X25519 public key | JWK (JSON Web Key) with curve parameters |
| **Ciphertext structure** | Binary: `<32 bytes><32 bytes><variable>` | Text: `header.encrypted_key.iv.ciphertext.tag` (dot-separated) |
| **Encoding** | Base64 (standard) | Base64url (URL-safe) for each JWE part, then base64 for transport |
| **Key size** | 32 bytes (X25519) | Variable (P-256 ECDSA, ~65 bytes for public key) |
| **Encryption algorithm** | AES-128-GCM (or similar, HPKE-dependent) | AES-256-GCM (explicitly A256GCM) |
| **Payload size overhead** | ~64 bytes (duplicate ephemeral + encapsulated) | Variable (JWE header JSON + structure) |
| **Metadata** | Same for both (includes `"crypto": "hpke"` or `"crypto": "jose"`) | Same for both |

### Example Sizes

For a typical ping operation (small payload):
- **HPKE**: ~64 bytes overhead + encrypted data
- **JOSE**: ~200-300 bytes overhead (JWE header with JWK) + encrypted data

JOSE typically has higher overhead due to the JSON header structure, but provides standardized JWE format and broader ecosystem compatibility.

---

## Implementation Details

### HPKE Code Path

- **KDC Encryption**: `tdns-nm/tnm/kdc/encrypt.go` (V1) or `tdns-nm/tnm/kdc/encrypt_v2.go` (V2)
- **KRS Decryption**: `tdns-nm/tnm/krs/decrypt.go` (V1) or `tdns-nm/tnm/krs/decrypt_v2.go` (V2)
- **Transport**: `tdns-nm/tnm/hpke_transport.go`

### JOSE Code Path

- **KDC Encryption**: `tdns-nm/tnm/kdc/encrypt_v2.go` (uses crypto abstraction layer)
- **KRS Decryption**: `tdns-nm/tnm/krs/decrypt_v2.go` (uses crypto abstraction layer)
- **Backend**: `tdns/v2/crypto/jose/backend.go`

### Chunk Preparation

Both HPKE and JOSE payloads are prepared in:
- **V1 (HPKE only)**: `tdns-nm/tnm/kdc/chunks.go`
- **V2 (HPKE + JOSE)**: `tdns-nm/tnm/kdc/chunks_v2.go`

The crypto backend is selected based on node's `SupportedCrypto` field and stored in manifest metadata as `"crypto": "hpke"` or `"crypto": "jose"`.
