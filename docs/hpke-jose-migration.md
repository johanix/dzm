I’ll create a comprehensive architectural document summarizing our entire discussion.​​​​​​​​​​​​​​​​

Perfect! I’ve created a comprehensive 25,000+ word architectural document that captures our entire discussion in detail.

[View your architecture document](computer:///mnt/user-data/outputs/tdns-jose-migration-architecture.md)

The document includes:

- Complete current architecture description (HPKE, CHUNK RRtype, enrollment flow)
- Detailed JOSE vs HPKE comparison
- Crypto abstraction layer design with code examples
- Enrollment flow generalization
- 7-phase implementation strategy (20 weeks)
- Extensive C implementation considerations
- Migration and compatibility strategies
- Open questions for future resolution

You can download this file on your iPad and reference it whenever needed - either in Claude Co

de or for your own planning. It’s written in Markdown so it’s easy to read and can be converted to other formats if needed.​​​​​​​​​​​​​​​​

# TDNS JOSE Migration Architecture Document

**Date:** January 20, 2026  
**Author:** Discussion between johanix and Claude  
**Purpose:** Architectural planning for adding JOSE (JWS/JWK/JWE) support to TDNS alongside existing HPKE implementation

-----

## Table of Contents

1. [Executive Summary](#executive-summary)
1. [Current Architecture](#current-architecture)
1. [Motivation for JOSE Support](#motivation-for-jose-support)
1. [JOSE vs HPKE Comparison](#jose-vs-hpke-comparison)
1. [Crypto Abstraction Layer Design](#crypto-abstraction-layer-design)
1. [Enrollment Flow Generalization](#enrollment-flow-generalization)
1. [Implementation Strategy](#implementation-strategy)
1. [C Implementation Considerations](#c-implementation-considerations)
1. [Migration and Compatibility](#migration-and-compatibility)
1. [Open Questions and Next Steps](#open-questions-and-next-steps)

-----

## Executive Summary

The TDNS project currently uses HPKE (Hybrid Public Key Encryption) for secure distribution of DNSSEC private keys from a central Key Distribution Center (KDC) to edge Key Receiver Services (KRS). This document outlines a plan to add support for JOSE (JSON Object Signing and Encryption) standards as an alternative cryptographic backend while maintaining the existing HPKE implementation.

**Key Goals:**

- Support both HPKE and JOSE cryptographic backends simultaneously
- Enable implementation of KRS in C for integration with open-source authoritative DNS servers (BIND9, NSD, Knot-DNS)
- Maintain backward compatibility with existing HPKE deployments
- Use well-established, widely-understood standards to facilitate adoption

**Architecture Principle:**
Abstract the cryptographic layer so that HPKE and JOSE become pluggable backends behind a common interface, while keeping all DNS transport, chunking, manifest handling, and distribution logic crypto-agnostic.

-----

## Current Architecture

### Repository Structure

- **tdns**: Core DNS server with DNSSEC support
  - HPKE support: `v2/hpke/`
  - CHUNK RRtype: `v2/core/`
- **tdns-nm**: Network management and key distribution
  - KDC (Key Distribution Center): Central service
  - KRS (Key Receiver Service): Edge receiver

### HPKE Implementation (`v2/hpke/`)

**Key Components:**

- `hpke.go`: Core HPKE functionality
- `hpkekey.go`: Key generation and management
- `hpkequery.go`: DNS query integration
- `hpkeresponse.go`: Response handling

**Capabilities:**

- Private/public key pair generation
- HPKE encryption (Seal) of DNS messages
- HPKE decryption (Open) of encrypted responses
- Integration with DNS queries for encrypted responses
- Support for sealing responses to specific recipient public keys

**HPKE Process:**

1. Generate ephemeral key pair
1. Use recipient’s public key + ephemeral key for hybrid encryption
1. Encrypt plaintext → ciphertext
1. Recipient uses their private key to decrypt

### CHUNK RRtype Implementation (`v2/core/`)

**Purpose:** Handle DNS responses that exceed practical size limits by splitting them into manageable chunks.

**Wire Format:**

```
CHUNK RDATA:
├── ChunkNum (uint16): Sequence number (1-based)
├── NumChunks (uint16): Total chunks in complete message
└── Data ([]byte): Chunk payload
```

**Key Features:**

- Arbitrary data splitting into configurable chunk sizes
- Each chunk self-describes position and total count
- Reassembly validation ensures all chunks present
- Works seamlessly with HPKE-encrypted data (chunks the ciphertext)

**DNS RR Structure:**

- Each chunk is a separate DNS Resource Record
- Same owner name, different RDATA
- Standard DNS RR format (owner, TTL, class, type, RDATA)

### Distribution Architecture

**Distribution Flow:**

1. **KDC Creates Distribution:**
- Encrypts blob (e.g., DNSSEC private keys) with HPKE
- Uses ephemeral key + target node’s public HPKE key
- Creates signed manifest (cleartext JSON, integrity-protected)
- Combines manifest + encrypted blob into “distribution”
1. **Publishing Strategy:**
   
   **Small Distribution (fits in single RR):**
   
   ```
   {nodeid}.{distributionid}.{controlzone} IN CHUNK
   ├── ChunkNum: 1
   ├── NumChunks: 1
   └── Data: [manifest || encrypted_blob]
   ```
   
   **Large Distribution (requires chunking):**
   
   ```
   1.{nodeid}.{distid}.{controlzone} IN CHUNK (ChunkNum=1, NumChunks=N)
   2.{nodeid}.{distid}.{controlzone} IN CHUNK (ChunkNum=2, NumChunks=N)
   ...
   N.{nodeid}.{distid}.{controlzone} IN CHUNK (ChunkNum=N, NumChunums=N)
   ```
1. **KRS Receives Distribution:**
- Receives DNS NOTIFY for new distribution
- Queries for CHUNK RR(s) at appropriate name
- If `NumChunks > 1`, fetches all numbered chunks sequentially
- Reassembles chunks into complete distribution
- Verifies manifest signature
- Decrypts blob with its private HPKE key
- Processes content (e.g., installs DNSSEC keys)

**Manifest Structure (JSON):**

```json
{
    "version": "1.0",
    "timestamp": "2026-01-20T12:00:00Z",
    "content_type": "dnssec-keys",
    "num_chunks": 1,
    "ttl_data": {
        "publish": 3600,
        "activate": 7200,
        "inactive": 86400
    },
    "signature": "base64_signature_data"
}
```

**Manifest Purpose:**

- Metadata about distribution (type, timestamp, chunk count)
- DNSSEC key rollover scheduling parameters (TTLs)
- Integrity protection via signature
- Cleartext allows monitoring/debugging without decryption

**DNS Naming Hierarchy Benefits:**

- Control zone scope: Overall administrative boundary
- Distribution ID: Unique identifier for each distribution event
- Node ID: Target-specific addressing
- Chunk number: Per-chunk addressing when needed

**Transport:** TCP DNS preferred over UDP to avoid packet size constraints.

### Current Enrollment Flow

**Objective:** Securely establish mutual key exchange between KDC and KRS without pre-shared secrets.

**Phase 1: Bootstrap Package (Out-of-Band)**

KDC generates enrollment package containing:

- One-time authentication token (time-limited)
- KDC long-term public HPKE key
- KDC public SIG(0) key (for DNS message signing)
- KDC IP address
- Configuration metadata

Package is Base64-encoded and transported to KRS via secure out-of-band mechanism (e.g., secure email, configuration management, manual setup).

**Phase 2: Activation Window**

KDC operator “activates” the enrollment package:

- Package enters active state
- KDC will accept enrollment requests with that auth token
- Time window: typically 5 minutes
- Prevents replay attacks and limits exposure

**Phase 3: Enrollment Request**

KRS imports enrollment package:

1. Extracts and stores KDC public HPKE key
1. Extracts and stores KDC public SIG(0) key
1. Generates its own key pairs (HPKE + SIG(0))
1. Creates enrollment request containing:
- KRS public HPKE key
- KRS public SIG(0) key
- Authentication token from package
1. Encrypts entire request using KDC’s public HPKE key
1. Sends encrypted request as DNS NOTIFY with EDNS(0) option to KDC IP

**Phase 4: Mutual Key Exchange Complete**

KDC receives enrollment request:

1. Decrypts using its private HPKE key
1. Validates authentication token (correct + within time window)
1. Extracts and stores KRS public keys
1. Both parties now have each other’s encryption + signing keys
1. All future communication can be encrypted and authenticated

**Security Properties:**

- Forward secrecy via ephemeral keys in HPKE
- Time-limited enrollment window prevents token reuse
- Mutual authentication via exchanged public keys
- No long-term shared secrets to manage
- Out-of-band bootstrap provides initial trust anchor

**Current Authentication:** SIG(0) used for DNS message authentication, not TSIG. Preference for SIG(0) due to its public-key approach vs TSIG’s shared secrets.

-----

## Motivation for JOSE Support

### Primary Drivers

1. **Broader Familiarity and Adoption**
- JOSE (JWS/JWK/JWE) are widely-known standards used across web and API ecosystems
- Much larger developer community familiar with JSON Web Tokens
- Extensive documentation, tutorials, and Stack Overflow answers
- Standard debugging tools (jwt.io, online validators)
1. **C Implementation Requirements**
- Need to implement KRS in C for integration with open-source DNS servers
- Target servers: BIND9, NSD, Knot-DNS
- These are all C-based implementations
- Goal: Create KRS module that can be incorporated upstream
1. **Mature Library Ecosystem**
- JOSE has well-established C libraries (cjose, libjwt, jose)
- HPKE is newer (RFC 9180 from 2022)
- HPKE C support requires OpenSSL 3.2+ (late 2023)
- Less mature HPKE C ecosystem with fewer examples
1. **Upstream Acceptance**
- DNS server maintainers more likely to accept code using well-known standards
- Easier to review and maintain JOSE-based code
- Lower barrier to contribution acceptance
- Better long-term maintenance prospects
1. **Standardization and Interoperability**
- JOSE: RFCs 7515 (JWS), 7516 (JWE), 7517 (JWK)
- Years of deployment and security scrutiny
- Well-documented security considerations
- Clear upgrade paths and versioning

### Functionality Parity

JOSE provides equivalent functionality to HPKE for this use case:

- JWE (JSON Web Encryption) provides encryption
- ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static) maintains hybrid encryption model
- JWK (JSON Web Key) provides standardized key representation
- JWS (JSON Web Signing) available if needed beyond SIG(0)

### Why Support Both?

**Not replacing HPKE, but augmenting:**

- HPKE implementation is working well
- Some deployments may prefer compact binary formats
- JOSE brings benefits for broader adoption
- Support both at least until pros/cons better understood
- Allow ecosystem to choose based on needs

**Future Direction:**

- Likely to become Internet-Draft/RFC documenting this approach
- Novel use of JOSE over DNS transport (no known existing projects)
- Practical solution to real operational problem (DNSSEC key distribution)

-----

## JOSE vs HPKE Comparison

### Size and Encoding Considerations

**Common Factor:**

- Both require Base64 encoding for DNS transport
- ~33% encoding overhead present in both cases
- Not a differentiator for this comparison

**JOSE Characteristics:**

- JSON-based format (more verbose)
- JWE Compact Serialization: `header.encrypted_key.iv.ciphertext.tag`
- Each component Base64url-encoded
- More human-readable for debugging

**HPKE Characteristics:**

- Binary format (more compact before encoding)
- Custom serialization
- Less overhead in structure
- Requires custom tooling for inspection

**Impact with TCP DNS:**

- Using TCP removes UDP’s ~512-byte practical limit
- Packet size less critical than in UDP-constrained scenarios
- Chunking handles large responses regardless of format
- Size difference becomes less significant

### Algorithm and Cryptographic Properties

**HPKE:**

- RFC 9180 (2022)
- Hybrid Public Key Encryption
- KEM (Key Encapsulation Mechanism) + AEAD
- Purpose-built for ephemeral key exchange
- Compact ciphertext format

**JOSE/JWE:**

- RFC 7516 (2015)
- Multiple algorithm options
- ECDH-ES + AES-GCM common choice
- More flexible but requires careful algorithm selection
- Established security analysis

**For This Use Case:**
Both provide adequate security:

- Forward secrecy via ephemeral keys
- Authenticated encryption
- Support for common elliptic curves (P-256, P-384)
- Well-understood attack surface

### Library and Tool Support

**HPKE in Go:**

- Native support in recent Go crypto libraries
- Good integration with existing TDNS codebase
- Adequate tooling for current implementation

**HPKE in C:**

- Requires OpenSSL 3.2+ (very recent)
- Limited standalone libraries (hpke-compact, etc.)
- Fewer examples and less documentation
- Smaller community

**JOSE in Go:**

- Multiple mature libraries (go-jose, jwt-go, etc.)
- Extensive examples and documentation
- Large ecosystem

**JOSE in C:**

- cjose (Cisco) - mature, well-maintained
- libjwt - actively developed
- jose (RHEL/Fedora crypto stack)
- Good OpenSSL integration
- Rich documentation and examples

### Developer Experience

**HPKE:**

- More niche expertise required
- Smaller community to draw from
- Less familiar to most developers
- Newer technology with evolving best practices

**JOSE:**

- Familiar to web developers
- Large knowledge base (tutorials, Q&A)
- Standard debugging tools available
- Established patterns and practices

### Integration with DNS Servers

**Target Servers (BIND9, NSD, Knot):**

- All written in C
- All depend on OpenSSL or similar crypto libraries
- None have built-in JOSE or HPKE support
- All maintainers familiar with RFCs and standard crypto

**HPKE Module:**

- New dependency or require OpenSSL 3.2+
- Less familiar to DNS maintainers
- Harder to find developers for maintenance
- Higher barrier to upstream acceptance

**JOSE Module:**

- Well-known standard
- Additional dependency but established libraries
- More reviewers available who understand it
- More likely to be accepted and maintained upstream
- Better documentation for future maintainers

### Summary Table

|Aspect               |HPKE                        |JOSE                      |
|---------------------|----------------------------|--------------------------|
|Maturity             |New (2022)                  |Established (2015)        |
|Size (pre-encoding)  |Compact binary              |Verbose JSON              |
|Size (post-Base64)   |Similar overhead            |Similar overhead          |
|C Libraries          |Limited, recent             |Mature, multiple          |
|Developer Familiarity|Niche                       |Widespread                |
|DNS Integration      |Purpose-built for encryption|General-purpose, adaptable|
|Upstream Acceptance  |Lower (unfamiliar)          |Higher (well-known)       |
|Debugging Tools      |Limited                     |Extensive                 |
|Security             |Well-designed, newer        |Well-analyzed, proven     |
|Documentation        |Growing                     |Extensive                 |

**Conclusion:** For the specific goal of C implementation in DNS servers, JOSE has significant practical advantages despite being slightly more verbose.

-----

## Crypto Abstraction Layer Design

### Design Principle

Create a clean separation between:

- **Crypto-agnostic components:** DNS transport, chunking, manifest handling, distribution flow
- **Crypto-specific components:** Key management, encryption/decryption operations

This allows HPKE and JOSE to be pluggable backends without duplicating the majority of the codebase.

### Common Layer (Crypto-Agnostic)

These components remain unchanged regardless of crypto backend:

**DNS Transport:**

- CHUNK RRtype wire format
- DNS naming scheme: `{num}.{nodeid}.{distid}.{controlzone}`
- NOTIFY mechanism for push notifications
- DNS query/response handling
- TCP preference for transport

**Chunking Logic:**

- Split large data into chunks
- Sequence numbering (ChunkNum, NumChunks)
- Chunk size configuration
- Reassembly and validation
- Works on opaque encrypted blobs

**Manifest Handling:**

- JSON parsing and generation
- Signature verification (SIG(0))
- Metadata extraction (content type, timestamp, TTLs)
- Version handling

**Distribution Flow:**

- NOTIFY triggering
- Query initiation
- Chunk fetching (single or multiple)
- Reassembly
- Content processing

**Authentication:**

- SIG(0) for DNS message signing
- Independent of encryption method
- Remains consistent across crypto backends

### Crypto-Specific Layer

Components that differ between HPKE and JOSE:

**Key Material Representation:**

HPKE:

```go
type HPKEPrivateKey []byte  // Binary format
type HPKEPublicKey []byte   // Binary format
```

JOSE:

```go
type JWK struct {
    Kty string  // "EC"
    Crv string  // "P-256"
    X   string  // Base64url
    Y   string  // Base64url
    D   string  // Base64url (private key only)
    Use string  // "enc"
    Alg string  // "ECDH-ES+A256GCM"
}
```

**Encryption Operations:**

HPKE:

```go
ciphertext := HPKESeal(recipientPublicKey, plaintext)
```

JOSE:

```go
jwe := JWEEncrypt(recipientJWK, plaintext)
// Returns JWE Compact Serialization string
```

**Decryption Operations:**

HPKE:

```go
plaintext, err := HPKEOpen(privateKey, ciphertext)
```

JOSE:

```go
plaintext, err := JWEDecrypt(privateJWK, jwe)
```

**Key Generation:**

HPKE:

```go
privateKey, publicKey := GenerateHPKEKeypair()
```

JOSE:

```go
jwk := GenerateJWK(curveName, keyUse)
// Returns JWK with both public and private components
```

**Key Serialization:**

HPKE:

```go
encodedKey := base64.StdEncoding.EncodeToString(publicKey)
```

JOSE:

```go
jwkJSON, _ := json.Marshal(jwk)
// Already in standard JSON format
```

### Proposed Go Interface

```go
// CryptoBackend defines the interface that both HPKE and JOSE must implement
type CryptoBackend interface {
    // Key Management
    GenerateKeypair() (PrivateKey, PublicKey, error)
    ParsePublicKey(data []byte) (PublicKey, error)
    ParsePrivateKey(data []byte) (PrivateKey, error)
    SerializePublicKey(pubkey PublicKey) ([]byte, error)
    SerializePrivateKey(privkey PrivateKey) ([]byte, error)
    
    // Encryption/Decryption
    Encrypt(recipientPubKey PublicKey, plaintext []byte) ([]byte, error)
    Decrypt(privateKey PrivateKey, ciphertext []byte) ([]byte, error)
    
    // Metadata
    Name() string           // "hpke" or "jose"
    Version() string        // Backend version identifier
}

// PrivateKey and PublicKey are interface types that wrap backend-specific implementations
type PrivateKey interface {
    Backend() string  // Returns "hpke" or "jose"
}

type PublicKey interface {
    Backend() string  // Returns "hpke" or "jose"
}
```

### Concrete Implementations

**HPKE Backend:**

```go
type HPKEBackend struct{}

func (h *HPKEBackend) Name() string { return "hpke" }

func (h *HPKEBackend) GenerateKeypair() (PrivateKey, PublicKey, error) {
    priv, pub := hpke.GenerateKeypair()
    return &HPKEPrivateKey{data: priv}, &HPKEPublicKey{data: pub}, nil
}

func (h *HPKEBackend) Encrypt(recipientPubKey PublicKey, plaintext []byte) ([]byte, error) {
    hpkePub := recipientPubKey.(*HPKEPublicKey)
    return hpke.Seal(hpkePub.data, plaintext), nil
}

// ... other methods
```

**JOSE Backend:**

```go
type JOSEBackend struct{}

func (j *JOSEBackend) Name() string { return "jose" }

func (j *JOSEBackend) GenerateKeypair() (PrivateKey, PublicKey, error) {
    jwk := jose.GenerateJWK("P-256", "enc")
    return &JOSEPrivateKey{jwk: jwk}, &JOSEPublicKey{jwk: jwk.Public()}, nil
}

func (j *JOSEBackend) Encrypt(recipientPubKey PublicKey, plaintext []byte) ([]byte, error) {
    josePub := recipientPubKey.(*JOSEPublicKey)
    encrypter, _ := jose.NewEncrypter(
        jose.A256GCM,
        jose.Recipient{Algorithm: jose.ECDH_ES, Key: josePub.jwk},
        nil,
    )
    jwe, _ := encrypter.Encrypt(plaintext)
    return []byte(jwe.CompactSerialize()), nil
}

// ... other methods
```

### Backend Selection and Registration

```go
var cryptoBackends = map[string]CryptoBackend{
    "hpke": &HPKEBackend{},
    "jose": &JOSEBackend{},
}

func GetCryptoBackend(name string) (CryptoBackend, error) {
    backend, exists := cryptoBackends[name]
    if !exists {
        return nil, fmt.Errorf("unknown crypto backend: %s", name)
    }
    return backend, nil
}
```

### Integration Points

**KDC Distribution Creation:**

```go
func CreateDistribution(nodeid string, content []byte, backend CryptoBackend) (*Distribution, error) {
    // Get node's public key (backend-specific format)
    nodePubKey, err := getNodePublicKey(nodeid)
    
    // Encrypt using selected backend
    ciphertext, err := backend.Encrypt(nodePubKey, content)
    
    // Create manifest with backend identifier
    manifest := Manifest{
        Version:     "1.0",
        Crypto:      backend.Name(),  // "hpke" or "jose"
        Timestamp:   time.Now(),
        ContentType: "dnssec-keys",
        // ... other fields
    }
    
    // Sign manifest (crypto-agnostic)
    signedManifest := signManifest(manifest)
    
    // Combine and optionally chunk
    distribution := combineManifestAndCiphertext(signedManifest, ciphertext)
    
    return distribution, nil
}
```

**KRS Distribution Processing:**

```go
func ProcessDistribution(chunks []ChunkRR) error {
    // Reassemble chunks (crypto-agnostic)
    data := reassembleChunks(chunks)
    
    // Parse manifest
    manifest, ciphertext := splitManifestAndCiphertext(data)
    
    // Verify manifest signature (crypto-agnostic)
    if !verifyManifest(manifest) {
        return errors.New("manifest signature invalid")
    }
    
    // Get appropriate crypto backend
    backend, err := GetCryptoBackend(manifest.Crypto)
    if err != nil {
        return err
    }
    
    // Decrypt using backend
    plaintext, err := backend.Decrypt(krsPrivateKey, ciphertext)
    if err != nil {
        return err
    }
    
    // Process content (crypto-agnostic)
    return processContent(manifest.ContentType, plaintext)
}
```

### Manifest Extensions

Add crypto backend indicator to manifest:

```json
{
    "version": "1.0",
    "crypto": "jose",
    "crypto_params": {
        "alg": "ECDH-ES+A256GCM",
        "enc": "A256GCM"
    },
    "timestamp": "2026-01-20T12:00:00Z",
    "content_type": "dnssec-keys",
    "num_chunks": 3,
    "ttl_data": {
        "publish": 3600,
        "activate": 7200,
        "inactive": 86400
    },
    "signature": "..."
}
```

**Manifest Fields:**

- `crypto`: Identifies backend (“hpke” or “jose”)
- `crypto_params`: Optional backend-specific parameters
- Backward compatible: Old KRS ignores unknown `crypto` values

### Benefits of This Approach

1. **Minimal Code Duplication:** Core logic written once, reused for both backends
1. **Easy Testing:** Can test backends independently and in combination
1. **Future Extensibility:** Adding new backends (e.g., post-quantum crypto) is straightforward
1. **Clear Separation:** Crypto complexity isolated from DNS/distribution logic
1. **Type Safety:** Go interfaces enforce consistent API across backends
1. **Runtime Selection:** Choose backend per distribution or per node

-----

## Enrollment Flow Generalization

### Current Enrollment (HPKE)

**Enrollment Package:**

```
Base64(
    auth_token || 
    kdc_hpke_pubkey ||
    kdc_sig0_pubkey ||
    kdc_address ||
    config
)
```

**Enrollment Request:**

```
HPKE.Seal(kdc_hpke_pubkey,
    krs_hpke_pubkey ||
    krs_sig0_pubkey ||
    auth_token
)
→ Send as DNS NOTIFY with EDNS(0) option
```

### Generalized Enrollment

**Versioned Enrollment Package (JSON):**

```json
{
    "version": "2.0",
    "crypto": "jose",
    "auth_token": "1a2b3c4d5e6f...",
    "kdc_encryption_key": {
        "kty": "EC",
        "crv": "P-256",
        "x": "base64url_encoded_x",
        "y": "base64url_encoded_y",
        "use": "enc",
        "kid": "kdc-2026-01"
    },
    "kdc_signing_key": "base64_sig0_pubkey",
    "kdc_address": "192.0.2.1",
    "kdc_port": 53,
    "control_zone": "kdc.example.com",
    "valid_until": "2026-01-20T12:05:00Z",
    "capabilities": ["hpke", "jose"]
}
```

**HPKE Format (backward compatible):**

```json
{
    "version": "2.0",
    "crypto": "hpke",
    "auth_token": "1a2b3c4d5e6f...",
    "kdc_encryption_key": "base64_encoded_hpke_pubkey",
    "kdc_signing_key": "base64_sig0_pubkey",
    "kdc_address": "192.0.2.1",
    "kdc_port": 53,
    "control_zone": "kdc.example.com",
    "valid_until": "2026-01-20T12:05:00Z"
}
```

**Package Fields:**

- `version`: Package format version (allows evolution)
- `crypto`: Backend identifier (“hpke” or “jose”)
- `auth_token`: One-time authentication token
- `kdc_encryption_key`: Format depends on crypto backend
  - HPKE: Base64-encoded binary public key
  - JOSE: Full JWK object
- `kdc_signing_key`: SIG(0) public key (independent of crypto)
- `kdc_address` / `kdc_port`: Network location
- `control_zone`: DNS zone for distribution
- `valid_until`: Token expiration timestamp
- `capabilities`: Optional list of supported crypto backends (future use)

**Encoding:** JSON package Base64-encoded for transport

### KRS Enrollment Process

**Step 1: Import Package**

```go
func ImportEnrollmentPackage(packageData string) (*EnrollmentConfig, error) {
    // Decode Base64
    jsonData, _ := base64.StdEncoding.DecodeString(packageData)
    
    // Parse JSON
    var pkg EnrollmentPackage
    json.Unmarshal(jsonData, &pkg)
    
    // Validate version
    if pkg.Version != "2.0" {
        return nil, errors.New("unsupported package version")
    }
    
    // Get crypto backend
    backend, err := GetCryptoBackend(pkg.Crypto)
    if err != nil {
        return nil, err
    }
    
    // Parse KDC public key using backend
    kdcPubKey, err := backend.ParsePublicKey(pkg.KDCEncryptionKey)
    
    // Store configuration
    config := &EnrollmentConfig{
        Backend:       backend,
        AuthToken:     pkg.AuthToken,
        KDCPubKey:     kdcPubKey,
        KDCSigKey:     pkg.KDCSigningKey,
        KDCAddress:    pkg.KDCAddress,
        ControlZone:   pkg.ControlZone,
        ValidUntil:    pkg.ValidUntil,
    }
    
    return config, nil
}
```

**Step 2: Generate KRS Keys**

```go
// Use same backend as enrollment package
krsPrivKey, krsPubKey, _ := config.Backend.GenerateKeypair()
krsSigPrivKey, krsSigPubKey := GenerateSIG0Keypair()

// Store keys securely
storeKeys(krsPrivKey, krsSigPrivKey)
```

**Step 3: Create Enrollment Request**

**HPKE Version:**

```go
requestData := struct {
    KRSPubKey   []byte
    KRSSigKey   []byte
    AuthToken   string
}{
    KRSPubKey: serializePublicKey(krsPubKey),
    KRSSigKey: krsSigPubKey,
    AuthToken: config.AuthToken,
}

requestBytes, _ := json.Marshal(requestData)
ciphertext, _ := config.Backend.Encrypt(config.KDCPubKey, requestBytes)
```

**JOSE Version:**

```go
requestData := struct {
    KRSPubKey   json.RawMessage  // JWK JSON
    KRSSigKey   []byte
    AuthToken   string
}{
    KRSPubKey: serializePublicKey(krsPubKey),  // Returns JWK JSON
    KRSSigKey: krsSigPubKey,
    AuthToken: config.AuthToken,
}

requestBytes, _ := json.Marshal(requestData)
ciphertext, _ := config.Backend.Encrypt(config.KDCPubKey, requestBytes)
// ciphertext is JWE Compact Serialization
```

**Step 4: Send Enrollment Request**

```go
// Construct DNS NOTIFY message
notify := &dns.Msg{
    MsgHdr: dns.MsgHdr{
        Opcode: dns.OpcodeNotify,
    },
}

// Add enrollment request in EDNS(0) option
edns := &dns.EDNS0_LOCAL{
    Code: EDNS_ENROLLMENT_REQUEST,
    Data: ciphertext,
}
notify.Extra = append(notify.Extra, &dns.OPT{
    Hdr: dns.RR_Header{
        Name:   ".",
        Rrtype: dns.TypeOPT,
    },
    Option: []dns.EDNS0{edns},
})

// Send to KDC
client := &dns.Client{Net: "tcp"}
client.Exchange(notify, config.KDCAddress+":"+config.KDCPort)
```

### KDC Enrollment Processing

**Step 1: Receive and Decrypt Request**

```go
func ProcessEnrollmentRequest(msg *dns.Msg) error {
    // Extract EDNS(0) enrollment data
    ciphertext := extractEnrollmentData(msg)
    
    // Determine backend (may need to try both, or use hint)
    // For simplicity, assume metadata or try-decrypt approach
    
    backend := determineBackend(ciphertext)
    plaintext, err := backend.Decrypt(kdcPrivKey, ciphertext)
    if err != nil {
        return err
    }
    
    // Parse request
    var req EnrollmentRequest
    json.Unmarshal(plaintext, &req)
    
    return processEnrollment(req)
}
```

**Step 2: Validate and Store**

```go
func processEnrollment(req EnrollmentRequest) error {
    // Validate auth token
    if !isValidToken(req.AuthToken) {
        return errors.New("invalid or expired token")
    }
    
    // Parse KRS public key (backend-specific)
    backend, _ := GetCryptoBackend(getTokenBackend(req.AuthToken))
    krsPubKey, _ := backend.ParsePublicKey(req.KRSPubKey)
    
    // Store KRS keys
    storeNodeKeys(req.NodeID, krsPubKey, req.KRSSigKey)
    
    // Mark token as used
    invalidateToken(req.AuthToken)
    
    return nil
}
```

### Multi-Backend Support Strategies

**Strategy 1: Single Backend Per Node**

- Each KRS chooses one backend during enrollment
- KDC remembers which backend each node uses
- Future distributions use that backend
- Simplest implementation

**Strategy 2: Dual Enrollment**

- KRS can enroll with both HPKE and JOSE keys
- KDC distributes using preferred backend (policy-based)
- Allows gradual migration
- More complex key management

**Strategy 3: Capability Negotiation**

- KRS advertises supported backends in enrollment request
- KDC selects based on policy or KRS preference
- Future-proof for additional backends

**Recommended: Strategy 1 (Start Simple)**

- One backend per node at enrollment time
- Can evolve to dual support later if needed
- Clear mental model for operators

### Backward Compatibility

**Version 1.0 (Current HPKE):**

- Binary enrollment package format
- No explicit crypto field
- Implicit HPKE usage

**Version 2.0 (Generalized):**

- JSON enrollment package
- Explicit `crypto` field
- Supports both HPKE and JOSE

**Migration Path:**

- KDC generates v2.0 packages with `crypto: "hpke"` for existing deployments
- Old KRS can continue with v1.0 packages (deprecated)
- New KRS uses v2.0 packages
- Eventually deprecate v1.0

### Security Considerations

**Token Management:**

- One-time tokens prevent replay
- Time windows limit exposure
- Tokens associated with specific crypto backend

**Key Separation:**

- Encryption keys separate from signing keys
- SIG(0) remains independent of encryption backend
- No key reuse across different purposes

**Forward Secrecy:**

- HPKE provides forward secrecy via ephemeral keys
- JOSE with ECDH-ES provides equivalent property
- Session keys not derivable from long-term keys

**Authentication Flow:**

- OOB package establishes initial trust
- Mutual key exchange in enrollment
- Subsequent messages authenticated via SIG(0) and encrypted

-----

## Implementation Strategy

### Phase 1: Foundation (Weeks 1-2)

**Objective:** Establish crypto abstraction layer in Go codebase

**Tasks:**

1. Define `CryptoBackend` interface
1. Implement HPKE backend wrapper (refactor existing code)
1. Implement JOSE backend (new code)
1. Unit tests for both backends
1. Integration tests with existing CHUNK/manifest code

**Deliverables:**

- `tdns/v2/crypto/` package with backend interface
- `tdns/v2/crypto/hpke/` - HPKE implementation
- `tdns/v2/crypto/jose/` - JOSE implementation
- Comprehensive test suite

**Success Criteria:**

- Both backends pass identical test suites
- Existing HPKE functionality unchanged
- JOSE backend feature-complete

### Phase 2: Enrollment Generalization (Weeks 3-4)

**Objective:** Update enrollment process to support both backends

**Tasks:**

1. Design v2.0 enrollment package format (JSON)
1. Update KDC enrollment package generation
1. Update KRS enrollment package import
1. Implement backend selection logic
1. Test HPKE and JOSE enrollment flows

**Deliverables:**

- Updated `tdns-nm/kdc/` enrollment code
- Updated `tdns-nm/krs/` enrollment code
- Migration guide for operators
- v2.0 enrollment package specification document

**Success Criteria:**

- HPKE enrollment continues working (v1.0 and v2.0)
- JOSE enrollment works with v2.0 packages
- Clear documentation for operators

### Phase 3: Distribution Updates (Weeks 5-6)

**Objective:** Enable distributions using either backend

**Tasks:**

1. Update manifest to include `crypto` field
1. Update KDC distribution creation to use selected backend
1. Update KRS distribution processing to detect backend
1. Test mixed deployments (some nodes HPKE, some JOSE)

**Deliverables:**

- Updated manifest specification
- Backend selection logic in KDC
- Backend detection logic in KRS
- Integration tests for both backends

**Success Criteria:**

- KDC can distribute to HPKE and JOSE nodes simultaneously
- KRS correctly processes distributions regardless of backend
- No regression in existing HPKE deployments

### Phase 4: C Implementation (Weeks 7-10)

**Objective:** Implement KRS in C with JOSE support

**Tasks:**

1. Set up C project structure
1. Implement DNS/CHUNK parsing in C
1. Integrate cjose library for JOSE operations
1. Implement manifest parsing (JSON-C)
1. Implement enrollment flow in C
1. Implement distribution processing in C
1. Extensive testing against Go KDC

**Deliverables:**

- `tdns-nm-c/krs/` - C implementation of KRS
- Build system (Makefile, configure script)
- Documentation for compilation and deployment
- Test suite

**Success Criteria:**

- C KRS enrolls successfully with Go KDC
- C KRS receives and processes JOSE distributions
- Memory safety verified (valgrind, sanitizers)
- Compatible with BIND9/NSD/Knot dependencies

### Phase 5: DNS Server Integration (Weeks 11-14)

**Objective:** Create modules for open-source DNS servers

**Tasks:**

1. Design BIND9 module interface
1. Design NSD module interface
1. Design Knot module interface
1. Implement proof-of-concept module for one server (likely BIND9)
1. Documentation for module integration

**Deliverables:**

- KRS module for at least one DNS server
- Integration guide
- Example configurations
- Upstream contribution proposal

**Success Criteria:**

- Module successfully integrates with target DNS server
- DNSSEC keys automatically distributed and installed
- Minimal performance overhead
- Positive feedback from DNS server maintainers

### Phase 6: Testing and Documentation (Weeks 15-16)

**Objective:** Comprehensive testing and documentation

**Tasks:**

1. End-to-end testing of complete system
1. Performance benchmarking (HPKE vs JOSE)
1. Security audit and penetration testing
1. Write operator documentation
1. Write developer documentation
1. Create example deployments

**Deliverables:**

- Test report comparing HPKE and JOSE
- Performance analysis document
- Security assessment
- Operator guide
- Developer guide
- Example configurations

**Success Criteria:**

- All test scenarios pass
- Performance acceptable for production
- No critical security issues
- Documentation complete and clear

### Phase 7: Internet-Draft (Weeks 17-20)

**Objective:** Document approach for IETF standardization

**Tasks:**

1. Write Internet-Draft for CHUNK RRtype
1. Write Internet-Draft for DNSSEC key distribution architecture
1. Write Internet-Draft for JOSE over DNS (if novel enough)
1. Present at IETF DNSOP working group
1. Incorporate feedback

**Deliverables:**

- draft-tdns-chunk-rrtype
- draft-tdns-dnssec-key-distribution
- Possibly: draft-tdns-jose-dns-transport
- Presentation slides

**Success Criteria:**

- Drafts accepted by working group
- Positive feedback from community
- Path forward for standardization clear

### Parallel Work Streams

**Throughout All Phases:**

- Maintain existing HPKE production deployments
- Gather operator feedback
- Address bugs and issues
- Update documentation based on learnings

### Resource Requirements

**Development:**

- Primary developer (you): 50-75% time
- Optional: Additional developer for C implementation: 25-50% time

**Infrastructure:**

- Test environments for KDC and multiple KRS instances
- DNS server test environments (BIND9, NSD, Knot)
- CI/CD for automated testing

**Documentation:**

- Technical writer (optional but helpful for Internet-Drafts)

### Risk Management

**Technical Risks:**

- JOSE libraries in C may have bugs or limitations
  - Mitigation: Early prototyping, extensive testing
- DNS server integration may be more complex than anticipated
  - Mitigation: Engage with upstream maintainers early
- Performance of JOSE may be inadequate
  - Mitigation: Benchmark early, optimize critical paths

**Adoption Risks:**

- DNS server maintainers may not accept modules
  - Mitigation: Clean code, good documentation, security audit
- Operators may prefer HPKE for compactness
  - Mitigation: Support both, let ecosystem choose

**Timeline Risks:**

- C implementation may take longer than estimated
  - Mitigation: Start simple, iterate, consider contractor help

-----

## C Implementation Considerations

### Target DNS Servers

**BIND9:**

- Most widely deployed authoritative server
- C codebase, modular architecture
- DLZ (Dynamically Loadable Zones) plugin system
- Active development by ISC

**NSD:**

- Authoritative-only server
- C codebase, focused on performance
- Less modular than BIND9
- Maintained by NLnet Labs

**Knot DNS:**

- Modern authoritative server
- C codebase with focus on DNSSEC
- Module system for extensions
- Maintained by CZ.NIC

**Common Characteristics:**

- All use OpenSSL or compatible crypto library
- All have DNSSEC support
- All written in C (C99 or newer)
- All have active maintainer communities

### C Library Ecosystem

**JOSE Libraries:**

**1. cjose (Recommended)**

- Maintained by Cisco
- Mature and well-tested
- Good OpenSSL integration
- Supports JWE, JWS, JWK
- Active maintenance
- Documentation adequate
- License: MIT

**2. libjwt**

- Focus on JWT (JWS)
- Less emphasis on JWE
- Smaller codebase
- Active development
- License: MPL-2.0

**3. jose (RHEL/Fedora)**

- Part of Red Hat crypto stack
- Command-line tools + library
- Good for reference implementation
- May have RHEL-specific dependencies
- License: Apache 2.0

**HPKE Libraries (for comparison):**

**1. OpenSSL 3.2+ (Built-in)**

- Requires recent OpenSSL version
- May not be available on all target systems
- Part of larger dependency
- Best integration if available

**2. hpke-compact**

- Standalone library
- Fewer dependencies
- Less mature
- Limited adoption

### Recommended C Stack

**For KRS Implementation:**

```
Core:
├── C99 or C11 standard
├── POSIX APIs for networking
├── libc (glibc, musl, etc.)

DNS:
├── Custom lightweight DNS message parser
│   (or minimal use of ldns/libunbound if acceptable)

Crypto:
├── OpenSSL 1.1.1+ (for general crypto)
├── cjose (for JOSE operations)
└── Custom SIG(0) implementation (or from BIND9 if allowed)

JSON:
├── json-c (lightweight, widely used)
└── Alternative: cJSON (single-file, simpler)

Utilities:
├── libevent or libuv (for async I/O, optional)
└── Standard POSIX I/O sufficient for simple case
```

### Architecture for C KRS

**Modular Design:**

```
krs/
├── main.c              # Entry point, configuration
├── config.c/.h         # Configuration file parsing
├── enrollment.c/.h     # Enrollment logic
├── distribution.c/.h   # Distribution processing
├── dns.c/.h            # DNS message handling
├── chunk.c/.h          # CHUNK RRtype parsing/reassembly
├── manifest.c/.h       # Manifest parsing/verification
├── crypto_jose.c/.h    # JOSE crypto backend
├── crypto_hpke.c/.h    # HPKE crypto backend (optional)
├── crypto.c/.h         # Crypto abstraction interface
├── sig0.c/.h           # SIG(0) implementation
├── notify.c/.h         # NOTIFY handling
├── storage.c/.h        # Key storage, persistence
└── util.c/.h           # Utilities, logging
```

**Crypto Abstraction in C:**

```c
// crypto.h
typedef struct crypto_backend {
    const char *name;
    
    int (*generate_keypair)(void **priv_key, void **pub_key);
    int (*parse_public_key)(const char *data, size_t len, void **pub_key);
    int (*parse_private_key)(const char *data, size_t len, void **priv_key);
    
    int (*encrypt)(void *pub_key, const uint8_t *plaintext, size_t pt_len,
                   uint8_t **ciphertext, size_t *ct_len);
    int (*decrypt)(void *priv_key, const uint8_t *ciphertext, size_t ct_len,
                   uint8_t **plaintext, size_t *pt_len);
    
    void (*free_public_key)(void *pub_key);
    void (*free_private_key)(void *priv_key);
} crypto_backend_t;

// Get backend by name
crypto_backend_t *crypto_get_backend(const char *name);
```

**JOSE Backend Implementation:**

```c
// crypto_jose.c
#include <cjose/cjose.h>
#include "crypto.h"

static int jose_generate_keypair(void **priv_key, void **pub_key) {
    cjose_jwk_t *jwk = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_256, NULL);
    if (!jwk) return -1;
    
    *priv_key = jwk;
    *pub_key = cjose_jwk_get_public(jwk);  // Extract public JWK
    return 0;
}

static int jose_encrypt(void *pub_key, const uint8_t *plaintext, size_t pt_len,
                        uint8_t **ciphertext, size_t *ct_len) {
    cjose_jwk_t *recipient_key = (cjose_jwk_t *)pub_key;
    
    // Create JWE header
    cjose_header_t *hdr = cjose_header_new(NULL);
    cjose_header_set(hdr, CJOSE_HDR_ALG, "ECDH-ES+A256KW", NULL);
    cjose_header_set(hdr, CJOSE_HDR_ENC, "A256GCM", NULL);
    
    // Encrypt
    cjose_jwe_t *jwe = cjose_jwe_encrypt(recipient_key, hdr, 
                                          plaintext, pt_len, NULL);
    if (!jwe) return -1;
    
    // Serialize to compact format
    const char *compact = cjose_jwe_export(jwe, NULL);
    *ciphertext = (uint8_t *)strdup(compact);
    *ct_len = strlen(compact);
    
    cjose_jwe_release(jwe);
    return 0;
}

static int jose_decrypt(void *priv_key, const uint8_t *ciphertext, size_t ct_len,
                        uint8_t **plaintext, size_t *pt_len) {
    cjose_jwk_t *jwk = (cjose_jwk_t *)priv_key;
    
    // Import JWE
    cjose_jwe_t *jwe = cjose_jwe_import((const char *)ciphertext, ct_len, NULL);
    if (!jwe) return -1;
    
    // Decrypt
    size_t content_len;
    uint8_t *content = cjose_jwe_decrypt(jwe, jwk, &content_len, NULL);
    if (!content) {
        cjose_jwe_release(jwe);
        return -1;
    }
    
    *plaintext = content;
    *pt_len = content_len;
    
    cjose_jwe_release(jwe);
    return 0;
}

crypto_backend_t jose_backend = {
    .name = "jose",
    .generate_keypair = jose_generate_keypair,
    .encrypt = jose_encrypt,
    .decrypt = jose_decrypt,
    // ... other functions
};
```

### Memory Management

**Critical Considerations:**

- No garbage collection in C
- Manual allocation/deallocation required
- Memory leaks are serious issues in long-running daemons
- Use valgrind and AddressSanitizer during development

**Best Practices:**

```c
// Always pair allocations with frees
uint8_t *buffer = malloc(size);
if (!buffer) {
    // Handle allocation failure
    return -1;
}

// Use the buffer
// ...

// Always free
free(buffer);
buffer = NULL;  // Prevent use-after-free
```

**Resource Management:**

```c
// RAII-style pattern with goto cleanup
int process_distribution(const char *data) {
    uint8_t *plaintext = NULL;
    crypto_backend_t *backend = NULL;
    json_object *manifest = NULL;
    int ret = -1;
    
    // Allocate resources
    backend = crypto_get_backend("jose");
    if (!backend) goto cleanup;
    
    manifest = json_tokener_parse(data);
    if (!manifest) goto cleanup;
    
    // ... process
    
    ret = 0;  // Success
    
cleanup:
    if (plaintext) free(plaintext);
    if (manifest) json_object_put(manifest);
    return ret;
}
```

### Error Handling

**Consistent Error Reporting:**

```c
// Return codes
#define KRS_OK          0
#define KRS_ERROR      -1
#define KRS_ENOMEM     -2
#define KRS_EINVAL     -3
#define KRS_ECRYPTO    -4
#define KRS_EDNS       -5

// Logging
#define LOG_ERROR(fmt, ...) \
    fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)

// Usage
int result = crypto_decrypt(key, ct, ct_len, &pt, &pt_len);
if (result != KRS_OK) {
    LOG_ERROR("Decryption failed: %d", result);
    return result;
}
```

### DNS Server Module Integration

**BIND9 DLZ (Dynamically Loadable Zones):**

```c
// Example DLZ module skeleton
#include <dlz_minimal.h>

// Module initialization
int dlz_version(unsigned int *flags) {
    *flags = 0;
    return DLZ_DLOPEN_VERSION;
}

// Create instance
isc_result_t dlz_create(const char *dlzname, unsigned int argc, 
                        char *argv[], void **dbdata, ...) {
    krs_context_t *ctx = malloc(sizeof(krs_context_t));
    if (!ctx) return ISC_R_NOMEMORY;
    
    // Initialize KRS context
    krs_init(ctx, argv);
    
    *dbdata = ctx;
    return ISC_R_SUCCESS;
}

// Destroy instance
void dlz_destroy(void *dbdata) {
    krs_context_t *ctx = (krs_context_t *)dbdata;
    krs_cleanup(ctx);
    free(ctx);
}

// Handle queries (minimal for KRS - mainly for status)
isc_result_t dlz_lookup(const char *zone, const char *name, void *dbdata,
                        dns_sdlzlookup_t *lookup) {
    // KRS doesn't serve data, mainly receives distributions
    return ISC_R_NOTFOUND;
}
```

**Integration Points:**

- Module receives NOTIFY messages via DNS server
- Triggers KRS enrollment or distribution processing
- Installs received keys into DNS server’s key store
- Signals zone reload after key updates

### Build System

**Autotools (Recommended for Portability):**

```bash
# configure.ac
AC_INIT([tdns-krs], [1.0], [support@example.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

# Check for required libraries
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.1])
PKG_CHECK_MODULES([JSON_C], [json-c])
PKG_CHECK_MODULES([CJOSE], [cjose >= 0.6.0])

AC_OUTPUT
```

**CMake (Alternative, Modern):**

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(tdns-krs C)

set(CMAKE_C_STANDARD 99)

# Find dependencies
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSON_C REQUIRED json-c)
pkg_check_modules(CJOSE REQUIRED cjose)

# Source files
add_executable(krs
    src/main.c
    src/config.c
    src/enrollment.c
    src/distribution.c
    src/dns.c
    src/chunk.c
    src/manifest.c
    src/crypto.c
    src/crypto_jose.c
    src/sig0.c
    src/notify.c
    src/storage.c
    src/util.c
)

# Link libraries
target_link_libraries(krs
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CJOSE_LIBRARIES}
)

# Include directories
target_include_directories(krs PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CJOSE_INCLUDE_DIRS}
)
```

### Testing Strategy for C Code

**Unit Tests (Check or cmocka):**

```c
// test_chunk.c
#include <check.h>
#include "chunk.h"

START_TEST(test_chunk_parse) {
    uint8_t rdata[] = {0x00, 0x01, 0x00, 0x03, 'a', 'b', 'c'};
    chunk_t chunk;
    
    int ret = chunk_parse(rdata, sizeof(rdata), &chunk);
    ck_assert_int_eq(ret, KRS_OK);
    ck_assert_int_eq(chunk.num, 1);
    ck_assert_int_eq(chunk.total, 3);
    ck_assert_int_eq(chunk.data_len, 3);
    ck_assert_mem_eq(chunk.data, "abc", 3);
}
END_TEST

Suite *chunk_suite(void) {
    Suite *s = suite_create("Chunk");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_chunk_parse);
    suite_add_tcase(s, tc_core);
    return s;
}
```

**Integration Tests:**

- Test against real Go KDC
- Verify enrollment flow end-to-end
- Test distribution reception and processing
- Validate key installation

**Memory Tests:**

```bash
# Valgrind for memory leaks
valgrind --leak-check=full --show-leak-kinds=all ./krs

# AddressSanitizer during compilation
CFLAGS="-fsanitize=address -g" ./configure
make
./krs
```

### Documentation for C KRS

**README.md:**

- Build instructions for various platforms
- Dependency installation guides
- Configuration examples
- Deployment guide

**INSTALL.md:**

- Detailed build from source
- Distribution-specific packages (future)
- Integration with BIND9/NSD/Knot

**API Documentation:**

- Doxygen comments in header files
- Generate HTML docs with `doxygen`

**Example Doxygen Comment:**

```c
/**
 * @brief Decrypt ciphertext using specified crypto backend
 * 
 * @param backend   Crypto backend to use
 * @param priv_key  Private key for decryption
 * @param ct        Ciphertext buffer
 * @param ct_len    Length of ciphertext
 * @param pt        Pointer to receive plaintext buffer (caller must free)
 * @param pt_len    Pointer to receive plaintext length
 * @return KRS_OK on success, error code on failure
 */
int crypto_decrypt(crypto_backend_t *backend, void *priv_key,
                   const uint8_t *ct, size_t ct_len,
                   uint8_t **pt, size_t *pt_len);
```

### Platform Considerations

**Target Platforms:**

- Linux (primary): Ubuntu, Debian, RHEL, CentOS
- FreeBSD (common for DNS servers)
- OpenBSD (security-focused deployments)

**Compiler Compatibility:**

- GCC 4.9+
- Clang 3.9+
- Ensure C99 compliance

**Endianness:**

- DNS wire format is big-endian
- Use `htons()`, `ntohs()`, `htonl()`, `ntohl()`
- Test on both little-endian (x86) and big-endian (if possible)

**32-bit vs 64-bit:**

- Support both architectures
- Be careful with pointer arithmetic
- Use `size_t` for sizes, `intptr_t` for pointers

-----

## Migration and Compatibility

### Coexistence Strategy

**Principle:** HPKE and JOSE must coexist peacefully, potentially forever.

**Design Goals:**

1. No breaking changes to existing HPKE deployments
1. New deployments can choose either backend
1. Mixed deployments supported (some nodes HPKE, some JOSE)
1. Gradual migration paths available

### Versioning Strategy

**Protocol Versions:**

- **v1.0:** Original HPKE-only implementation (current)
- **v2.0:** Crypto-agnostic with explicit backend selection (new)

**Manifest Versioning:**

**v1.0 Manifest (HPKE implicit):**

```json
{
    "version": "1.0",
    "timestamp": "...",
    "content_type": "...",
    "signature": "..."
}
```

**v2.0 Manifest (Explicit crypto):**

```json
{
    "version": "2.0",
    "crypto": "hpke",
    "timestamp": "...",
    "content_type": "...",
    "signature": "..."
}
```

**Backward Compatibility:**

- v2.0 KRS can process v1.0 manifests (assumes HPKE)
- v1.0 KRS rejects v2.0 manifests with unknown `crypto` field
- Operators must upgrade KRS before KDC sends v2.0 manifests

### Migration Paths

**Path 1: Gradual KRS Upgrade (HPKE → HPKE v2.0)**

1. Upgrade all KRS to v2.0 (still using HPKE)
1. All nodes now support v2.0 manifests
1. Optionally deploy new nodes with JOSE
1. KDC distributes using appropriate backend per node

**Path 2: New Deployment with JOSE**

1. Deploy fresh infrastructure with v2.0 KDC and KRS
1. Use JOSE from day one
1. No migration concerns

**Path 3: Dual Backend Enrollment (Advanced)**

1. KRS enrolls with both HPKE and JOSE keys
1. KDC can distribute using either backend
1. Allows A/B testing of backends
1. Provides redundancy if one backend has issues

### Feature Flags and Configuration

**KDC Configuration:**

```yaml
kdc:
  default_crypto: "jose"  # Default for new enrollments
  supported_crypto: ["hpke", "jose"]
  
  nodes:
    - id: "ns1.example.com"
      crypto: "hpke"  # Override for specific node
    - id: "ns2.example.com"
      crypto: "jose"
```

**KRS Configuration:**

```yaml
krs:
  supported_crypto: ["jose"]  # Can list multiple
  preferred_crypto: "jose"    # Used during enrollment
```

### Monitoring and Observability

**Metrics to Track:**

- Enrollments by backend type
- Distributions sent per backend
- Distribution processing time (HPKE vs JOSE)
- Encryption/decryption performance
- Error rates per backend

**Logging:**

```
[INFO] Node ns1.example.com enrolled with backend: hpke
[INFO] Distribution dist-12345 created for ns1.example.com using hpke
[INFO] Distribution dist-12345 processed successfully (backend: hpke, duration: 15ms)
```

**Alerts:**

- Backend-specific error rate thresholds
- Performance degradation detection
- Enrollment failures by backend

### Rollback Strategy

**If JOSE Has Issues:**

1. Stop creating JOSE enrollments
1. Continue supporting existing JOSE nodes
1. New enrollments use HPKE
1. Eventually migrate JOSE nodes back to HPKE (re-enrollment)

**If HPKE Has Issues:**

- Same strategy in reverse
- Flexibility of dual support provides safety net

### Testing Mixed Deployments

**Test Scenarios:**

1. KDC with 50% HPKE nodes, 50% JOSE nodes
1. Simultaneous distributions to both types
1. Node migration (HPKE → JOSE via re-enrollment)
1. Failure modes (JOSE node receives HPKE distribution, etc.)

**Validation:**

- All nodes receive correct distributions
- No cross-contamination of crypto backends
- Performance acceptable for both backends
- Error handling graceful

-----

## Open Questions and Next Steps

### Open Questions

**1. Performance Comparison**

- **Question:** What is the actual performance difference between HPKE and JOSE in this use case?
- **Impact:** May influence default backend choice
- **Resolution:** Benchmark both implementations in Phase 6

**2. JWE Algorithm Selection**

- **Question:** Which specific JWE algorithms to support? (ECDH-ES, ECDH-ES+A256KW, others?)
- **Impact:** Affects interoperability and security profile
- **Resolution:** Research best practices, consult JOSE experts

**3. Key Rotation Strategy**

- **Question:** How do long-term HPKE/JOSE keys get rotated? Current enrollment flow bootstraps initial keys, but what about rotation?
- **Impact:** Operational security over time
- **Resolution:** Design key rotation protocol (possibly in Phase 3)

**4. DNS Server Upstream Acceptance**

- **Question:** Will BIND9/NSD/Knot maintainers accept KRS modules?
- **Impact:** Determines deployment model (separate daemon vs integrated module)
- **Resolution:** Early engagement with maintainers, proof-of-concept in Phase 5

**5. C Library Maturity**

- **Question:** Are there hidden issues with cjose or other C JOSE libraries that might surface during implementation?
- **Impact:** May require library switching or custom implementation
- **Resolution:** Early prototyping in Phase 4, fallback options identified

**6. Manifest Size Growth**

- **Question:** Does adding crypto metadata to manifest cause size issues?
- **Impact:** May affect chunking behavior or DNS response sizes
- **Resolution:** Monitor manifest sizes, optimize if needed

**7. Multi-Signer Support**

- **Question:** Should distributions support signatures from multiple KDCs (for redundancy)?
- **Impact:** Complexity in manifest verification
- **Resolution:** Out of scope for initial implementation, revisit later

**8. Post-Quantum Crypto**

- **Question:** When and how to add post-quantum crypto support?
- **Impact:** Future-proofing the design
- **Resolution:** Ensure abstraction layer can accommodate PQ algorithms, implement when mature PQ libraries available

### Immediate Next Steps

**Week 1:**

1. ✅ Document architecture (this document)
1. Set up development branches in Git repos
1. Create GitHub issues for Phase 1 tasks
1. Set up CI/CD for automated testing

**Week 2:**

1. Implement `CryptoBackend` interface in Go
1. Refactor existing HPKE code to fit interface
1. Start JOSE backend implementation
1. Begin unit test suite

**Week 3:**

1. Complete JOSE backend implementation
1. Integration testing with existing CHUNK/manifest code
1. Begin enrollment flow updates
1. Document API changes

**Week 4:**

1. Complete enrollment generalization
1. Test HPKE and JOSE enrollment flows
1. Begin distribution updates
1. Performance benchmarking setup

### Long-Term Considerations

**Standardization Path:**

- Target IETF DNSOP working group
- Consider coordination with DPRIVE (DNS privacy) working group
- Engage with broader DNS community early

**Community Building:**

- Open-source release strategy
- Contributor guidelines
- Community feedback channels

**Commercial Considerations:**

- Support model (community vs commercial)
- Trademark/branding considerations
- Documentation for enterprise deployments

-----

## Conclusion

This document outlines a comprehensive plan to add JOSE (JWS/JWK/JWE) support to the TDNS key distribution infrastructure alongside existing HPKE implementation. The approach emphasizes:

1. **Clean Abstraction:** Crypto backends as pluggable modules behind a common interface
1. **Backward Compatibility:** Existing HPKE deployments continue working unchanged
1. **Practical Focus:** C implementation to enable integration with open-source DNS servers
1. **Standards-Based:** Leveraging well-established JOSE RFCs for broader adoption
1. **Operational Flexibility:** Support for both backends allows ecosystem choice

The phased implementation plan provides a clear path from initial abstraction layer through C implementation and eventual DNS server integration. The generalized enrollment flow maintains security properties while accommodating multiple crypto backends.

Key success factors:

- Maintaining dual HPKE/JOSE support provides safety and flexibility
- C implementation with JOSE increases likelihood of upstream DNS server adoption
- Clean abstraction layer enables future crypto backend additions (e.g., post-quantum)
- Thorough testing ensures production readiness for critical DNSSEC key distribution

**Next Action:** Begin Phase 1 implementation of crypto abstraction layer in Go codebase.

-----

## Appendix: References

**RFCs and Standards:**

- RFC 9180: Hybrid Public Key Encryption (HPKE)
- RFC 7515: JSON Web Signature (JWS)
- RFC 7516: JSON Web Encryption (JWE)
- RFC 7517: JSON Web Key (JWK)
- RFC 2931: DNS Request and Transaction Signatures (SIG(0))
- RFC 1996: A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)

**Libraries:**

- cjose: https://github.com/cisco/cjose
- libjwt: https://github.com/benmcollins/libjwt
- json-c: https://github.com/json-c/json-c
- go-jose: https://github.com/go-jose/go-jose

**DNS Servers:**

- BIND9: https://www.isc.org/bind/
- NSD: https://www.nlnetlabs.nl/projects/nsd/
- Knot DNS: https://www.knot-dns.cz/

**Project Repositories:**

- tdns: https://github.com/johanix/tdns
- tdns-nm: https://github.com/johanix/tdns-nm

-----

**Document Version:** 1.0  
**Last Updated:** January 20, 2026  
**Author:** Johan Ihrén (johanix) with Claude  
**Status:** Architecture Planning Document