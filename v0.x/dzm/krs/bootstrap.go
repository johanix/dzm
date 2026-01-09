/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Bootstrap client implementation for KRS
 */

package krs

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/johanix/dzm/v0.x/dzm"
	"github.com/johanix/dzm/v0.x/dzm/kdc"
	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/johanix/tdns/v0.x/tdns/edns0"
	"github.com/johanix/tdns/v0.x/tdns/hpke"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// BootstrapConfig represents the configuration generated during bootstrap
type BootstrapConfig struct {
	Service    ServiceConfig    `yaml:"service"`
	Log        LogConfig        `yaml:"log"`
	ApiServer  ApiServerConfig  `yaml:"apiserver"`
	DnsEngine  DnsEngineConfig  `yaml:"dnsengine"`
	Krs        KrsBootstrapConf `yaml:"krs"`
}

type ServiceConfig struct {
	Name    string `yaml:"name"`
	Verbose bool   `yaml:"verbose"`
	Debug   bool   `yaml:"debug"`
}

type LogConfig struct {
	File string `yaml:"file"`
}

type ApiServerConfig struct {
	UseTLS    bool     `yaml:"usetls,omitempty"` // Always true - omitted from config (defaults to true)
	Addresses []string `yaml:"addresses"`
	ApiKey    string   `yaml:"apikey"`
	CertFile  string   `yaml:"certfile"`
	KeyFile   string   `yaml:"keyfile"`
	BaseURL   string   `yaml:"baseurl,omitempty"` // Base URL for API client (used by krs-cli, not by tdns-krs)
}

type DnsEngineConfig struct {
	Addresses  []string `yaml:"addresses"`
	Transports []string `yaml:"transports"`
	CertFile   string   `yaml:"certfile,omitempty"`
	KeyFile    string   `yaml:"keyfile,omitempty"`
}

type KrsBootstrapConf struct {
	Database    DatabaseConf `yaml:"database"`
	Node        NodeConf     `yaml:"node"`
	ControlZone string       `yaml:"control_zone"`
	UseChunk    bool         `yaml:"use_chunk"`
}

// RunEnroll performs the complete enrollment process
// blobFile: Path to enrollment blob file
// configDir: Directory where config and keys will be written (default: /etc/tdns)
// notifyAddress: IP:port address where KDC should send NOTIFY messages
// Returns: error
func RunEnroll(blobFile string, configDir string, notifyAddress string) error {
	// 1. Parse bootstrap blob file
	blob, err := kdc.ParseBootstrapBlob(blobFile)
	if err != nil {
		return fmt.Errorf("failed to parse bootstrap blob: %v", err)
	}

	log.Printf("KRS: Parsed enrollment blob for node %s", blob.NodeID)

	// 2. Generate HPKE keypair
	hpkePubKey, hpkePrivKey, err := hpke.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate HPKE keypair: %v", err)
	}
	log.Printf("KRS: Generated HPKE keypair")

	// 3. Generate SIG(0) keypair (Ed25519)
	sig0Key := new(dns.KEY)
	sig0Key.Algorithm = dns.ED25519
	sig0Key.Flags = 256 // SIG(0) key flag
	sig0Key.Protocol = 3
	sig0Key.Header().Name = blob.NodeID
	sig0Key.Header().Rrtype = dns.TypeKEY
	sig0Key.Header().Class = dns.ClassINET
	sig0Key.Header().Ttl = 3600

	sig0PrivKey, err := sig0Key.Generate(256)
	if err != nil {
		return fmt.Errorf("failed to generate SIG(0) keypair: %v", err)
	}

	// Get SIG(0) public key as DNSKEY string
	sig0PubKeyStr := sig0Key.String()
	log.Printf("KRS: Generated SIG(0) keypair")

	// 4. Create bootstrap request
	// Use the provided notify address (from command line flag)
	bootstrapReq := map[string]interface{}{
		"hpke_pubkey":    hex.EncodeToString(hpkePubKey),
		"sig0_pubkey":    sig0PubKeyStr,
		"auth_token":     blob.Token,
		"timestamp":      time.Now().Format(time.RFC3339),
		"notify_address": notifyAddress,
	}

	reqJSON, err := json.Marshal(bootstrapReq)
	if err != nil {
		return fmt.Errorf("failed to marshal bootstrap request: %v", err)
	}

	// 5. Encrypt bootstrap request using HPKE Base mode
	// Decode KDC HPKE public key from hex
	kdcHpkePubKey, err := hex.DecodeString(blob.KdcHpkePubKey)
	if err != nil {
		return fmt.Errorf("failed to decode KDC HPKE public key: %v", err)
	}

	encryptedReq, _, err := hpke.Encrypt(kdcHpkePubKey, nil, reqJSON)
	if err != nil {
		return fmt.Errorf("failed to encrypt bootstrap request: %v", err)
	}
	log.Printf("KRS: Encrypted enrollment request (length: %d)", len(encryptedReq))

	// 6. Create CHUNK record with encrypted bootstrap request
	chunk := &core.CHUNK{
		Format:     core.FormatJSON,
		HMACLen:    0, // No HMAC for bootstrap
		HMAC:       nil,
		Sequence:   0,
		Total:      0, // Total=0 indicates bootstrap/manifest
		DataLength: uint16(len(encryptedReq)),
		Data:       encryptedReq,
	}

	chunkRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("_bootstrap.%s", blob.ControlZone),
			Rrtype: core.TypeCHUNK,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Data: chunk,
	}

	// 7. Create DNS UPDATE message
	updateMsg, err := tdns.CreateUpdate(blob.ControlZone, []dns.RR{chunkRR}, []dns.RR{})
	if err != nil {
		return fmt.Errorf("failed to create DNS UPDATE: %v", err)
	}

	// 8. Sign UPDATE with SIG(0)
	// Convert Ed25519 private key to PEM format for PrepareKeyCache
	sig0PrivKeyPEM, err := tdns.PrivateKeyToPEM(sig0PrivKey)
	if err != nil {
		return fmt.Errorf("failed to convert SIG(0) key to PEM: %v", err)
	}

	// Create PrivateKeyCache using PrepareKeyCache
	pkc, err := tdns.PrepareKeyCache(sig0PrivKeyPEM, sig0PubKeyStr)
	if err != nil {
		return fmt.Errorf("failed to prepare SIG(0) key cache: %v", err)
	}

	// Create Sig0ActiveKeys structure for signing
	sak := &tdns.Sig0ActiveKeys{
		Keys: []*tdns.PrivateKeyCache{pkc},
	}

	signedMsg, err := tdns.SignMsg(*updateMsg, blob.ControlZone, sak)
	if err != nil {
		return fmt.Errorf("failed to sign DNS UPDATE: %v", err)
	}
	log.Printf("KRS: Signed DNS UPDATE with SIG(0)")

	// 9. Send UPDATE to KDC
	// Validate bootstrap address is present
	if blob.KdcBootstrapAddress == "" {
		return fmt.Errorf("bootstrap blob is missing kdc_bootstrap_address field - the KDC configuration is incomplete. Please regenerate the bootstrap blob with a properly configured KDC (kdc_bootstrap_address must be set in KDC config)")
	}

	// Parse KDC bootstrap address (IP:port)
	host, port, err := net.SplitHostPort(blob.KdcBootstrapAddress)
	if err != nil {
		return fmt.Errorf("invalid KDC bootstrap address format '%s': %v (expected format: IP:port or hostname:port)", blob.KdcBootstrapAddress, err)
	}

	// Resolve hostname if needed
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("failed to resolve KDC address %s: %v", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses found for KDC host %s", host)
	}

	kdcAddr := net.JoinHostPort(addrs[0], port)
	log.Printf("KRS: Sending enrollment UPDATE to %s", kdcAddr)

	client := new(dns.Client)
	client.Timeout = 10 * time.Second

	resp, _, err := client.Exchange(signedMsg, kdcAddr)
	if err != nil {
		return fmt.Errorf("failed to send DNS UPDATE: %v", err)
	}

	// 10. Extract and process response from CHUNK EDNS(0) option
	// KDC always returns a CHUNK option with either success or error details
	opt := resp.IsEdns0()
	if opt == nil {
		return fmt.Errorf("no EDNS(0) option in response (expected CHUNK option with bootstrap response)")
	}

	chunkOpt, found := edns0.ExtractChunkOption(opt)
	if !found {
		return fmt.Errorf("no CHUNK EDNS(0) option in response (expected CHUNK option with bootstrap response)")
	}

	contentType, encryptedData, err := edns0.ParseBootstrapConfirmation(chunkOpt)
	if err != nil {
		return fmt.Errorf("failed to parse bootstrap response: %v", err)
	}

	if contentType != edns0.CHUNKContentTypeBootstrapConfirmation {
		return fmt.Errorf("unexpected content type in response: %d (expected %d)", contentType, edns0.CHUNKContentTypeBootstrapConfirmation)
	}

	// 11. Decrypt response (may be encrypted or unencrypted)
	// Try to decrypt first (for encrypted responses - both success and error can be encrypted)
	var decryptedData []byte
	decryptedData, err = hpke.DecryptAuth(hpkePrivKey, kdcHpkePubKey, encryptedData)
	if err != nil {
		// Decryption failed - might be unencrypted error message (for errors before KDC has node's pubkey)
		// Only try unencrypted if RCODE indicates an error
		if resp.Rcode != dns.RcodeSuccess {
			log.Printf("KRS: Failed to decrypt response (may be unencrypted error): %v", err)
			decryptedData = encryptedData // Use as-is, might be unencrypted error
		} else {
			// RCODE is SUCCESS but decryption failed - this is unexpected
			return fmt.Errorf("failed to decrypt bootstrap confirmation: %v (RCODE was SUCCESS, so response should be encrypted)", err)
		}
	}

	var confirmation edns0.BootstrapConfirmation
	if err := json.Unmarshal(decryptedData, &confirmation); err != nil {
		return fmt.Errorf("failed to parse response JSON: %v", err)
	}

	// Check if this is an error response
	if confirmation.Status == "error" {
		errorMsg := confirmation.ErrorMessage
		if errorMsg == "" {
			errorMsg = "Unknown error"
		}
		return fmt.Errorf("bootstrap failed: %s (RCODE: %s)", errorMsg, dns.RcodeToString[resp.Rcode])
	}

	// Validate success confirmation
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("bootstrap UPDATE failed with RCODE %s (but received success confirmation - this is unexpected)", dns.RcodeToString[resp.Rcode])
	}

	if confirmation.Status != "success" {
		return fmt.Errorf("bootstrap confirmation status: %s (error: %s)", confirmation.Status, confirmation.ErrorMessage)
	}

	if confirmation.NodeID != blob.NodeID {
		return fmt.Errorf("confirmation node ID mismatch: expected %s, got %s", blob.NodeID, confirmation.NodeID)
	}

	log.Printf("KRS: Enrollment confirmation received and validated for node %s", confirmation.NodeID)

	// 12. Write key files
	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Write HPKE private key
	hpkeKeyFile := filepath.Join(configDir, fmt.Sprintf("%s.hpke.privatekey", strings.TrimSuffix(blob.NodeID, ".")))
	hpkeKeyContent := fmt.Sprintf(`# KRS HPKE Private Key (X25519)
# Generated: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
# 
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone.
#
# Public Key: %s
#
%s
`, time.Now().Format(time.RFC3339), hex.EncodeToString(hpkePubKey), hex.EncodeToString(hpkePrivKey))

	if err := os.WriteFile(hpkeKeyFile, []byte(hpkeKeyContent), 0600); err != nil {
		return fmt.Errorf("failed to write HPKE private key: %v", err)
	}
	log.Printf("KRS: Wrote HPKE private key to %s", hpkeKeyFile)

	// Write SIG(0) private key (PEM format)
	sig0KeyFile := filepath.Join(configDir, fmt.Sprintf("%s.sig0.privatekey", strings.TrimSuffix(blob.NodeID, ".")))
	// Reuse sig0PrivKeyPEM from earlier (already converted to PEM for PrepareKeyCache)
	if err := os.WriteFile(sig0KeyFile, []byte(sig0PrivKeyPEM), 0600); err != nil {
		return fmt.Errorf("failed to write SIG(0) private key: %v", err)
	}
	log.Printf("KRS: Wrote SIG(0) private key to %s", sig0KeyFile)

	// 13. Generate API certs (if needed)
	// For now, we'll generate a self-signed certificate for localhost
	certFile, keyFile, err := generateAPICerts(configDir, blob.NodeID)
	if err != nil {
		return fmt.Errorf("failed to generate API certificates: %v", err)
	}
	log.Printf("KRS: Generated API certificates: %s, %s", certFile, keyFile)

	// 14. Ensure database directory exists (before generating config)
	// The database DSN is hardcoded in the config, so we check it here
	dbDSN := "/var/lib/tdns/krs.db"
	if err := dzm.EnsureDatabaseDirectory(dbDSN); err != nil {
		return fmt.Errorf("failed to ensure database directory: %v", err)
	}
	log.Printf("KRS: Database directory ready: %s", filepath.Dir(dbDSN))

	// 15. Generate config file
	configFile := filepath.Join(configDir, "tdns-krs.yaml")
	// Construct baseurl with /api/v1 path (API always uses TLS, no trailing slash)
	apiAddress := "127.0.0.1:8990"
	baseURL := fmt.Sprintf("https://%s/api/v1", apiAddress)
	config := BootstrapConfig{
		Service: ServiceConfig{
			Name:    "TDNS-KRS",
			Verbose: true,
			Debug:   false,
		},
		Log: LogConfig{
			File: "/var/log/tdns/tdns-krs.log",
		},
		ApiServer: ApiServerConfig{
			// UseTLS not set - omitted from config (defaults to true in tdns)
			Addresses: []string{apiAddress},
			ApiKey:    generateApiKey(),
			CertFile:  certFile,
			KeyFile:   keyFile,
			BaseURL:   baseURL, // Base URL for krs-cli API client (includes /api/v1/ path)
		},
		DnsEngine: DnsEngineConfig{
			Addresses:  []string{notifyAddress}, // Use notify address as primary DNS engine address
			Transports: []string{"do53"},
			CertFile:   certFile,
			KeyFile:    keyFile,
		},
		Krs: KrsBootstrapConf{
			Database: DatabaseConf{
				DSN: "/var/lib/tdns/krs.db",
			},
			Node: NodeConf{
				ID:              blob.NodeID,
				LongTermPrivKey: hpkeKeyFile,
				KdcAddress:      blob.KdcBootstrapAddress,
				KdcHpkePubKey:   confirmation.KdcHpkePubKey,
			},
			ControlZone: blob.ControlZone,
			UseChunk:    true, // Use CHUNK format
		},
	}

	configYAML, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Add header comment with generation timestamp
	headerComment := fmt.Sprintf("# This configuration file was auto-generated by krs-cli enroll\n# Generated at: %s\n#\n# WARNING: This file is auto-generated. Manual edits may be overwritten.\n# To regenerate, run: krs-cli enroll --package <blobfile> --configdir <dir>\n#\n", time.Now().Format(time.RFC3339))
	configWithHeader := []byte(headerComment + string(configYAML))

	if err := os.WriteFile(configFile, configWithHeader, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
		log.Printf("KRS: Wrote configuration file to %s", configFile)

	// 16. Success message
	fmt.Printf("\n")
	fmt.Printf("✓ Enrollment completed successfully!\n")
	fmt.Printf("\n")
	fmt.Printf("Configuration written to: %s\n", configDir)
	fmt.Printf("  - Config file: %s\n", configFile)
	fmt.Printf("  - HPKE key: %s\n", hpkeKeyFile)
	fmt.Printf("  - SIG(0) key: %s\n", sig0KeyFile)
	fmt.Printf("  - API cert: %s\n", certFile)
	fmt.Printf("  - API key: %s\n", keyFile)
	fmt.Printf("\n")
	fmt.Printf("Node ID: %s\n", confirmation.NodeID)
	fmt.Printf("KDC HPKE Public Key: %s\n", confirmation.KdcHpkePubKey)
	fmt.Printf("\n")
	fmt.Printf("Next steps:\n")
	fmt.Printf("  1. Review the configuration file: %s\n", configFile)
	fmt.Printf("  2. Adjust settings as needed (database path, addresses, etc.)\n")
	fmt.Printf("  3. Start tdns-krs with: krs-cli daemon start\n")
	fmt.Printf("\n")

	return nil
}

// generateAPICerts generates a self-signed certificate for API server
func generateAPICerts(configDir string, nodeID string) (certFile string, keyFile string, err error) {
	// Create certs subdirectory
	certsDir := filepath.Join(configDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create certs directory: %v", err)
	}

	// Generate private key
	_, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"TDNS-KRS"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(nil, &template, &template, privKey.Public(), privKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %v", err)
	}

	// Write certificate (PEM format)
	certFile = filepath.Join(certsDir, "localhost.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return "", "", fmt.Errorf("failed to write certificate: %v", err)
	}

	// Write private key (PEM format)
	keyFile = filepath.Join(certsDir, "localhost.key")
	keyPEM, err := tdns.PrivateKeyToPEM(privKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert key to PEM: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte(keyPEM), 0600); err != nil {
		return "", "", fmt.Errorf("failed to write private key: %v", err)
	}

	return certFile, keyFile, nil
}

// generateApiKey generates a random API key
func generateApiKey() string {
	// Generate 32 random bytes and encode as hex
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// Fallback to timestamp-based key if crypto/rand fails
		keyStr := fmt.Sprintf("%x", time.Now().UnixNano())
		for len(keyStr) < 64 {
			keyStr += "0"
		}
		return keyStr[:64]
	}
	return hex.EncodeToString(key)
}

