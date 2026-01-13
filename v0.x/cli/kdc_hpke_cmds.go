/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC HPKE CLI commands
 */
package cli

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/johanix/tdns/v0.x/hpke"
	"github.com/spf13/cobra"
)

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

func init() {
	KdcHpkeCmd.AddCommand(kdcHpkeGenerateCmd)
	
	// HPKE command flags
	kdcHpkeGenerateCmd.Flags().String("outfile", "", "Output file path for HPKE private key (required)")
	kdcHpkeGenerateCmd.MarkFlagRequired("outfile")
}
