/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared HPKE key loading functions
 */

package tnm

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// LoadPrivateKey loads a private key from a file path
// The file should contain a hex-encoded 32-byte HPKE private key
// Comments (lines starting with #) and whitespace are ignored
func LoadPrivateKey(keyPath string) ([]byte, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("private key path is empty")
	}

	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %v", keyPath, err)
	}

	// Parse key (skip comments, decode hex)
	keyLines := strings.Split(string(keyData), "\n")
	var keyHex string
	for _, line := range keyLines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keyHex += line
		}
	}

	if keyHex == "" {
		return nil, fmt.Errorf("could not find key in file %s", keyPath)
	}

	// Decode hex key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %v", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes (got %d)", len(key))
	}

	return key, nil
}
