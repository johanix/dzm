/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Database utility functions for TDNS Node Management
 */

package tnm

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsureDatabaseDirectory ensures that the directory for a database file exists.
// If the directory doesn't exist, it attempts to create it with 0755 permissions.
// Returns an error with helpful instructions if the directory cannot be created or accessed.
//
// Parameters:
//   - dsn: The database file path (e.g., "/var/lib/tdns/krs.db")
//
// Returns:
//   - error: nil if the directory exists or was successfully created, otherwise an error with instructions
func EnsureDatabaseDirectory(dsn string) error {
	dbDir := filepath.Dir(dsn)
	if dbDir == "." || dbDir == "" {
		// Database file is in current directory, no directory to create
		return nil
	}

	// Check if directory exists
	info, err := os.Stat(dbDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist - try to create it
			if err := os.MkdirAll(dbDir, 0755); err != nil {
				return fmt.Errorf("database directory does not exist and cannot be created: %s\n"+
					"Error: %v\n"+
					"Please create the directory manually with appropriate permissions:\n"+
					"  mkdir -p %s\n"+
					"  chmod 755 %s\n"+
					"Or run with sufficient privileges to create the directory", dbDir, err, dbDir, dbDir)
			}
			// Directory created successfully
			return nil
		}
		// Other error (permission denied, etc.)
		return fmt.Errorf("cannot access database directory %s: %v\n"+
			"Please check directory permissions or create it manually:\n"+
			"  mkdir -p %s\n"+
			"  chmod 755 %s", dbDir, err, dbDir, dbDir)
	}

	// Directory exists - verify it's actually a directory
	if !info.IsDir() {
		return fmt.Errorf("database path %s exists but is not a directory", dbDir)
	}

	return nil
}

