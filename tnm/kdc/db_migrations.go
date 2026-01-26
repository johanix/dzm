/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Temporary database migrations for upgrading existing databases
 * These migrations should be removed once all databases have been upgraded
 */

package kdc

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

// migrateAddCompletedAtColumn adds the completed_at column to distribution_records if it doesn't exist
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddCompletedAtColumn() error {
	var columnExists bool

	if kdc.DBType == "sqlite" {
		// SQLite: Check if column exists using pragma
		var count int
		err := kdc.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('distribution_records') WHERE name='completed_at'").Scan(&count)
		columnExists = (err == nil && count > 0)
	} else {
		// MySQL/MariaDB: Check if column exists by querying information_schema
		var count int
		err := kdc.DB.QueryRow(
			"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND COLUMN_NAME = 'completed_at'",
		).Scan(&count)
		columnExists = (err == nil && count > 0)
	}

	if columnExists {
		// Column already exists, nothing to do
		return nil
	}

	// Column doesn't exist, add it
	var alterStmt string
	if kdc.DBType == "sqlite" {
		alterStmt = "ALTER TABLE distribution_records ADD COLUMN completed_at DATETIME"
	} else {
		alterStmt = "ALTER TABLE distribution_records ADD COLUMN completed_at TIMESTAMP NULL"
	}

	_, err := kdc.DB.Exec(alterStmt)
	if err != nil {
		// Check if error is "duplicate column" (column already exists - race condition)
		if strings.Contains(err.Error(), "duplicate column") ||
			strings.Contains(err.Error(), "already exists") ||
			strings.Contains(err.Error(), "Duplicate column name") {
			return nil // Column already exists, that's fine
		}
		return fmt.Errorf("failed to add completed_at column: %v", err)
	}
	log.Printf("KDC: Added completed_at column to distribution_records table")
	return nil
}

// migrateAddCompletedStatus updates the status ENUM/CHECK constraint to include 'completed'
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddCompletedStatus() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if constraint already allows 'completed' by trying to update a test record
		// We'll check if we can set status to 'completed' on an existing record
		// If it fails, we need to recreate the table
		var testID, originalStatus string
		err := kdc.DB.QueryRow("SELECT id, status FROM distribution_records LIMIT 1").Scan(&testID, &originalStatus)
		if err == nil && testID != "" {
			// Try to update a record to 'completed' to test the constraint
			_, err = kdc.DB.Exec("UPDATE distribution_records SET status = 'completed' WHERE id = ?", testID)
			if err != nil && strings.Contains(err.Error(), "CHECK constraint failed") {
				// Constraint doesn't allow 'completed', need to recreate table
				log.Printf("KDC: Recreating distribution_records table to update CHECK constraint for 'completed' status")

				// Create new table with correct constraint
				_, err = kdc.DB.Exec(`
					CREATE TABLE IF NOT EXISTS distribution_records_new (
						id TEXT PRIMARY KEY,
						zone_name TEXT NOT NULL,
						key_id TEXT NOT NULL,
						node_id TEXT,
						encrypted_key BLOB NOT NULL,
						ephemeral_pub_key BLOB NOT NULL,
						created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
						expires_at DATETIME,
						status TEXT NOT NULL DEFAULT 'pending',
						distribution_id TEXT NOT NULL,
						completed_at DATETIME,
						FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
						FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
						FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
						CHECK (status IN ('pending', 'delivered', 'active', 'revoked', 'completed'))
					)`)
				if err != nil {
					return fmt.Errorf("failed to create new distribution_records table: %v", err)
				}

				// Copy data
				_, err = kdc.DB.Exec(`
					INSERT INTO distribution_records_new 
					SELECT id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key, 
					       created_at, expires_at, status, distribution_id, completed_at
					FROM distribution_records`)
				if err != nil {
					return fmt.Errorf("failed to copy data to new table: %v", err)
				}

				// Drop old table
				_, err = kdc.DB.Exec("DROP TABLE distribution_records")
				if err != nil {
					return fmt.Errorf("failed to drop old table: %v", err)
				}

				// Rename new table
				_, err = kdc.DB.Exec("ALTER TABLE distribution_records_new RENAME TO distribution_records")
				if err != nil {
					return fmt.Errorf("failed to rename new table: %v", err)
				}

				// Recreate indexes
				indexes := []string{
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_zone_name ON distribution_records(zone_name)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_key_id ON distribution_records(key_id)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_node_id ON distribution_records(node_id)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_status ON distribution_records(status)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_distribution_id ON distribution_records(distribution_id)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_completed_at ON distribution_records(completed_at)",
				}
				for _, idxStmt := range indexes {
					if _, err := kdc.DB.Exec(idxStmt); err != nil {
						log.Printf("KDC: Warning: Failed to recreate index: %v", err)
					}
				}

				log.Printf("KDC: Successfully updated distribution_records table CHECK constraint")
			} else if err == nil {
				// Update succeeded, revert it to original status
				_, _ = kdc.DB.Exec("UPDATE distribution_records SET status = ? WHERE id = ?", originalStatus, testID)
			}
		}
		// If no records exist or constraint already allows 'completed', nothing to do
		return nil
	} else {
		// MySQL/MariaDB: Alter ENUM to include 'completed'
		// Check if 'completed' is already in the ENUM
		var enumValues string
		err := kdc.DB.QueryRow(
			"SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND COLUMN_NAME = 'status'",
		).Scan(&enumValues)
		if err != nil {
			return fmt.Errorf("failed to check status ENUM: %v", err)
		}

		if !strings.Contains(enumValues, "completed") {
			// Update ENUM to include 'completed'
			_, err = kdc.DB.Exec(
				"ALTER TABLE distribution_records MODIFY COLUMN status ENUM('pending', 'delivered', 'active', 'revoked', 'completed') NOT NULL DEFAULT 'pending'",
			)
			if err != nil {
				return fmt.Errorf("failed to update status ENUM: %v", err)
			}
			log.Printf("KDC: Updated status ENUM to include 'completed'")
		}
		return nil
	}
}

// migrateAddActiveDistState updates the state ENUM/CHECK constraint to include 'active_dist'
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddActiveDistState() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if constraint already allows 'active_dist' by trying to update a test record
		var testID, originalState string
		err := kdc.DB.QueryRow("SELECT id, state FROM dnssec_keys LIMIT 1").Scan(&testID, &originalState)
		if err == nil && testID != "" {
			// Try to update a record to 'active_dist' to test the constraint
			_, err = kdc.DB.Exec("UPDATE dnssec_keys SET state = 'active_dist' WHERE id = ?", testID)
			if err != nil && strings.Contains(err.Error(), "CHECK constraint failed") {
				// Constraint doesn't allow 'active_dist', need to recreate table
				log.Printf("KDC: Recreating dnssec_keys table to update CHECK constraint for 'active_dist' state")

				// Create new table with correct constraint
				_, err = kdc.DB.Exec(`
					CREATE TABLE IF NOT EXISTS dnssec_keys_new (
						id TEXT PRIMARY KEY,
						zone_name TEXT NOT NULL,
						key_type TEXT NOT NULL,
						key_id INTEGER NOT NULL,
						algorithm INTEGER NOT NULL,
						flags INTEGER NOT NULL,
						public_key TEXT NOT NULL,
						private_key BLOB NOT NULL,
						state TEXT NOT NULL DEFAULT 'created',
						created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
						published_at DATETIME,
						activated_at DATETIME,
						retired_at DATETIME,
						comment TEXT,
						FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
						CHECK (key_type IN ('KSK', 'ZSK', 'CSK')),
						CHECK (state IN ('created', 'published', 'standby', 'active', 'active_dist', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked'))
					)`)
				if err != nil {
					return fmt.Errorf("failed to create new dnssec_keys table: %v", err)
				}

				// Copy data
				_, err = kdc.DB.Exec(`
					INSERT INTO dnssec_keys_new 
					SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key, 
					       state, created_at, published_at, activated_at, retired_at, comment
					FROM dnssec_keys`)
				if err != nil {
					return fmt.Errorf("failed to copy data to new table: %v", err)
				}

				// Drop old table
				_, err = kdc.DB.Exec("DROP TABLE dnssec_keys")
				if err != nil {
					return fmt.Errorf("failed to drop old table: %v", err)
				}

				// Rename new table
				_, err = kdc.DB.Exec("ALTER TABLE dnssec_keys_new RENAME TO dnssec_keys")
				if err != nil {
					return fmt.Errorf("failed to rename new table: %v", err)
				}

				// Recreate indexes
				indexes := []string{
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_name ON dnssec_keys(zone_name)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_key_type ON dnssec_keys(key_type)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_state ON dnssec_keys(state)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_key_type_state ON dnssec_keys(zone_name, key_type, state)",
				}
				for _, idxStmt := range indexes {
					if _, err := kdc.DB.Exec(idxStmt); err != nil {
						log.Printf("KDC: Warning: Failed to recreate index: %v", err)
					}
				}

				log.Printf("KDC: Successfully updated dnssec_keys table CHECK constraint")
			} else if err == nil {
				// Update succeeded, revert it to original state
				_, _ = kdc.DB.Exec("UPDATE dnssec_keys SET state = ? WHERE id = ?", originalState, testID)
			}
		}
		// If no records exist or constraint already allows 'active_dist', nothing to do
		return nil
	} else {
		// MySQL/MariaDB: Alter ENUM to include 'active_dist'
		// Check if 'active_dist' is already in the ENUM
		var enumValues string
		err := kdc.DB.QueryRow(
			"SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'dnssec_keys' AND COLUMN_NAME = 'state'",
		).Scan(&enumValues)
		if err != nil {
			return fmt.Errorf("failed to check state ENUM: %v", err)
		}

		if !strings.Contains(enumValues, "active_dist") {
			// Update ENUM to include 'active_dist'
			_, err = kdc.DB.Exec(
				"ALTER TABLE dnssec_keys MODIFY COLUMN state ENUM('created', 'published', 'standby', 'active', 'active_dist', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked') NOT NULL DEFAULT 'created'",
			)
			if err != nil {
				return fmt.Errorf("failed to update state ENUM: %v", err)
			}
			log.Printf("KDC: Updated state ENUM to include 'active_dist'")
		}
		return nil
	}
}

// migrateAddActiveCEState updates the state ENUM/CHECK constraint to include 'active_ce'
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddActiveCEState() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if constraint already allows 'active_ce' by trying to update a test record
		var testID, originalState string
		err := kdc.DB.QueryRow("SELECT id, state FROM dnssec_keys LIMIT 1").Scan(&testID, &originalState)
		if err == nil && testID != "" {
			// Try to update a record to 'active_ce' to test the constraint
			_, err = kdc.DB.Exec("UPDATE dnssec_keys SET state = 'active_ce' WHERE id = ?", testID)
			if err != nil && strings.Contains(err.Error(), "CHECK constraint failed") {
				// Constraint doesn't allow 'active_ce', need to recreate table
				log.Printf("KDC: Recreating dnssec_keys table to update CHECK constraint for 'active_ce' state")

				// Create new table with correct constraint
				_, err = kdc.DB.Exec(`
					CREATE TABLE IF NOT EXISTS dnssec_keys_new (
						id TEXT PRIMARY KEY,
						zone_name TEXT NOT NULL,
						key_type TEXT NOT NULL,
						key_id INTEGER NOT NULL,
						algorithm INTEGER NOT NULL,
						flags INTEGER NOT NULL,
						public_key TEXT NOT NULL,
						private_key BLOB NOT NULL,
						state TEXT NOT NULL DEFAULT 'created',
						created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
						published_at DATETIME,
						activated_at DATETIME,
						retired_at DATETIME,
						comment TEXT,
						FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
						CHECK (key_type IN ('KSK', 'ZSK', 'CSK')),
						CHECK (state IN ('created', 'published', 'standby', 'active', 'active_dist', 'active_ce', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked'))
					)`)
				if err != nil {
					return fmt.Errorf("failed to create new dnssec_keys table: %v", err)
				}

				// Copy data
				_, err = kdc.DB.Exec(`
					INSERT INTO dnssec_keys_new 
					SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key, 
					       state, created_at, published_at, activated_at, retired_at, comment
					FROM dnssec_keys`)
				if err != nil {
					return fmt.Errorf("failed to copy data to new table: %v", err)
				}

				// Drop old table
				_, err = kdc.DB.Exec("DROP TABLE dnssec_keys")
				if err != nil {
					return fmt.Errorf("failed to drop old table: %v", err)
				}

				// Rename new table
				_, err = kdc.DB.Exec("ALTER TABLE dnssec_keys_new RENAME TO dnssec_keys")
				if err != nil {
					return fmt.Errorf("failed to rename new table: %v", err)
				}

				// Recreate indexes
				indexes := []string{
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_name ON dnssec_keys(zone_name)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_key_type ON dnssec_keys(key_type)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_state ON dnssec_keys(state)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_key_type_state ON dnssec_keys(zone_name, key_type, state)",
				}
				for _, idxStmt := range indexes {
					if _, err := kdc.DB.Exec(idxStmt); err != nil {
						log.Printf("KDC: Warning: Failed to recreate index: %v", err)
					}
				}

				log.Printf("KDC: Successfully updated dnssec_keys table CHECK constraint for 'active_ce'")
			} else if err == nil {
				// Update succeeded, revert it to original state
				_, _ = kdc.DB.Exec("UPDATE dnssec_keys SET state = ? WHERE id = ?", originalState, testID)
			}
		}
		// If no records exist or constraint already allows 'active_ce', nothing to do
		return nil
	} else {
		// MySQL/MariaDB: Alter ENUM to include 'active_ce'
		// Check if 'active_ce' is already in the ENUM
		var enumValues string
		err := kdc.DB.QueryRow(
			"SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'dnssec_keys' AND COLUMN_NAME = 'state'",
		).Scan(&enumValues)
		if err != nil {
			return fmt.Errorf("failed to check state ENUM: %v", err)
		}

		if !strings.Contains(enumValues, "active_ce") {
			// Update ENUM to include 'active_ce'
			_, err = kdc.DB.Exec(
				"ALTER TABLE dnssec_keys MODIFY COLUMN state ENUM('created', 'published', 'standby', 'active', 'active_dist', 'active_ce', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked') NOT NULL DEFAULT 'created'",
			)
			if err != nil {
				return fmt.Errorf("failed to update state ENUM: %v", err)
			}
			log.Printf("KDC: Updated state ENUM to include 'active_ce'")
		}
		return nil
	}
}

// markOldCompletedDistributions marks old distributions as complete if they have all confirmations
// This handles distributions that were completed before we added completion tracking
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) markOldCompletedDistributions() {
	// Find distributions that:
	// 1. Are not already marked as completed
	// 2. Are older than 1 minute (to avoid race conditions)
	// 3. Have all nodes confirmed
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT dr.distribution_id, dr.zone_name
		 FROM distribution_records dr
		 WHERE dr.status != 'completed'
		   AND dr.created_at < datetime('now', '-1 minute')
		   AND NOT EXISTS (
		     SELECT 1 FROM distribution_records dr2
		     WHERE dr2.distribution_id = dr.distribution_id
		       AND dr2.status = 'completed'
		   )`,
	)
	if err != nil {
		log.Printf("KDC: Warning: Failed to query old distributions: %v", err)
		return
	}
	defer rows.Close()

	var distributionsToComplete []struct {
		distID   string
		zoneName string
	}

	for rows.Next() {
		var distID, zoneName string
		if err := rows.Scan(&distID, &zoneName); err != nil {
			continue
		}

		// Check if all nodes have confirmed
		allConfirmed, err := kdc.CheckAllNodesConfirmed(distID, zoneName)
		if err == nil && allConfirmed {
			distributionsToComplete = append(distributionsToComplete, struct {
				distID   string
				zoneName string
			}{distID, zoneName})
		}
	}

	// Mark distributions as complete with retry logic to handle SQLite locking
	for _, dist := range distributionsToComplete {
		maxRetries := 3
		retryDelay := 100 * time.Millisecond

		for attempt := 0; attempt < maxRetries; attempt++ {
			if attempt > 0 {
				// Exponential backoff
				time.Sleep(retryDelay * time.Duration(1<<uint(attempt-1)))
			}

			err := kdc.MarkDistributionComplete(dist.distID)
			if err == nil {
				log.Printf("KDC: Marked old distribution %s as complete (had all confirmations)", dist.distID)
				break
			}

			// If it's a locking error and we have retries left, try again
			if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
				continue
			}

			// Final attempt failed or non-locking error
			log.Printf("KDC: Warning: Failed to mark old distribution %s as complete: %v", dist.distID, err)
			break
		}
	}
}

// migrateAddSig0PubkeyToNodes adds the sig0_pubkey column to nodes table if it doesn't exist
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddSig0PubkeyToNodes() error {
	var columnExists bool

	if kdc.DBType == "sqlite" {
		// SQLite: Check if column exists using pragma
		var count int
		err := kdc.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name='sig0_pubkey'").Scan(&count)
		columnExists = (err == nil && count > 0)
	} else {
		// MySQL/MariaDB: Check if column exists by querying information_schema
		var count int
		err := kdc.DB.QueryRow(
			"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'nodes' AND COLUMN_NAME = 'sig0_pubkey'",
		).Scan(&count)
		columnExists = (err == nil && count > 0)
	}

	if columnExists {
		// Column already exists, nothing to do
		return nil
	}

	// Column doesn't exist, add it
	var alterStmt string
	if kdc.DBType == "sqlite" {
		alterStmt = "ALTER TABLE nodes ADD COLUMN sig0_pubkey TEXT"
	} else {
		alterStmt = "ALTER TABLE nodes ADD COLUMN sig0_pubkey TEXT"
	}

	_, err := kdc.DB.Exec(alterStmt)
	if err != nil {
		// Check if error is "duplicate column" (column already exists - race condition)
		if strings.Contains(err.Error(), "duplicate column") ||
			strings.Contains(err.Error(), "already exists") ||
			strings.Contains(err.Error(), "Duplicate column name") {
			return nil // Column already exists, that's fine
		}
		return fmt.Errorf("failed to add sig0_pubkey column: %v", err)
	}
	log.Printf("KDC: Added sig0_pubkey column to nodes table")
	return nil
}

// migrateAddSupportedCryptoToNodes adds the supported_crypto column to nodes table if it doesn't exist
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddSupportedCryptoToNodes() error {
	var columnExists bool

	if kdc.DBType == "sqlite" {
		// SQLite: Check if column exists using pragma
		var count int
		err := kdc.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name='supported_crypto'").Scan(&count)
		columnExists = (err == nil && count > 0)
	} else {
		// MySQL/MariaDB: Check if column exists by querying information_schema
		var count int
		err := kdc.DB.QueryRow(
			"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'nodes' AND COLUMN_NAME = 'supported_crypto'",
		).Scan(&count)
		columnExists = (err == nil && count > 0)
	}

	if columnExists {
		// Column already exists, nothing to do
		return nil
	}

	// Column doesn't exist, add it
	var alterStmt string
	if kdc.DBType == "sqlite" {
		// SQLite uses TEXT for JSON data
		alterStmt = "ALTER TABLE nodes ADD COLUMN supported_crypto TEXT"
	} else {
		// MySQL/MariaDB uses JSON type
		alterStmt = "ALTER TABLE nodes ADD COLUMN supported_crypto JSON"
	}

	_, err := kdc.DB.Exec(alterStmt)
	if err != nil {
		// Check if error is "duplicate column" (column already exists - race condition)
		if strings.Contains(err.Error(), "duplicate column") ||
			strings.Contains(err.Error(), "already exists") ||
			strings.Contains(err.Error(), "Duplicate column name") {
			return nil // Column already exists, that's fine
		}
		return fmt.Errorf("failed to add supported_crypto column: %v", err)
	}
	log.Printf("KDC: Added supported_crypto column to nodes table")
	return nil
}

// migrateAddJosePubKeyToNodes adds the long_term_jose_pub_key column to nodes table if it doesn't exist
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddJosePubKeyToNodes() error {
	var columnExists bool

	if kdc.DBType == "sqlite" {
		// SQLite: Check if column exists using pragma
		var count int
		err := kdc.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name='long_term_jose_pub_key'").Scan(&count)
		columnExists = (err == nil && count > 0)
	} else {
		// MySQL/MariaDB: Check if column exists by querying information_schema
		var count int
		err := kdc.DB.QueryRow(
			"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'nodes' AND COLUMN_NAME = 'long_term_jose_pub_key'",
		).Scan(&count)
		columnExists = (err == nil && count > 0)
	}

	if columnExists {
		// Column already exists, nothing to do
		return nil
	}

	// Column doesn't exist, add it
	var alterStmt string
	if kdc.DBType == "sqlite" {
		alterStmt = "ALTER TABLE nodes ADD COLUMN long_term_jose_pub_key BLOB"
	} else {
		alterStmt = "ALTER TABLE nodes ADD COLUMN long_term_jose_pub_key BLOB"
	}

	_, err := kdc.DB.Exec(alterStmt)
	if err != nil {
		// Check if error is "duplicate column" (column already exists - race condition)
		if strings.Contains(err.Error(), "duplicate column") ||
			strings.Contains(err.Error(), "already exists") ||
			strings.Contains(err.Error(), "Duplicate column name") {
			return nil // Column already exists, that's fine
		}
		return fmt.Errorf("failed to add long_term_jose_pub_key column: %v", err)
	}
	log.Printf("KDC: Added long_term_jose_pub_key column to nodes table")
	return nil
}

// MigrateEnrollmentTokensTable creates the bootstrap_tokens table if it doesn't exist
// Note: Table name is kept as "bootstrap_tokens" for backward compatibility
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) MigrateEnrollmentTokensTable() error {
	log.Printf("KDC: Checking if bootstrap_tokens table exists...")
	var tableExists bool

	if kdc.DBType == "sqlite" {
		// SQLite: Check if table exists
		var count int
		err := kdc.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='bootstrap_tokens'").Scan(&count)
		if err != nil {
			log.Printf("KDC: Error checking for bootstrap_tokens table: %v", err)
		}
		tableExists = (err == nil && count > 0)
		log.Printf("KDC: bootstrap_tokens table exists check: %v (count=%d)", tableExists, count)
	} else {
		// MySQL/MariaDB: Check if table exists
		var count int
		err := kdc.DB.QueryRow(
			"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'bootstrap_tokens'",
		).Scan(&count)
		if err != nil {
			log.Printf("KDC: Error checking for bootstrap_tokens table: %v", err)
		}
		tableExists = (err == nil && count > 0)
		log.Printf("KDC: bootstrap_tokens table exists check: %v (count=%d)", tableExists, count)
	}

	if tableExists {
		// Table already exists, nothing to do
		log.Printf("KDC: bootstrap_tokens table already exists, skipping migration")
		return nil
	}

	log.Printf("KDC: bootstrap_tokens table does not exist, creating it...")

	// Table doesn't exist, create it
	var createStmt string
	if kdc.DBType == "sqlite" {
		// Note: No FOREIGN KEY constraint - bootstrap tokens are created BEFORE nodes exist
		createStmt = `CREATE TABLE IF NOT EXISTS bootstrap_tokens (
			token_id TEXT PRIMARY KEY,
			token_value TEXT NOT NULL UNIQUE,
			node_id TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			activated_at DATETIME,
			expires_at DATETIME,
			activated INTEGER NOT NULL DEFAULT 0,
			used INTEGER NOT NULL DEFAULT 0,
			used_at DATETIME,
			created_by TEXT,
			comment TEXT
		)`
	} else {
		// Note: No FOREIGN KEY constraint - bootstrap tokens are created BEFORE nodes exist
		createStmt = `CREATE TABLE IF NOT EXISTS bootstrap_tokens (
			token_id VARCHAR(255) PRIMARY KEY,
			token_value VARCHAR(255) NOT NULL UNIQUE,
			node_id VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			activated_at TIMESTAMP NULL,
			expires_at TIMESTAMP NULL,
			activated BOOLEAN NOT NULL DEFAULT FALSE,
			used BOOLEAN NOT NULL DEFAULT FALSE,
			used_at TIMESTAMP NULL,
			created_by VARCHAR(255),
			comment TEXT,
			INDEX idx_token_value (token_value),
			INDEX idx_node_id (node_id),
			INDEX idx_expires_at (expires_at),
			INDEX idx_activated (activated),
			INDEX idx_used (used)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
	}

	// For SQLite, ensure foreign keys are enabled before creating table with FK constraint
	if kdc.DBType == "sqlite" {
		log.Printf("KDC: Enabling foreign keys for SQLite...")
		if _, err := kdc.DB.Exec("PRAGMA foreign_keys = ON"); err != nil {
			log.Printf("KDC: Warning: Failed to enable foreign keys: %v", err)
		} else {
			log.Printf("KDC: Foreign keys enabled successfully")
		}
	}

	log.Printf("KDC: Executing CREATE TABLE statement for bootstrap_tokens...")
	_, err := kdc.DB.Exec(createStmt)
	if err != nil {
		log.Printf("KDC: ERROR: Failed to create bootstrap_tokens table: %v", err)
		return fmt.Errorf("failed to create bootstrap_tokens table: %v", err)
	}
	log.Printf("KDC: Successfully created bootstrap_tokens table")

	// Verify table was created
	log.Printf("KDC: Verifying bootstrap_tokens table was created...")
	var verifyCount int
	if kdc.DBType == "sqlite" {
		err = kdc.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='bootstrap_tokens'").Scan(&verifyCount)
	} else {
		err = kdc.DB.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'bootstrap_tokens'").Scan(&verifyCount)
	}
	if err != nil {
		log.Printf("KDC: WARNING: Could not verify table creation: %v", err)
	} else if verifyCount == 0 {
		log.Printf("KDC: ERROR: Table verification failed - table still does not exist after creation attempt!")
		return fmt.Errorf("table verification failed - bootstrap_tokens table was not created")
	} else {
		log.Printf("KDC: Table verification successful - bootstrap_tokens table exists")
	}

	// Create indexes for SQLite (MySQL indexes are in CREATE TABLE)
	if kdc.DBType == "sqlite" {
		indexes := []string{
			"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_token_value ON bootstrap_tokens(token_value)",
			"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_node_id ON bootstrap_tokens(node_id)",
			"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_expires_at ON bootstrap_tokens(expires_at)",
			"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_activated ON bootstrap_tokens(activated)",
			"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_used ON bootstrap_tokens(used)",
		}
		for _, idxStmt := range indexes {
			if _, err := kdc.DB.Exec(idxStmt); err != nil {
				log.Printf("KDC: Warning: Failed to create index: %v", err)
			}
		}
	}

	// Migrate: Remove FK constraint if it exists (enrollment tokens are created before nodes exist)
	if err := kdc.migrateRemoveEnrollmentTokensFK(); err != nil {
		log.Printf("KDC: Warning: Failed to remove FK constraint from bootstrap_tokens: %v", err)
	}

	return nil
}

// migrateRemoveEnrollmentTokensFK removes the foreign key constraint from bootstrap_tokens table
// Note: Table name is kept as "bootstrap_tokens" for backward compatibility
// This is needed because enrollment tokens are created BEFORE nodes exist
func (kdc *KdcDB) migrateRemoveEnrollmentTokensFK() error {
	if kdc.DBType == "sqlite" {
		// SQLite doesn't support dropping FK constraints directly
		// Check if table exists and has FK constraint by checking schema
		var sqlSchema string
		err := kdc.DB.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='bootstrap_tokens'").Scan(&sqlSchema)
		if err != nil {
			// Table doesn't exist or error - nothing to do
			return nil
		}

		// Check if FK constraint exists in schema
		if strings.Contains(sqlSchema, "FOREIGN KEY") {
			log.Printf("KDC: Found FK constraint in bootstrap_tokens table, recreating without FK...")

			// Check if table has data
			var rowCount int
			kdc.DB.QueryRow("SELECT COUNT(*) FROM bootstrap_tokens").Scan(&rowCount)
			if rowCount > 0 {
				log.Printf("KDC: WARNING: bootstrap_tokens table has %d rows - cannot safely remove FK constraint", rowCount)
				return fmt.Errorf("cannot remove FK constraint: table has existing data")
			}

			// Recreate table without FK constraint
			// SQLite: Drop and recreate
			if _, err := kdc.DB.Exec("DROP TABLE bootstrap_tokens"); err != nil {
				return fmt.Errorf("failed to drop bootstrap_tokens table: %v", err)
			}

			createStmt := `CREATE TABLE bootstrap_tokens (
				token_id TEXT PRIMARY KEY,
				token_value TEXT NOT NULL UNIQUE,
				node_id TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				activated_at DATETIME,
				expires_at DATETIME,
				activated INTEGER NOT NULL DEFAULT 0,
				used INTEGER NOT NULL DEFAULT 0,
				used_at DATETIME,
				created_by TEXT,
				comment TEXT
			)`

			if _, err := kdc.DB.Exec(createStmt); err != nil {
				return fmt.Errorf("failed to recreate bootstrap_tokens table: %v", err)
			}

			// Recreate indexes
			indexes := []string{
				"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_token_value ON bootstrap_tokens(token_value)",
				"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_node_id ON bootstrap_tokens(node_id)",
				"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_expires_at ON bootstrap_tokens(expires_at)",
				"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_activated ON bootstrap_tokens(activated)",
				"CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_used ON bootstrap_tokens(used)",
			}
			for _, idxStmt := range indexes {
				if _, err := kdc.DB.Exec(idxStmt); err != nil {
					log.Printf("KDC: Warning: Failed to create index: %v", err)
				}
			}

			log.Printf("KDC: Successfully recreated bootstrap_tokens table without FK constraint")
		}
	} else {
		// MySQL/MariaDB: Check if FK constraint exists and drop it
		var fkExists bool
		err := kdc.DB.QueryRow(`
			SELECT COUNT(*) > 0 
			FROM information_schema.KEY_COLUMN_USAGE 
			WHERE TABLE_SCHEMA = DATABASE() 
			AND TABLE_NAME = 'bootstrap_tokens' 
			AND REFERENCED_TABLE_NAME = 'nodes'
		`).Scan(&fkExists)

		if err != nil {
			// Error checking - assume FK doesn't exist
			return nil
		}

		if fkExists {
			log.Printf("KDC: Found FK constraint in bootstrap_tokens table, dropping it...")

			// Find the constraint name
			var constraintName string
			err := kdc.DB.QueryRow(`
				SELECT CONSTRAINT_NAME 
				FROM information_schema.KEY_COLUMN_USAGE 
				WHERE TABLE_SCHEMA = DATABASE() 
				AND TABLE_NAME = 'bootstrap_tokens' 
				AND REFERENCED_TABLE_NAME = 'nodes'
				LIMIT 1
			`).Scan(&constraintName)

			if err == nil && constraintName != "" {
				dropStmt := fmt.Sprintf("ALTER TABLE bootstrap_tokens DROP FOREIGN KEY %s", constraintName)
				if _, err := kdc.DB.Exec(dropStmt); err != nil {
					return fmt.Errorf("failed to drop FK constraint: %v", err)
				}
				log.Printf("KDC: Successfully dropped FK constraint %s from bootstrap_tokens table", constraintName)
			}
		}
	}

	return nil
}

// migrateMakeDistributionZoneKeyNullable makes zone_name and key_id nullable in distribution_records
// This allows node_components distributions to use NULL for these fields (they're not about zones/keys)
// Foreign key constraints remain but only apply when values are NOT NULL
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateMakeDistributionZoneKeyNullable() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if columns are already nullable by checking table info
		var zoneNameNullable, keyIDNullable bool

		rows, err := kdc.DB.Query("PRAGMA table_info(distribution_records)")
		if err != nil {
			return fmt.Errorf("failed to query table info: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull int
			var defaultValue, pk interface{}

			if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
				continue
			}

			if name == "zone_name" {
				zoneNameNullable = (notNull == 0)
			}
			if name == "key_id" {
				keyIDNullable = (notNull == 0)
			}
		}

		if zoneNameNullable && keyIDNullable {
			// Already nullable, nothing to do
			return nil
		}

		// Need to recreate table to make columns nullable
		log.Printf("KDC: Recreating distribution_records table to make zone_name and key_id nullable")

		// Create new table with nullable zone_name, key_id, and ephemeral_pub_key
		_, err = kdc.DB.Exec(`
			CREATE TABLE IF NOT EXISTS distribution_records_new (
				id TEXT PRIMARY KEY,
				zone_name TEXT,
				key_id TEXT,
				node_id TEXT,
				encrypted_key BLOB NOT NULL,
				ephemeral_pub_key BLOB NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				expires_at DATETIME,
				status TEXT NOT NULL DEFAULT 'pending',
				distribution_id TEXT NOT NULL,
				completed_at DATETIME,
				FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
				FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
				FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
				CHECK (status IN ('pending', 'delivered', 'active', 'revoked', 'completed'))
			)`)
		if err != nil {
			return fmt.Errorf("failed to create new distribution_records table: %v", err)
		}

		// Copy data
		_, err = kdc.DB.Exec(`
			INSERT INTO distribution_records_new 
			SELECT id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key, 
			       created_at, expires_at, status, distribution_id, completed_at
			FROM distribution_records`)
		if err != nil {
			return fmt.Errorf("failed to copy data to new table: %v", err)
		}

		// Drop old table
		_, err = kdc.DB.Exec("DROP TABLE distribution_records")
		if err != nil {
			return fmt.Errorf("failed to drop old table: %v", err)
		}

		// Rename new table
		_, err = kdc.DB.Exec("ALTER TABLE distribution_records_new RENAME TO distribution_records")
		if err != nil {
			return fmt.Errorf("failed to rename new table: %v", err)
		}

		// Recreate indexes
		indexes := []string{
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_zone_name ON distribution_records(zone_name)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_key_id ON distribution_records(key_id)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_node_id ON distribution_records(node_id)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_status ON distribution_records(status)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_distribution_id ON distribution_records(distribution_id)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_completed_at ON distribution_records(completed_at)",
		}
		for _, idxStmt := range indexes {
			if _, err := kdc.DB.Exec(idxStmt); err != nil {
				log.Printf("KDC: Warning: Failed to create index: %v", err)
			}
		}

		log.Printf("KDC: Successfully made zone_name and key_id nullable in distribution_records")
	} else {
		// MySQL/MariaDB: Use ALTER TABLE to modify columns
		// Check if columns are already nullable
		var zoneNameNullable, keyIDNullable bool

		var zoneNameNull, keyIDNull string
		err := kdc.DB.QueryRow(
			"SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND COLUMN_NAME = 'zone_name'",
		).Scan(&zoneNameNull)
		if err == nil {
			zoneNameNullable = (zoneNameNull == "YES")
		}

		err = kdc.DB.QueryRow(
			"SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND COLUMN_NAME = 'key_id'",
		).Scan(&keyIDNull)
		if err == nil {
			keyIDNullable = (keyIDNull == "YES")
		}

		if zoneNameNullable && keyIDNullable {
			// Already nullable, nothing to do
			return nil
		}

		// Modify columns to allow NULL
		if !zoneNameNullable {
			_, err = kdc.DB.Exec(
				"ALTER TABLE distribution_records MODIFY COLUMN zone_name VARCHAR(255) NULL",
			)
			if err != nil {
				return fmt.Errorf("failed to make zone_name nullable: %v", err)
			}
			log.Printf("KDC: Made zone_name nullable in distribution_records")
		}

		if !keyIDNullable {
			_, err = kdc.DB.Exec(
				"ALTER TABLE distribution_records MODIFY COLUMN key_id VARCHAR(255) NULL",
			)
			if err != nil {
				return fmt.Errorf("failed to make key_id nullable: %v", err)
			}
			log.Printf("KDC: Made key_id nullable in distribution_records")
		}
	}

	return nil
}

// migrateMakeDistributionConfirmationsZoneKeyNullable makes zone_name and key_id nullable in distribution_confirmations
// This allows node_components distributions to use NULL for these fields (they're not about zones/keys)
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateMakeDistributionConfirmationsZoneKeyNullable() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if columns are already nullable by trying to insert NULL
		// Actually, SQLite doesn't enforce NOT NULL constraints on existing tables when we alter them
		// We need to recreate the table or use a workaround
		// For now, let's check if we can insert a NULL value
		var testID string = "migration_test_" + fmt.Sprintf("%d", time.Now().Unix())
		_, err := kdc.DB.Exec(
			`INSERT INTO distribution_confirmations (id, distribution_id, zone_name, key_id, node_id) 
			 VALUES (?, 'test', NULL, NULL, 'test')`,
			testID,
		)
		if err == nil {
			// NULL is allowed, delete test record
			kdc.DB.Exec("DELETE FROM distribution_confirmations WHERE id = ?", testID)
			return nil
		}

		// NULL is not allowed, need to recreate table
		log.Printf("KDC: Recreating distribution_confirmations table to make zone_name and key_id nullable")

		// Create new table with nullable columns
		_, err = kdc.DB.Exec(`
			CREATE TABLE IF NOT EXISTS distribution_confirmations_new (
				id TEXT PRIMARY KEY,
				distribution_id TEXT NOT NULL,
				zone_name TEXT NULL,
				key_id TEXT NULL,
				node_id TEXT NOT NULL,
				confirmed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
				FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
				FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
				UNIQUE (distribution_id, node_id)
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create new distribution_confirmations table: %v", err)
		}

		// Copy data from old table to new (convert empty strings to NULL)
		_, err = kdc.DB.Exec(`
			INSERT INTO distribution_confirmations_new 
			SELECT id, distribution_id, 
			       CASE WHEN zone_name = '' THEN NULL ELSE zone_name END,
			       CASE WHEN key_id = '' THEN NULL ELSE key_id END,
			       node_id, confirmed_at
			FROM distribution_confirmations
		`)
		if err != nil {
			return fmt.Errorf("failed to copy data to new table: %v", err)
		}

		// Drop old table and rename new one
		_, err = kdc.DB.Exec("DROP TABLE distribution_confirmations")
		if err != nil {
			return fmt.Errorf("failed to drop old table: %v", err)
		}

		_, err = kdc.DB.Exec("ALTER TABLE distribution_confirmations_new RENAME TO distribution_confirmations")
		if err != nil {
			return fmt.Errorf("failed to rename new table: %v", err)
		}

		// Recreate indexes
		indexes := []string{
			"CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_distribution_id ON distribution_confirmations(distribution_id)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_zone_key ON distribution_confirmations(zone_name, key_id)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_node_id ON distribution_confirmations(node_id)",
		}
		for _, idxStmt := range indexes {
			if _, err := kdc.DB.Exec(idxStmt); err != nil {
				log.Printf("KDC: Warning: Failed to create index: %v", err)
			}
		}

		log.Printf("KDC: Successfully made zone_name and key_id nullable in distribution_confirmations")
	} else {
		// MySQL/MariaDB: Use ALTER TABLE to modify columns
		// Check if columns are already nullable
		var zoneNameNullable, keyIDNullable bool

		var zoneNameNull, keyIDNull string
		err := kdc.DB.QueryRow(
			"SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_confirmations' AND COLUMN_NAME = 'zone_name'",
		).Scan(&zoneNameNull)
		if err == nil {
			zoneNameNullable = (zoneNameNull == "YES")
		}

		err = kdc.DB.QueryRow(
			"SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_confirmations' AND COLUMN_NAME = 'key_id'",
		).Scan(&keyIDNull)
		if err == nil {
			keyIDNullable = (keyIDNull == "YES")
		}

		if zoneNameNullable && keyIDNullable {
			// Already nullable, nothing to do
			return nil
		}

		// Modify columns to allow NULL
		if !zoneNameNullable {
			_, err = kdc.DB.Exec(
				"ALTER TABLE distribution_confirmations MODIFY COLUMN zone_name VARCHAR(255) NULL",
			)
			if err != nil {
				return fmt.Errorf("failed to make zone_name nullable: %v", err)
			}
			log.Printf("KDC: Made zone_name nullable in distribution_confirmations")
		}

		if !keyIDNullable {
			_, err = kdc.DB.Exec(
				"ALTER TABLE distribution_confirmations MODIFY COLUMN key_id VARCHAR(255) NULL",
			)
			if err != nil {
				return fmt.Errorf("failed to make key_id nullable: %v", err)
			}
			log.Printf("KDC: Made key_id nullable in distribution_confirmations")
		}
	}

	return nil
}

// migrateMakeLongTermPubKeyNullable makes long_term_hpke_pub_key nullable in nodes table
// and renames long_term_pub_key -> long_term_hpke_pub_key
// This allows JOSE-only nodes to have NULL for HPKE keys and makes the column name clearer
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateMakeLongTermPubKeyNullable() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if column needs to be renamed or made nullable
		var sqlStr string
		err := kdc.DB.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='nodes'").Scan(&sqlStr)
		if err != nil {
			// Table doesn't exist yet - initSchema will create it with correct column name, nothing to do
			if err == sql.ErrNoRows {
				return nil
			}
			return fmt.Errorf("failed to check nodes table schema: %v", err)
		}

		// Check if column needs to be renamed
		needsRename := strings.Contains(sqlStr, "long_term_pub_key") && !strings.Contains(sqlStr, "long_term_hpke_pub_key")
		// Check if column needs to be made nullable
		needsNullable := strings.Contains(sqlStr, "long_term_pub_key BLOB NOT NULL") || strings.Contains(sqlStr, "long_term_pub_key BLOB UNIQUE NOT NULL") ||
			strings.Contains(sqlStr, "long_term_hpke_pub_key BLOB NOT NULL") || strings.Contains(sqlStr, "long_term_hpke_pub_key BLOB UNIQUE NOT NULL")

		if !needsRename && !needsNullable {
			// Already has correct column name and nullable, nothing to do
			return nil
		}

		// Need to rebuild table to rename column and/or make it nullable
		log.Printf("KDC: Recreating nodes table to rename long_term_pub_key -> long_term_hpke_pub_key and make it nullable")

		// Start transaction
		tx, err := kdc.DB.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %v", err)
		}
		defer tx.Rollback()

		// Create new table with correct column name and nullable (keep UNIQUE constraint - SQLite allows multiple NULLs)
		_, err = tx.Exec(`
			CREATE TABLE nodes_new (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				long_term_hpke_pub_key BLOB UNIQUE,
				long_term_jose_pub_key BLOB,
				supported_crypto TEXT,
				sig0_pubkey TEXT,
				notify_address TEXT,
				registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				state TEXT NOT NULL DEFAULT 'online',
				comment TEXT,
				CHECK (state IN ('online', 'offline', 'compromised', 'suspended'))
			)`)
		if err != nil {
			return fmt.Errorf("failed to create new nodes table: %v", err)
		}

		// Copy all data from old table to new table (handle both old and new column names)
		// Check which column name exists in the old table
		var oldColName string
		if strings.Contains(sqlStr, "long_term_hpke_pub_key") {
			oldColName = "long_term_hpke_pub_key"
		} else {
			oldColName = "long_term_pub_key"
		}

		_, err = tx.Exec(fmt.Sprintf(`
			INSERT INTO nodes_new 
			SELECT id, name, %s, long_term_jose_pub_key, supported_crypto, 
			       sig0_pubkey, notify_address, registered_at, last_seen, state, comment
			FROM nodes`, oldColName))
		if err != nil {
			return fmt.Errorf("failed to copy data to new table: %v", err)
		}

		// Drop old table
		_, err = tx.Exec("DROP TABLE nodes")
		if err != nil {
			return fmt.Errorf("failed to drop old table: %v", err)
		}

		// Rename new table
		_, err = tx.Exec("ALTER TABLE nodes_new RENAME TO nodes")
		if err != nil {
			return fmt.Errorf("failed to rename new table: %v", err)
		}

		// Recreate indexes
		indexes := []string{
			"CREATE INDEX IF NOT EXISTS idx_nodes_state ON nodes(state)",
			"CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen)",
		}
		for _, idxStmt := range indexes {
			if _, err := tx.Exec(idxStmt); err != nil {
				log.Printf("KDC: Warning: Failed to recreate index: %v", err)
			}
		}

		// Recreate trigger
		_, err = tx.Exec(`
			CREATE TRIGGER IF NOT EXISTS nodes_last_seen 
			AFTER UPDATE ON nodes
			BEGIN
				UPDATE nodes SET last_seen = CURRENT_TIMESTAMP WHERE id = NEW.id;
			END`)
		if err != nil {
			log.Printf("KDC: Warning: Failed to recreate trigger: %v", err)
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %v", err)
		}

		log.Printf("KDC: Successfully renamed long_term_pub_key -> long_term_hpke_pub_key and made it nullable in nodes table")
	} else {
		// MySQL/MariaDB: Check if column needs to be renamed
		var oldColExists, newColExists bool
		var oldColNullable, newColNullable string

		// Check if old column name exists
		err := kdc.DB.QueryRow(
			"SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'nodes' AND COLUMN_NAME = 'long_term_pub_key'",
		).Scan(&oldColNullable)
		oldColExists = (err == nil)

		// Check if new column name exists
		err = kdc.DB.QueryRow(
			"SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'nodes' AND COLUMN_NAME = 'long_term_hpke_pub_key'",
		).Scan(&newColNullable)
		newColExists = (err == nil)

		if oldColExists && !newColExists {
			// Need to rename column
			log.Printf("KDC: Renaming long_term_pub_key -> long_term_hpke_pub_key in nodes table")
			_, err = kdc.DB.Exec("ALTER TABLE nodes CHANGE COLUMN long_term_pub_key long_term_hpke_pub_key BLOB NULL")
			if err != nil {
				return fmt.Errorf("failed to rename long_term_pub_key to long_term_hpke_pub_key: %v", err)
			}
			log.Printf("KDC: Successfully renamed long_term_pub_key -> long_term_hpke_pub_key in nodes table")
		} else if newColExists && newColNullable != "YES" {
			// Column already renamed, just need to make it nullable
			alterStmt := "ALTER TABLE nodes MODIFY COLUMN long_term_hpke_pub_key BLOB NULL"
			_, err = kdc.DB.Exec(alterStmt)
			if err != nil {
				return fmt.Errorf("failed to make long_term_hpke_pub_key nullable: %v", err)
			}
			log.Printf("KDC: Made long_term_hpke_pub_key nullable in nodes table")
		} else if newColExists && newColNullable == "YES" {
			// Already renamed and nullable, nothing to do
			return nil
		}
	}

	return nil
}

// migrateMakeEphemeralPubKeyNullable makes ephemeral_pub_key nullable in distribution_records table
// This allows JOSE backend distributions to have NULL for ephemeral_pub_key (JWE embeds it in the header)
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateMakeEphemeralPubKeyNullable() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if column is already nullable by checking table info
		var ephemeralPubKeyNullable bool

		rows, err := kdc.DB.Query("PRAGMA table_info(distribution_records)")
		if err != nil {
			return fmt.Errorf("failed to query table info: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull int
			var defaultValue, pk interface{}

			if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
				continue
			}

			if name == "ephemeral_pub_key" {
				ephemeralPubKeyNullable = (notNull == 0)
				break
			}
		}

		if ephemeralPubKeyNullable {
			// Already nullable, nothing to do
			return nil
		}

		// Need to recreate table to make column nullable
		log.Printf("KDC: Recreating distribution_records table to make ephemeral_pub_key nullable")

		// Start transaction
		tx, err := kdc.DB.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %v", err)
		}
		defer tx.Rollback()

		// Create new table with nullable ephemeral_pub_key
		_, err = tx.Exec(`
			CREATE TABLE distribution_records_new (
				id TEXT PRIMARY KEY,
				zone_name TEXT,
				key_id TEXT,
				node_id TEXT,
				encrypted_key BLOB NOT NULL,
				ephemeral_pub_key BLOB NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				expires_at DATETIME,
				status TEXT NOT NULL DEFAULT 'pending',
				distribution_id TEXT NOT NULL,
				completed_at DATETIME,
				operation TEXT,
				payload TEXT,
				FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
				FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
				FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
				CHECK (status IN ('pending', 'delivered', 'active', 'revoked', 'completed'))
			)`)
		if err != nil {
			return fmt.Errorf("failed to create new distribution_records table: %v", err)
		}

		// Check if operation and payload columns exist
		var operationExists, payloadExists bool
		rows2, err := tx.Query("PRAGMA table_info(distribution_records)")
		if err == nil {
			defer rows2.Close()
			for rows2.Next() {
				var cid int
				var name, dataType string
				var notNull int
				var defaultValue, pk interface{}
				if err := rows2.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
					continue
				}
				if name == "operation" {
					operationExists = true
				}
				if name == "payload" {
					payloadExists = true
				}
			}
		}

		// Copy data from old table to new table (handle optional operation/payload columns)
		var copyStmt string
		if operationExists && payloadExists {
			copyStmt = `
			INSERT INTO distribution_records_new 
			SELECT id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key, 
			       created_at, expires_at, status, distribution_id, completed_at, operation, payload
			FROM distribution_records`
		} else {
			// operation/payload columns don't exist yet - use NULL for them
			copyStmt = `
			INSERT INTO distribution_records_new 
			SELECT id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key, 
			       created_at, expires_at, status, distribution_id, completed_at, NULL, NULL
			FROM distribution_records`
		}
		_, err = tx.Exec(copyStmt)
		if err != nil {
			return fmt.Errorf("failed to copy data to new table: %v", err)
		}

		// Drop old table
		_, err = tx.Exec("DROP TABLE distribution_records")
		if err != nil {
			return fmt.Errorf("failed to drop old table: %v", err)
		}

		// Rename new table
		_, err = tx.Exec("ALTER TABLE distribution_records_new RENAME TO distribution_records")
		if err != nil {
			return fmt.Errorf("failed to rename new table: %v", err)
		}

		// Recreate indexes
		indexes := []string{
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_zone_name ON distribution_records(zone_name)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_key_id ON distribution_records(key_id)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_node_id ON distribution_records(node_id)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_status ON distribution_records(status)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_distribution_id ON distribution_records(distribution_id)",
			"CREATE INDEX IF NOT EXISTS idx_distribution_records_completed_at ON distribution_records(completed_at)",
		}
		for _, idxStmt := range indexes {
			if _, err := tx.Exec(idxStmt); err != nil {
				log.Printf("KDC: Warning: Failed to recreate index: %v", err)
			}
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %v", err)
		}

		log.Printf("KDC: Successfully made ephemeral_pub_key nullable in distribution_records table")
	} else {
		// MySQL/MariaDB: Use ALTER TABLE to modify column
		// Check if column is already nullable
		var ephemeralPubKeyNullable bool

		var ephemeralPubKeyNull string
		err := kdc.DB.QueryRow(
			"SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND COLUMN_NAME = 'ephemeral_pub_key'",
		).Scan(&ephemeralPubKeyNull)
		if err == nil {
			ephemeralPubKeyNullable = (ephemeralPubKeyNull == "YES")
		}

		if ephemeralPubKeyNullable {
			// Already nullable, nothing to do
			return nil
		}

		// Modify column to allow NULL
		_, err = kdc.DB.Exec(
			"ALTER TABLE distribution_records MODIFY COLUMN ephemeral_pub_key BLOB NULL",
		)
		if err != nil {
			return fmt.Errorf("failed to make ephemeral_pub_key nullable: %v", err)
		}
		log.Printf("KDC: Made ephemeral_pub_key nullable in distribution_records")
	}

	return nil
}

// migrateAddOperationAndPayload adds operation and payload columns to distribution_records
// This enables operation-based distributions (ping, roll_key, delete_key, update_components)
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddOperationAndPayload() error {
	var operationExists, payloadExists bool

	if kdc.DBType == "sqlite" {
		// SQLite: Check if columns exist using pragma
		var count int
		err := kdc.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('distribution_records') WHERE name='operation'").Scan(&count)
		operationExists = (err == nil && count > 0)

		err = kdc.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('distribution_records') WHERE name='payload'").Scan(&count)
		payloadExists = (err == nil && count > 0)
	} else {
		// MySQL/MariaDB: Check if columns exist by querying information_schema
		var count int
		err := kdc.DB.QueryRow(
			"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND COLUMN_NAME = 'operation'",
		).Scan(&count)
		operationExists = (err == nil && count > 0)

		err = kdc.DB.QueryRow(
			"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND COLUMN_NAME = 'payload'",
		).Scan(&count)
		payloadExists = (err == nil && count > 0)
	}

	// If both columns already exist, nothing to do
	if operationExists && payloadExists {
		return nil
	}

	// Add operation column if it doesn't exist
	if !operationExists {
		var alterStmt string
		if kdc.DBType == "sqlite" {
			alterStmt = "ALTER TABLE distribution_records ADD COLUMN operation TEXT NOT NULL DEFAULT 'ping'"
		} else {
			alterStmt = "ALTER TABLE distribution_records ADD COLUMN operation VARCHAR(50) NOT NULL DEFAULT 'ping'"
		}

		_, err := kdc.DB.Exec(alterStmt)
		if err != nil {
			// Check if error is "duplicate column" (column already exists - race condition)
			if strings.Contains(err.Error(), "duplicate column") ||
				strings.Contains(err.Error(), "already exists") ||
				strings.Contains(err.Error(), "Duplicate column name") {
				// Column already exists, that's fine
			} else {
				return fmt.Errorf("failed to add operation column: %v", err)
			}
		} else {
			log.Printf("KDC: Added operation column to distribution_records table")
		}
	}

	// Add payload column if it doesn't exist
	if !payloadExists {
		var alterStmt string
		if kdc.DBType == "sqlite" {
			alterStmt = "ALTER TABLE distribution_records ADD COLUMN payload TEXT NULL"
		} else {
			alterStmt = "ALTER TABLE distribution_records ADD COLUMN payload JSON NULL"
		}

		_, err := kdc.DB.Exec(alterStmt)
		if err != nil {
			// Check if error is "duplicate column" (column already exists - race condition)
			if strings.Contains(err.Error(), "duplicate column") ||
				strings.Contains(err.Error(), "already exists") ||
				strings.Contains(err.Error(), "Duplicate column name") {
				// Column already exists, that's fine
			} else {
				return fmt.Errorf("failed to add payload column: %v", err)
			}
		} else {
			log.Printf("KDC: Added payload column to distribution_records table")
		}
	}

	// Update existing records to set appropriate operation types
	// Records with NULL zone_name AND NULL key_id are node_components operations
	// All other records are roll_key operations (key distributions)
	if !operationExists {
		log.Printf("KDC: Updating existing distribution records with operation types...")

		// Update node_components distributions (zone_name IS NULL AND key_id IS NULL)
		nodeComponentsStmt := "UPDATE distribution_records SET operation = 'node_components' WHERE zone_name IS NULL AND key_id IS NULL AND operation = 'ping'"
		result, err := kdc.DB.Exec(nodeComponentsStmt)
		if err != nil {
			log.Printf("KDC: Warning: Failed to update node_components records: %v", err)
		} else {
			rowsAffected, _ := result.RowsAffected()
			if rowsAffected > 0 {
				log.Printf("KDC: Updated %d records to operation='node_components'", rowsAffected)
			}
		}

		// Update key distributions (zone_name IS NOT NULL OR key_id IS NOT NULL)
		rollKeyStmt := "UPDATE distribution_records SET operation = 'roll_key' WHERE (zone_name IS NOT NULL OR key_id IS NOT NULL) AND operation = 'ping'"
		result, err = kdc.DB.Exec(rollKeyStmt)
		if err != nil {
			log.Printf("KDC: Warning: Failed to update roll_key records: %v", err)
		} else {
			rowsAffected, _ := result.RowsAffected()
			if rowsAffected > 0 {
				log.Printf("KDC: Updated %d records to operation='roll_key'", rowsAffected)
			}
		}
	}

	// Create index on operation column
	var indexExists bool
	if kdc.DBType == "sqlite" {
		var count int
		err := kdc.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_distribution_records_operation'").Scan(&count)
		indexExists = (err == nil && count > 0)
	} else {
		var count int
		err := kdc.DB.QueryRow(
			"SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND INDEX_NAME = 'idx_distribution_records_operation'",
		).Scan(&count)
		indexExists = (err == nil && count > 0)
	}

	if !indexExists {
		_, err := kdc.DB.Exec("CREATE INDEX idx_distribution_records_operation ON distribution_records(operation)")
		if err != nil {
			// Don't fail migration if index creation fails
			log.Printf("KDC: Warning: Failed to create operation index: %v", err)
		} else {
			log.Printf("KDC: Created index on operation column")
		}
	}

	log.Printf("KDC: Successfully migrated distribution_records to support operation-based distributions")
	return nil
}
