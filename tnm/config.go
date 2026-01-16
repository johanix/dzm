/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Configuration structures for tdns-kdc and tdns-krs
 */

package tnm

import (
	"time"
)

// KdcConf represents the KDC configuration
type KdcConf struct {
	Database DatabaseConf `yaml:"database" mapstructure:"database"`
	ControlZone string    `yaml:"control_zone" mapstructure:"control_zone"` // DNS zone for distribution events
	DefaultAlgorithm uint8 `yaml:"default_algorithm" mapstructure:"default_algorithm"` // Default DNSSEC algorithm (e.g., 15 for ED25519)
	KeyRotationInterval time.Duration `yaml:"key_rotation_interval" mapstructure:"key_rotation_interval"` // How often to rotate ZSKs
	StandbyKeyCount int `yaml:"standby_key_count" mapstructure:"standby_key_count"` // Number of standby ZSKs to maintain
	PublishTime time.Duration `yaml:"publish_time" mapstructure:"publish_time"` // Time to wait before published -> standby
	RetireTime time.Duration `yaml:"retire_time" mapstructure:"retire_time"` // Time to wait before retired -> removed
	DistributionTTL time.Duration `yaml:"distribution_ttl" mapstructure:"distribution_ttl"` // TTL for distributions (default: 5 minutes, like TSIG)
	ChunkMaxSize int `yaml:"chunk_max_size" mapstructure:"chunk_max_size"` // Maximum RDATA size per CHUNK (bytes, default: 60000)
	KdcHpkePrivKey string `yaml:"kdc_hpke_priv_key" mapstructure:"kdc_hpke_priv_key"` // Path to KDC HPKE private key file
	KdcBootstrapAddress string `yaml:"kdc_bootstrap_address" mapstructure:"kdc_bootstrap_address"` // IP:port where KDC accepts bootstrap requests
	BootstrapExpirationWindow time.Duration `yaml:"bootstrap_expiration_window" mapstructure:"bootstrap_expiration_window"` // Expiration window after activation (default: 5 minutes)
	CatalogZone string `yaml:"catalog_zone" mapstructure:"catalog_zone"` // Catalog zone name (e.g., "catalog.example.com.")
}

// KrsConf represents the KRS configuration
type KrsConf struct {
	Database    KrsDatabaseConf `yaml:"database" mapstructure:"database"`
	Node        NodeConf     `yaml:"node" mapstructure:"node"`
	ControlZone string       `yaml:"control_zone" mapstructure:"control_zone"` // DNS zone for distribution events
	DnsEngine   DnsEngineConf `yaml:"dnsengine" mapstructure:"dnsengine"`       // DNS engine config for NOTIFY
}

// DatabaseConf represents database configuration for KDC
type DatabaseConf struct {
	Type string `yaml:"type" mapstructure:"type" validate:"required,oneof=sqlite mariadb"` // Database type: "sqlite" or "mariadb"
	DSN  string `yaml:"dsn" mapstructure:"dsn" validate:"required"`                        // DSN: SQLite file path or MariaDB "user:password@tcp(host:port)/dbname"
}

// KrsDatabaseConf represents database configuration for KRS (SQLite only for edge nodes)
type KrsDatabaseConf struct {
	DSN string `yaml:"dsn" mapstructure:"dsn" validate:"required"` // SQLite file path
}

// NodeConf represents the edge node's identity and connection info
type NodeConf struct {
	ID              string `yaml:"id" mapstructure:"id" validate:"required"`              // Node ID (must match KDC)
	LongTermPrivKey string `yaml:"long_term_priv_key" mapstructure:"long_term_priv_key" validate:"required"` // Path to HPKE long-term private key file
	KdcAddress      string `yaml:"kdc_address" mapstructure:"kdc_address" validate:"required"` // KDC server address (IP:port)
	KdcHpkePubKey   string `yaml:"kdc_hpke_pubkey,omitempty" mapstructure:"kdc_hpke_pubkey"` // KDC HPKE public key (hex encoded, for future communications)
}

// DnsEngineConf represents DNS engine configuration for NOTIFY receiver
type DnsEngineConf struct {
	Addresses []string `yaml:"addresses" mapstructure:"addresses" validate:"required"` // Addresses to listen on
	Transports []string `yaml:"transports" mapstructure:"transports" validate:"required,min=1,dive,oneof=do53"` // Only do53 for now
}

// GetChunkMaxSize returns the configured chunk size, or default (60000) if not set
func (conf *KdcConf) GetChunkMaxSize() int {
	if conf.ChunkMaxSize <= 0 {
		return 60000 // Default: 60KB
	}
	return conf.ChunkMaxSize
}

// GetDistributionTTL returns the configured distribution TTL, or default (5 minutes) if not set
func (conf *KdcConf) GetDistributionTTL() time.Duration {
	if conf.DistributionTTL <= 0 {
		return 5 * time.Minute // Default: 5 minutes (like TSIG signatures)
	}
	return conf.DistributionTTL
}

// GetBootstrapExpirationWindow returns the configured bootstrap expiration window, or default (5 minutes) if not set
func (conf *KdcConf) GetBootstrapExpirationWindow() time.Duration {
	if conf.BootstrapExpirationWindow <= 0 {
		return 5 * time.Minute // Default: 5 minutes
	}
	return conf.BootstrapExpirationWindow
}
