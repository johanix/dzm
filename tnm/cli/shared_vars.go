/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 * Shared variables for CLI commands
 */
package cli

import (
	"time"

	"github.com/spf13/cobra"
)

// Variables used by PrepArgs and other CLI functions
// These are stubs for variables that may be defined in other CLI files
var (
	keyid        uint16
	parpri       string
	childpri     string
	keytype      string
	NewState     string
	rollaction   string
	myIdentity   string
	filename     string
	childSig0Src string
	timelayout   = time.RFC3339
)

// Stub commands for ping.go init function
var (
	CombinerCmd = &cobra.Command{Use: "combiner", Hidden: true}
	AgentCmd    = &cobra.Command{Use: "agent", Hidden: true}
)
