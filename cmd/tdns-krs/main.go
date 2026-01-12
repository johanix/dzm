/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-krs - Key Receiving Service daemon (edge receiver for HPKE key distribution)
 */

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/johanix/dzm/v0.x/krs"
	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/johanix/tdns/v0.x/tdns/hpke"
	"gopkg.in/yaml.v3"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeKrs
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conf := &tdns.Conf
	err := conf.MainInit(ctx, tdns.DefaultKrsCfgFile)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	apirouter, err := conf.SetupAPIRouter(ctx)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error setting up API router: %v", err))
	}

	// SIGHUP reload watcher
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				log.Printf("SIGHUP received - reload not yet implemented for KRS")
			}
		}
	}()

	// Initialize KRS (replaces conf.StartKrs())
	err = startKrs(ctx, conf, apirouter)
	if err != nil {
		// Print error to stdout/stderr for visibility
		fmt.Fprintf(os.Stderr, "FATAL: Error starting KRS: %v\n", err)
		tdns.Shutdowner(conf, fmt.Sprintf("Error starting KRS: %v", err))
	}

	// Enter main loop
	conf.MainLoop(ctx, stop)
}

// startKrs initializes and starts all KRS subsystems
// This replaces the tdns.StartKrs() function but uses dzm packages
func startKrs(ctx context.Context, conf *tdns.Config, apirouter *mux.Router) error {
	// Parse KRS configuration from stored YAML bytes
	var krsConf krs.KrsConf

	// conf.Internal.KrsConf is either []byte (YAML) or already *krs.KrsConf
	switch v := conf.Internal.KrsConf.(type) {
	case []byte:
		// Unmarshal YAML bytes into krs.KrsConf
		if err := yaml.Unmarshal(v, &krsConf); err != nil {
			return fmt.Errorf("failed to unmarshal KRS config: %v", err)
		}
		conf.Internal.KrsConf = &krsConf
	case *krs.KrsConf:
		krsConf = *v
	default:
		return fmt.Errorf("KRS configuration not found or invalid type (got %T)", conf.Internal.KrsConf)
	}

	// Initialize KRS database
	krsDB, err := krs.NewKrsDB(krsConf.Database.DSN)
	if err != nil {
		// Return detailed error message (already includes helpful instructions)
		return fmt.Errorf("failed to initialize KRS database: %v", err)
	}
	conf.Internal.KrsDB = krsDB

	// Load node configuration (long-term HPKE private key)
	privKeyData, err := os.ReadFile(krsConf.Node.LongTermPrivKey)
	if err != nil {
		return fmt.Errorf("failed to read long-term private key: %v", err)
	}

	// Parse private key (hex format with optional comments)
	privKeyHex := ""
	lines := strings.Split(string(privKeyData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			privKeyHex += line
		}
	}

	// Decode hex private key
	privKey, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode private key (must be hex): %v", err)
	}
	if len(privKey) != 32 {
		return fmt.Errorf("private key must be 32 bytes (got %d)", len(privKey))
	}

	// Derive public key from private key
	pubKey, err := hpke.DerivePublicKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to derive public key: %v", err)
	}

	// Store node config in database
	nodeConfig := &krs.NodeConfig{
		ID:              krsConf.Node.ID,
		LongTermPubKey:  pubKey,
		LongTermPrivKey: privKey,
		KdcAddress:      krsConf.Node.KdcAddress,
		ControlZone:     krsConf.ControlZone,
		RegisteredAt:    time.Now(),
		LastSeen:        time.Now(),
	}
	if err := krsDB.SetNodeConfig(nodeConfig); err != nil {
		return fmt.Errorf("failed to store node config: %v", err)
	}

	// Register KRS API routes directly on the router
	// Pass conf as map to avoid circular import, and pass ping handler
	confMap := map[string]interface{}{
		"ApiServer": map[string]interface{}{
			"ApiKey":    conf.ApiServer.ApiKey,
			"Addresses": conf.ApiServer.Addresses,
		},
	}
	// Call SetupKrsAPIRoutes directly on the router (not via RegisterAPIRoute)
	// because SetupAPIRouter has already been called and returned
	krs.SetupKrsAPIRoutes(apirouter, krsDB, &krsConf, confMap, tdns.APIping(conf))

	// Start API dispatcher
	go func() {
		log.Printf("TDNS %s (%s): starting: APIdispatcher", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
		if err := tdns.APIdispatcher(conf, apirouter, conf.Internal.APIStopCh); err != nil {
			log.Printf("Error from APIdispatcher engine: %v", err)
		}
	}()

	// Register debug query handler FIRST (for all queries) - logs all queries before processing
	// This is optional - only register if debug mode is enabled
	if tdns.Globals.Debug {
		if err := tdns.RegisterDebugQueryHandler(); err != nil {
			return fmt.Errorf("failed to register debug query handler: %v", err)
		}
		log.Printf("KRS: Registered debug query handler")
	}

	// Register debug NOTIFY handler FIRST (for all NOTIFYs) - logs all NOTIFYs before processing
	// This is optional - only register if debug mode is enabled
	if tdns.Globals.Debug {
		if err := tdns.RegisterDebugNotifyHandler(); err != nil {
			return fmt.Errorf("failed to register debug NOTIFY handler: %v", err)
		}
		log.Printf("KRS: Registered debug NOTIFY handler")
	}

	// Register KRS NOTIFY handler (handles all NOTIFYs for control zone and distributions)
	// KRS handles NOTIFYs for any qtype, so we register with qtype=0 (all NOTIFYs)
	krsNotifyHandler := func(ctx context.Context, dnr *tdns.DnsNotifyRequest) error {
		return krs.HandleKrsNotify(ctx, dnr, krsDB, &krsConf)
	}
	if err := tdns.RegisterNotifyHandler(0, krsNotifyHandler); err != nil {
		return fmt.Errorf("failed to register KRS NOTIFY handler: %v", err)
	}
	log.Printf("KRS: Registered NOTIFY handler for all NOTIFYs")

	// Register engines using the registration API
	if len(krsConf.DnsEngine.Addresses) > 0 {
		if err := tdns.RegisterEngine("DnsEngine", func(ctx context.Context) error {
			return tdns.DnsEngine(ctx, conf)
		}); err != nil {
			return fmt.Errorf("failed to register DnsEngine: %v", err)
		}
	} else {
		log.Printf("KRS: WARNING: No DNS engine addresses configured, DnsEngine not started")
	}

	if err := tdns.RegisterEngine("KeyStateWorker", func(ctx context.Context) error {
		return krs.KeyStateWorker(ctx, krsDB)
	}); err != nil {
		return fmt.Errorf("failed to register KeyStateWorker: %v", err)
	}

	// Start all registered engines (including DnsEngine and KeyStateWorker)
	tdns.StartRegisteredEngines(ctx)

	log.Printf("TDNS %s (%s): KRS started successfully", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
	return nil
}

