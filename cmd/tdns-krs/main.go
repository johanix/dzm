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
	"github.com/johanix/dzm/v0.x/dzm/krs"
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

	// Setup KRS API routes
	// Pass conf as map to avoid circular import, and pass ping handler
	confMap := map[string]interface{}{
		"ApiServer": map[string]interface{}{
			"ApiKey":    conf.ApiServer.ApiKey,
			"Addresses": conf.ApiServer.Addresses,
		},
	}
	krs.SetupKrsAPIRoutes(apirouter, krsDB, &krsConf, confMap, tdns.APIping(conf))

	// Start API dispatcher
	go func() {
		log.Printf("TDNS %s (%s): starting: APIdispatcher", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
		if err := tdns.APIdispatcher(conf, apirouter, conf.Internal.APIStopCh); err != nil {
			log.Printf("Error from APIdispatcher engine: %v", err)
		}
	}()

	// Start NOTIFY receiver
	if len(krsConf.DnsEngine.Addresses) > 0 {
		log.Printf("KRS: Starting NOTIFY receiver with %d addresses", len(krsConf.DnsEngine.Addresses))
		go func() {
			log.Printf("TDNS %s (%s): starting: NotifyReceiver", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
			log.Printf("KRS: NotifyReceiver engine starting")
			if err := krs.StartNotifyReceiver(ctx, krsDB, &krsConf); err != nil {
				log.Printf("Error from NotifyReceiver engine: %v", err)
			}
		}()
	} else {
		log.Printf("KRS: WARNING: No DNS engine addresses configured, NOTIFY receiver not started")
	}

	// Start key state worker for automatic transitions
	go func() {
		log.Printf("TDNS %s (%s): starting: KeyStateWorker", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
		log.Printf("KRS: Starting KeyStateWorker")
		if err := krs.KeyStateWorker(ctx, krsDB); err != nil {
			log.Printf("Error from KeyStateWorker: %v", err)
		}
	}()

	log.Printf("TDNS %s (%s): KRS started successfully", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
	return nil
}

