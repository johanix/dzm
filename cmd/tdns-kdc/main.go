/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-kdc - Key Distribution Center daemon
 */

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/johanix/dzm/v0.x/dzm/kdc"
	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/johanix/tdns/v0.x/tdns/hpke"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeKdc
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conf := &tdns.Conf
	err := conf.MainInit(ctx, tdns.DefaultKdcCfgFile)
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
				log.Printf("SIGHUP received - reload not yet implemented for KDC")
			}
		}
	}()

	// Initialize KDC (replaces conf.StartKdc())
	err = startKdc(ctx, conf, apirouter)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error starting KDC: %v", err))
	}

	// Enter main loop
	conf.MainLoop(ctx, stop)
}

// startKdc initializes and starts all KDC subsystems
// This replaces the tdns.StartKdc() function but uses dzm packages
func startKdc(ctx context.Context, conf *tdns.Config, apirouter *mux.Router) error {
	// Parse KDC configuration from stored YAML bytes
	var kdcConf kdc.KdcConf

	// conf.Internal.KdcConf is either []byte (YAML) or already *kdc.KdcConf
	switch v := conf.Internal.KdcConf.(type) {
	case []byte:
		// Unmarshal YAML bytes into kdc.KdcConf
		if err := yaml.Unmarshal(v, &kdcConf); err != nil {
			return fmt.Errorf("failed to unmarshal KDC config: %v", err)
		}
		conf.Internal.KdcConf = &kdcConf
	case *kdc.KdcConf:
		kdcConf = *v
	default:
		return fmt.Errorf("KDC configuration not found or invalid type (got %T)", conf.Internal.KdcConf)
	}

	kdcDB, err := kdc.NewKdcDB(kdcConf.Database.Type, kdcConf.Database.DSN)
	if err != nil {
		return fmt.Errorf("failed to initialize KDC database: %v", err)
	}
	conf.Internal.KdcDB = kdcDB

	// Register KDC API routes using the registration API
	// Pass conf as map to avoid circular import, and pass ping handler
	confMap := map[string]interface{}{
		"ApiServer": map[string]interface{}{
			"ApiKey":    conf.ApiServer.ApiKey,
			"Addresses": conf.ApiServer.Addresses,
		},
		"DnsEngine": map[string]interface{}{
			"Addresses": conf.DnsEngine.Addresses,
		},
		"KdcConf": &kdcConf,
	}
	if err := tdns.RegisterAPIRoute(func(router *mux.Router) error {
		kdc.SetupKdcAPIRoutes(router, kdcDB, confMap, tdns.APIping(conf))
		return nil
	}); err != nil {
		return fmt.Errorf("failed to register KDC API routes: %v", err)
	}

	// Start API dispatcher (this is a TDNS internal engine, not registered)
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
		log.Printf("KDC: Registered debug query handler")
	}

	// Register query handlers for KDC-specific query types using the new registration API
	// This replaces the old channel-based approach
	kdcQueryHandler := func(ctx context.Context, dqr *tdns.DnsQueryRequest) error {
		if tdns.Globals.Debug {
			log.Printf("KDC: QueryHandler invoked (qname=%s, qtype=%s)", dqr.Qname, dns.TypeToString[dqr.Qtype])
		}
		// Convert DnsQueryRequest to kdc.KdcQueryRequest
		kdcReq := &kdc.KdcQueryRequest{
			ResponseWriter: dqr.ResponseWriter,
			Msg:            dqr.Msg,
			Qname:          dqr.Qname,
			Qtype:          dqr.Qtype,
			Options:        dqr.Options,
		}
		// Call KDC handler (will return ErrNotHandled for unsupported qtypes)
		return kdc.HandleKdcQuery(ctx, kdcReq, kdcDB, &kdcConf)
	}

	// Register handlers for each qtype that KDC handles
	if err := tdns.RegisterQueryHandler(hpke.TypeKMREQ, kdcQueryHandler); err != nil {
		return fmt.Errorf("failed to register KMREQ handler: %v", err)
	}
	if err := tdns.RegisterQueryHandler(hpke.TypeKMCTRL, kdcQueryHandler); err != nil {
		return fmt.Errorf("failed to register KMCTRL handler: %v", err)
	}
	if err := tdns.RegisterQueryHandler(core.TypeJSONMANIFEST, kdcQueryHandler); err != nil {
		return fmt.Errorf("failed to register JSONMANIFEST handler: %v", err)
	}
	if err := tdns.RegisterQueryHandler(core.TypeJSONCHUNK, kdcQueryHandler); err != nil {
		return fmt.Errorf("failed to register JSONCHUNK handler: %v", err)
	}
	log.Printf("KDC: Registered query handlers for KMREQ, KMCTRL, JSONMANIFEST, and JSONCHUNK")

	// Register debug NOTIFY handler FIRST (for all NOTIFYs) - logs all NOTIFYs before processing
	// This is optional - only register if debug mode is enabled
	if tdns.Globals.Debug {
		if err := tdns.RegisterDebugNotifyHandler(); err != nil {
			return fmt.Errorf("failed to register debug NOTIFY handler: %v", err)
		}
		log.Printf("KDC: Registered debug NOTIFY handler")
	}

	// Register KDC NOTIFY handler (handles confirmation NOTIFYs from KRS)
	// Only handles JSONMANIFEST NOTIFYs
	kdcNotifyHandler := func(ctx context.Context, dnr *tdns.DnsNotifyRequest) error {
		if tdns.Globals.Debug {
			log.Printf("KDC: NotifyHandler callback invoked (qname=%s)", dnr.Qname)
		}
		// Call KDC NOTIFY handler
		return kdc.HandleKdcNotify(ctx, dnr.Msg, dnr.Qname, dnr.ResponseWriter, kdcDB, &kdcConf)
	}
	if err := tdns.RegisterNotifyHandler(core.TypeJSONMANIFEST, kdcNotifyHandler); err != nil {
		return fmt.Errorf("failed to register JSONMANIFEST NOTIFY handler: %v", err)
	}
	log.Printf("KDC: Registered NOTIFY handler for JSONMANIFEST")

	// Register engines using the registration API
	if err := tdns.RegisterEngine("DnsEngine", func(ctx context.Context) error {
		return tdns.DnsEngine(ctx, conf)
	}); err != nil {
		return fmt.Errorf("failed to register DnsEngine: %v", err)
	}

	if err := tdns.RegisterEngine("KeyStateWorker", func(ctx context.Context) error {
		return kdc.KeyStateWorker(ctx, kdcDB, &kdcConf)
	}); err != nil {
		return fmt.Errorf("failed to register KeyStateWorker: %v", err)
	}

	// Start all registered engines (including DnsEngine and KeyStateWorker)
	tdns.StartRegisteredEngines(ctx)

	log.Printf("TDNS %s (%s): KDC started successfully", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
	return nil
}

