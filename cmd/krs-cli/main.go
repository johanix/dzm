/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * krs-cli - CLI tool for interacting with tdns-krs
 */

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/johanix/tdns-nm/tnm/cli"
	"github.com/johanix/tdns/v2"
)

var cfgFile, cfgFileUsed string
var LocalConfig string

var rootCmd = &cobra.Command{
	Use:   "krs-cli",
	Short: "krs-cli is a tool used to interact with tdns-krs via API",
	Long:  `krs-cli provides commands to manage received keys and node configuration in the Key Receiving Service (KRS)`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Set up CLI logging with file/line info when verbose or debug mode is enabled
		tdns.SetupCliLogging()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig, initApi)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", tdns.DefaultKrsCfgFile))
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "zone name")
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.ParentZone, "pzone", "Z", "", "parent zone name")

	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d",
		false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v",
		false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.ShowHeaders, "headers", "H",
		false, "show headers")

	// Set the client key for API client lookups
	cli.SetClientKey("tdns-krs")

	// Add all KRS commands directly to root (no "krs" prefix needed)
	// Note: bootstrap command is added separately since it doesn't require config initialization
	rootCmd.AddCommand(cli.KrsDnssecCmd, cli.KrsConfigCmd, cli.KrsQueryCmd, cli.KrsDebugCmd,
		cli.PingCmd, cli.DaemonCmd, cli.KrsEnrollCmd, cli.KrsComponentsCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Default to tdns-krs.yaml (KRS daemon config file)
		viper.SetConfigFile(tdns.DefaultKrsCfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		if tdns.Globals.Verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		log.Fatalf("Could not load config %s: Error: %v", viper.ConfigFileUsed(), err)
	}

	// Note: KRS config doesn't use localconfig merging like the old CLI config format
	// The KRS config is a single file that contains all necessary information

	// Unmarshal into KRS config structure
	err := viper.Unmarshal(&krsConfig)
	if err != nil {
		log.Fatalf("Error unmarshaling KRS config: %v", err)
	}

	// Set default UseTLS to true if not explicitly set in config
	// Viper doesn't set zero values, so we check if the key exists
	if !viper.IsSet("apiserver.usetls") {
		krsConfig.ApiServer.UseTLS = true
	}
}

// KrsConfig represents the KRS daemon configuration file structure
type KrsConfig struct {
	ApiServer struct {
		UseTLS    bool     `yaml:"usetls"` // Defaults to true if not set
		Addresses []string `yaml:"addresses"`
		ApiKey    string   `yaml:"apikey"`
		CertFile  string   `yaml:"certfile,omitempty"`
		KeyFile   string   `yaml:"keyfile,omitempty"`
		BaseURL   string   `yaml:"baseurl,omitempty"` // Base URL for API client (used by krs-cli)
	} `yaml:"apiserver"`
	Keys tdns.KeyConf `yaml:"keys,omitempty"` // Optional: TSIG keys if needed
}

var krsConfig KrsConfig

func initApi() {
	// Extract API connection details from KRS config file
	if krsConfig.ApiServer.ApiKey == "" {
		log.Fatalf("initApi: No API key found in KRS config file")
	}

	// Use explicit baseurl from config if available, otherwise construct from address
	baseURL := krsConfig.ApiServer.BaseURL
	if baseURL == "" {
		// Fallback: construct from address (for backward compatibility)
		if len(krsConfig.ApiServer.Addresses) == 0 {
			log.Fatalf("initApi: No API baseurl or addresses found in KRS config file")
		}
		address := krsConfig.ApiServer.Addresses[0]
		if krsConfig.ApiServer.UseTLS {
			baseURL = fmt.Sprintf("https://%s", address)
		} else {
			baseURL = fmt.Sprintf("http://%s", address)
		}
	}

	if tdns.Globals.Debug {
		fmt.Printf("initApi: Setting up API client for tdns-krs\n")
		fmt.Printf("  BaseURL: %s\n", baseURL)
		fmt.Printf("  UseTLS: %v\n", krsConfig.ApiServer.UseTLS)
	}

	// Create API client
	// AuthMethod is "X-API-Key" for KRS API (matches the header name)
	tmp := tdns.NewClient("tdns-krs", baseURL, krsConfig.ApiServer.ApiKey, "X-API-Key", "insecure")
	if tmp == nil {
		log.Fatalf("initApi: Failed to setup API client for tdns-krs. Exiting.")
	}
	tdns.Globals.ApiClients["tdns-krs"] = tmp

	// Store the API client for "tdns-krs" for convenience
	tdns.Globals.Api = tdns.Globals.ApiClients["tdns-krs"]

	// Parse TSIG keys if present (optional in KRS config)
	if len(krsConfig.Keys.Tsig) > 0 {
		numtsigs, _ := tdns.ParseTsigKeys(&krsConfig.Keys)
		if tdns.Globals.Debug {
			fmt.Printf("Parsed %d TSIG keys\n", numtsigs)
		}
	}
}

func main() {
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate
	Execute()
}
