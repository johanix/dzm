/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * kdc-cli - CLI tool for interacting with tdns-kdc
 */

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/johanix/dzm/v0.x/dzm/cli"
	"github.com/johanix/tdns/v0.x/tdns"
)

var cfgFile, cfgFileUsed string
var LocalConfig string

var rootCmd = &cobra.Command{
	Use:   "kdc-cli",
	Short: "kdc-cli is a tool used to interact with tdns-kdc via API",
	Long:  `kdc-cli provides commands to manage zones, nodes, keys, and distributions in the Key Distribution Center (KDC)`,
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
		fmt.Sprintf("config file (default is %s)", tdns.DefaultCliCfgFile))
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "zone name")
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.ParentZone, "pzone", "Z", "", "parent zone name")

	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d",
		false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v",
		false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.ShowHeaders, "headers", "H",
		false, "show headers")

	// Set the client key for API client lookups
	cli.SetClientKey("tdns-kdc")

	// Add all KDC commands directly to root (no "kdc" prefix needed)
	rootCmd.AddCommand(cli.KdcZoneCmd, cli.KdcNodeCmd, cli.KdcConfigCmd, cli.KdcDebugCmd, 
		cli.KdcDistribCmd, cli.KdcServiceCmd, cli.KdcComponentCmd, cli.PingCmd, cli.DaemonCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(tdns.DefaultCliCfgFile)
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

	LocalConfig = viper.GetString("cli.localconfig")
	if LocalConfig != "" {
		_, err := os.Stat(LocalConfig)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Fatalf("Error stat(%s): %v", LocalConfig, err)
			}
		} else {
			viper.SetConfigFile(LocalConfig)
			if err := viper.MergeInConfig(); err != nil {
				log.Fatalf("Error merging in local config from '%s'", LocalConfig)
			} else {
				if tdns.Globals.Verbose {
					fmt.Printf("Merging in local config from '%s'\n", LocalConfig)
				}
			}
		}
		viper.SetConfigFile(LocalConfig)
	}

	cli.ValidateConfig(nil, cfgFileUsed) // will terminate on error
	err := viper.Unmarshal(&cconf)
	if err != nil {
		log.Printf("Error from viper.UnMarshal(cfg): %v", err)
	}
}

var cconf CliConf

type CliConf struct {
	ApiServers []ApiDetails `yaml:"apiservers"`
	Keys       tdns.KeyConf `yaml:"keys"`
}

type ApiDetails struct {
	Name       string `validate:"required" yaml:"name"`
	BaseURL    string `validate:"required" yaml:"baseurl"`
	ApiKey     string `validate:"required" yaml:"apikey"`
	AuthMethod string `validate:"required" yaml:"authmethod"`
	Command    string `yaml:"command,omitempty"` // Optional: command to start the daemon
}

func initApi() {
	if tdns.Globals.Debug {
		fmt.Printf("initApi: setting up API clients for:")
	}
	for _, val := range cconf.ApiServers {
		tmp := tdns.NewClient(val.Name, val.BaseURL, val.ApiKey, val.AuthMethod, "insecure")
		if tmp == nil {
			log.Fatalf("initApi: Failed to setup API client for %q. Exiting.", val.Name)
		}
		tdns.Globals.ApiClients[val.Name] = tmp
		if tdns.Globals.Debug {
			fmt.Printf(" %s ", val.Name)
		}
	}
	if tdns.Globals.Debug {
		fmt.Printf("\n")
	}

	// Store the API client for "tdns-kdc" for convenience
	tdns.Globals.Api = tdns.Globals.ApiClients["tdns-kdc"]

	numtsigs, _ := tdns.ParseTsigKeys(&cconf.Keys)
	if tdns.Globals.Debug {
		fmt.Printf("Parsed %d TSIG keys\n", numtsigs)
	}
}

func main() {
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate
	Execute()
}

