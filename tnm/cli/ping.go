/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// getClientKey returns the client key for the current CLI tool.
// This is set by the main.go files (kdc-cli sets it to "tdns-kdc", krs-cli sets it to "tdns-krs").
var currentClientKey string

// SetClientKey sets the client key for API client lookups.
// This should be called from main.go before executing commands.
func SetClientKey(key string) {
	currentClientKey = key
}

// getClientKey returns the current client key.
func getClientKey() string {
	return currentClientKey
}

// getApiClient gets the API client for the current CLI tool.
// Since kdc-cli and krs-cli each only interact with one server,
// we don't need a parent command parameter.
func getApiClient(dieOnError bool) (*tdns.ApiClient, error) {
	clientKey := getClientKey()
	if clientKey == "" {
		if dieOnError {
			log.Fatalf("No client key set. This should not happen.")
		}
		return nil, fmt.Errorf("no client key set")
	}

	client := tdns.Globals.ApiClients[clientKey]
	if client == nil {
		if dieOnError {
			keys := make([]string, 0, len(tdns.Globals.ApiClients))
			for k := range tdns.Globals.ApiClients {
				keys = append(keys, k)
			}
			log.Fatalf("No API client found for %s (have clients for: %v)", clientKey, keys)
		}
		return nil, fmt.Errorf("no API client found for %s", clientKey)
	}

	if tdns.Globals.Debug {
		fmt.Printf("Using API client for %q:\nBaseUrl: %s\n", clientKey, client.BaseUrl)
	}
	return client, nil
}

// getApiDetailsByClientKey retrieves the ApiDetails configuration for a given clientKey
// by looking it up in the CLI config via viper.
func getApiDetailsByClientKey(clientKey string) map[string]interface{} {
	apiservers := viper.Get("apiservers")
	if apiservers == nil {
		return nil
	}

	servers, ok := apiservers.([]interface{})
	if !ok {
		return nil
	}

	for _, server := range servers {
		serverMap, ok := server.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := serverMap["name"].(string); ok && name == clientKey {
			return serverMap
		}
	}
	return nil
}

var PingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Send an API ping request and present the response",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			log.Fatal("ping must have no arguments")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		pr, err := api.SendPing(tdns.Globals.PingCount, false)
		if err != nil {
			if strings.Contains(err.Error(), "connection refused") {
				fmt.Printf("Error: connection refused. Most likely the daemon is not running\n")
				os.Exit(1)
			} else {
				log.Fatalf("Error from SendPing: %v", err)
			}
		}

		uptime := time.Since(pr.BootTime).Truncate(time.Second)
		weeks := uptime / (7 * 24 * time.Hour)
		uptime %= 7 * 24 * time.Hour
		days := uptime / (24 * time.Hour)
		uptime %= 24 * time.Hour
		hours := uptime / time.Hour
		uptime %= time.Hour
		minutes := uptime / time.Minute
		uptime %= time.Minute
		seconds := uptime / time.Second

		var uptimeStr string
		if weeks > 0 {
			uptimeStr = fmt.Sprintf("%dw%dd", weeks, days)
		} else if days > 0 {
			uptimeStr = fmt.Sprintf("%dd%dh", days, hours)
		} else if hours > 0 {
			uptimeStr = fmt.Sprintf("%dh%dm", hours, minutes)
		} else {
			uptimeStr = fmt.Sprintf("%dm%ds", minutes, seconds)
		}

		if tdns.Globals.Verbose {
			fmt.Printf("%s (version %s): pings: %d, pongs: %d, uptime: %s, time: %s, client: %s\n",
				pr.Msg, pr.Version, pr.Pings, pr.Pongs, uptimeStr, pr.Time.Format(timelayout), pr.Client)
		} else {
			fmt.Printf("%s: pings: %d, pongs: %d, uptime: %s, time: %s\n",
				pr.Msg, pr.Pings, pr.Pongs, uptimeStr, pr.Time.Format(timelayout))
		}
	},
}

func init() {
	PingCmd.Flags().IntVarP(&tdns.Globals.PingCount, "count", "c", 0, "#pings to send")
	PingCmd.Flags().BoolVarP(&newapi, "newapi", "n", false, "use new api client")
}
