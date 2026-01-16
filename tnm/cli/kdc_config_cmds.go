/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC config CLI commands
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var KdcConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage KDC configuration",
}

var kdcConfigGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get KDC configuration",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
		}

		resp, err := sendKdcRequest(api, "/kdc/config", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		configRaw, ok := resp["config"]
		if !ok {
			fmt.Printf("Error: 'config' key not found in response\n")
			return
		}

		config, ok := configRaw.(map[string]interface{})
		if !ok {
			fmt.Printf("Error: 'config' is not an object (got %T)\n", configRaw)
			return
		}

		// Pretty print the config
		configJSON, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling config: %v\n", err)
			return
		}
		fmt.Printf("%s\n", string(configJSON))
	},
}

func init() {
	KdcConfigCmd.AddCommand(kdcConfigGetCmd)
}
