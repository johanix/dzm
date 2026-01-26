/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC component CLI commands
 */
package cli

import (
	"fmt"
	"log"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var KdcComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage components in KDC",
}

var kdcComponentAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new component",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		componentName := cmd.Flag("name").Value.String()
		if componentName == "" {
			log.Fatalf("Error: --name is required")
		}

		componentID := cmd.Flag("cid").Value.String()
		if componentID == "" {
			log.Fatalf("Error: --cid is required")
		}

		comment := cmd.Flag("comment").Value.String()

		req := map[string]interface{}{
			"command": "add",
			"component": map[string]interface{}{
				"id":      componentID,
				"name":    componentName,
				"active":  true,
				"comment": comment,
			},
		}

		resp, err := sendKdcRequest(api, "/kdc/component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcComponentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all components",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		componentsRaw, ok := resp["components"]
		if !ok {
			fmt.Println("No components found")
			return
		}

		components, ok := componentsRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: 'components' is not an array")
		}

		if len(components) == 0 {
			fmt.Println("No components configured")
			return
		}

		// Build table rows for columnize
		var lines []string
		lines = append(lines, "ID | Name | Active | Comment")

		for _, c := range components {
			component, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			id := getString(component, "id")
			name := getString(component, "name")
			active := getBool(component, "active")
			comment := getString(component, "comment")
			activeStr := "yes"
			if !active {
				activeStr = "no"
			}
			lines = append(lines, fmt.Sprintf("%s | %s | %s | %s", id, name, activeStr, comment))
		}

		fmt.Println(columnize.SimpleFormat(lines))
	},
}

var kdcComponentDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a component",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		componentID := cmd.Flag("cid").Value.String()
		if componentID == "" {
			log.Fatalf("Error: --cid is required")
		}

		req := map[string]interface{}{
			"command":      "delete",
			"component_id": componentID,
		}

		resp, err := sendKdcRequest(api, "/kdc/component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

func init() {
	KdcComponentCmd.AddCommand(kdcComponentAddCmd, kdcComponentListCmd, kdcComponentDeleteCmd)

	// Component command flags
	kdcComponentAddCmd.Flags().String("cid", "", "Component ID")
	kdcComponentAddCmd.Flags().StringP("name", "n", "", "Component name")
	kdcComponentAddCmd.Flags().String("comment", "", "Comment")
	kdcComponentAddCmd.MarkFlagRequired("name")
	kdcComponentAddCmd.MarkFlagRequired("cid")
	kdcComponentDeleteCmd.Flags().String("cid", "", "Component ID")
	kdcComponentDeleteCmd.MarkFlagRequired("cid")
}
