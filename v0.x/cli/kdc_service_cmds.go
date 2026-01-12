/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC service CLI commands
 */
package cli

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var KdcServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage services in KDC",
}

var KdcServiceComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage service-component assignments",
	Long:  `Manage which components belong to which services`,
}

var KdcServiceTransactionCmd = &cobra.Command{
	Use:   "tx",
	Short: "Manage service modification transactions",
	Long:  `Transaction-based service modification allows batching multiple component changes and previewing their impact before applying them.`,
}

var kdcServiceAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new service",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		serviceName := cmd.Flag("name").Value.String()
		if serviceName == "" {
			log.Fatalf("Error: --name is required")
		}

		serviceID := cmd.Flag("sid").Value.String()
		if serviceID == "" {
			log.Fatalf("Error: --sid is required")
		}

		comment := cmd.Flag("comment").Value.String()

		req := map[string]interface{}{
			"command": "add",
			"service": map[string]interface{}{
				"id":      serviceID,
				"name":    serviceName,
				"active":  true,
				"comment": comment,
			},
		}

		resp, err := sendKdcRequest(api, "/kdc/service", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all services",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/service", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		servicesRaw, ok := resp["services"]
		if !ok {
			fmt.Println("No services found")
			return
		}

		services, ok := servicesRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: 'services' is not an array")
		}

		if len(services) == 0 {
			fmt.Println("No services configured")
			return
		}

		// Build table rows for columnize
		var rows []string
		rows = append(rows, "ID | Name | Active | Components | Comment")

		for _, s := range services {
			service, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			id := getString(service, "id")
			name := getString(service, "name")
			active := getBool(service, "active")
			comment := getString(service, "comment")
			activeStr := "yes"
			if !active {
				activeStr = "no"
			}
			
			// Always fetch and show components for this service
			componentsReq := map[string]interface{}{
				"command":      "list",
				"service_name": id, // Use ID to look up components
			}
			componentsResp, err := sendKdcRequest(api, "/kdc/service-component", componentsReq)
			componentsList := ""
			if err == nil && componentsResp["error"] != true {
				if assignmentsRaw, ok := componentsResp["assignments"]; ok {
					if assignments, ok := assignmentsRaw.([]interface{}); ok {
						componentIDs := make([]string, 0, len(assignments))
						for _, a := range assignments {
							if assignment, ok := a.(map[string]interface{}); ok {
								compID := getString(assignment, "component_id")
								if compID != "" {
									componentIDs = append(componentIDs, compID)
								}
							}
						}
						if len(componentIDs) > 0 {
							componentsList = strings.Join(componentIDs, ", ")
						} else {
							componentsList = "(none)"
						}
					}
				}
			}
			if componentsList == "" {
				componentsList = "(error fetching)"
			}
			rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s", id, name, activeStr, componentsList, comment))
		}
		
		if len(rows) > 1 {
			fmt.Println(columnize.SimpleFormat(rows))
		}
	},
}

var kdcServiceDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a service",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		serviceID := cmd.Flag("sid").Value.String()
		if serviceID == "" {
			log.Fatalf("Error: --sid is required")
		}

		req := map[string]interface{}{
			"command":    "delete",
			"service_id": serviceID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceComponentsCmd = &cobra.Command{
	Use:   "components",
	Short: "List components for a service",
	Long:  `List all components that are assigned to a specific service`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		serviceName := cmd.Flag("name").Value.String()
		if serviceName == "" {
			log.Fatalf("Error: --name is required")
		}

		req := map[string]interface{}{
			"command":      "list",
			"service_name": serviceName,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		assignmentsRaw, ok := resp["assignments"]
		if !ok {
			fmt.Printf("Service %s has no components assigned\n", serviceName)
			return
		}

		assignments, ok := assignmentsRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: 'assignments' is not an array")
		}

		if len(assignments) == 0 {
			fmt.Printf("Service %s has no components assigned\n", serviceName)
			return
		}

		fmt.Printf("Components for service %s:\n", serviceName)
		
		// Build table rows for columnize
		var rows []string
		rows = append(rows, "Component ID | Active")

		for _, a := range assignments {
			assignment, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			componentID := getString(assignment, "component_id")
			active := getBool(assignment, "active")
			activeStr := "yes"
			if !active {
				activeStr = "no"
			}
			rows = append(rows, fmt.Sprintf("%s | %s", componentID, activeStr))
		}
		
		if len(rows) > 1 {
			fmt.Println(columnize.SimpleFormat(rows))
		}
	},
}

var kdcServiceComponentAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Assign a component to a service",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "sname", "cname")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		serviceName := cmd.Flag("sname").Value.String()
		componentName := cmd.Flag("cname").Value.String()

		req := map[string]interface{}{
			"command":        "add",
			"service_name":   serviceName,
			"component_name": componentName,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceComponentDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Remove a component from a service",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "sname", "cname")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		serviceName := cmd.Flag("sname").Value.String()
		componentName := cmd.Flag("cname").Value.String()

		req := map[string]interface{}{
			"command":        "delete",
			"service_name":   serviceName,
			"component_name": componentName,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceComponentReplaceCmd = &cobra.Command{
	Use:   "replace",
	Short: "Atomically replace one component with another in a service",
	Long:  `Atomically replaces one component with another in a service. This ensures there's never a state with no signing component when replacing sign_* components. The operation is atomic: if adding the new component fails, the old one remains.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "sname")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		serviceName := cmd.Flag("sname").Value.String()
		oldComponentName := cmd.Flag("old").Value.String()
		newComponentName := cmd.Flag("new").Value.String()

		if oldComponentName == "" || newComponentName == "" {
			log.Fatalf("Error: --old and --new are required")
		}

		req := map[string]interface{}{
			"command":           "replace",
			"service_name":      serviceName,
			"old_component_name": oldComponentName,
			"new_component_name": newComponentName,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceTxStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a new service modification transaction",
	Long:  `Creates a new transaction for modifying a service. Returns a transaction token that can be used for subsequent operations.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		serviceID := cmd.Flag("sid").Value.String()
		if serviceID == "" {
			log.Fatalf("Error: --sid is required")
		}
		createdBy := cmd.Flag("created-by").Value.String()
		comment := cmd.Flag("comment").Value.String()

		req := map[string]interface{}{
			"command":    "start",
			"service_id": serviceID,
		}
		if createdBy != "" {
			req["created_by"] = createdBy
		}
		if comment != "" {
			req["comment"] = comment
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		txID := getString(resp, "tx_id")
		if txID != "" {
			fmt.Printf("Transaction started: %s\n", txID)
			fmt.Printf("%s\n", resp["msg"])
		} else {
			fmt.Printf("%s\n", resp["msg"])
		}
	},
}

var kdcServiceTxComponentAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a component to a transaction",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		txID := cmd.Flag("tx").Value.String()
		componentID := cmd.Flag("cid").Value.String()
		if componentID == "" {
			log.Fatalf("Error: --cid is required")
		}

		req := map[string]interface{}{
			"command":      "add-component",
			"tx_id":        txID,
			"component_id": componentID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceTxComponentDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Remove a component from a transaction",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		txID := cmd.Flag("tx").Value.String()
		componentID := cmd.Flag("cid").Value.String()
		if componentID == "" {
			log.Fatalf("Error: --cid is required")
		}

		req := map[string]interface{}{
			"command":      "remove-component",
			"tx_id":        txID,
			"component_id": componentID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceTxViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View the impact of a transaction (dry-run)",
	Long:  `Computes and displays what changes would result from committing the transaction, without actually applying them.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		txID := cmd.Flag("tx").Value.String()

		req := map[string]interface{}{
			"command": "view",
			"tx_id":   txID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		// Display delta report
		if deltaReportRaw, ok := resp["delta_report"]; ok {
			if deltaReport, ok := deltaReportRaw.(map[string]interface{}); ok {
				fmt.Printf("Transaction: %s\n", txID)
				fmt.Printf("Service: %s\n\n", getString(deltaReport, "service_id"))
				
				// Show component changes
				fmt.Printf("Component Changes:\n")
				
				// Original components
				if originalComps, ok := deltaReport["original_components"].([]interface{}); ok {
					compStrs := make([]string, len(originalComps))
					for i, c := range originalComps {
						compStrs[i] = fmt.Sprintf("%v", c)
					}
					if len(compStrs) == 0 {
						fmt.Printf("  Original: (none)\n")
					} else {
						fmt.Printf("  Original: %s\n", strings.Join(compStrs, ", "))
					}
				}
				
				// Updated components
				if updatedComps, ok := deltaReport["updated_components"].([]interface{}); ok {
					compStrs := make([]string, len(updatedComps))
					for i, c := range updatedComps {
						compStrs[i] = fmt.Sprintf("%v", c)
					}
					if len(compStrs) == 0 {
						fmt.Printf("  Updated:  (none)\n")
					} else {
						fmt.Printf("  Updated:  %s\n", strings.Join(compStrs, ", "))
					}
				}
				
				// Delta
				addedComps := []string{}
				if added, ok := deltaReport["added_components"].([]interface{}); ok {
					for _, c := range added {
						addedComps = append(addedComps, fmt.Sprintf("%v", c))
					}
				}
				removedComps := []string{}
				if removed, ok := deltaReport["removed_components"].([]interface{}); ok {
					for _, c := range removed {
						removedComps = append(removedComps, fmt.Sprintf("%v", c))
					}
				}
				
				if len(addedComps) > 0 || len(removedComps) > 0 {
					fmt.Printf("  Delta:\n")
					if len(addedComps) > 0 {
						fmt.Printf("    + Add:    %s\n", strings.Join(addedComps, ", "))
					}
					if len(removedComps) > 0 {
						fmt.Printf("    - Remove: %s\n", strings.Join(removedComps, ", "))
					}
				} else {
					fmt.Printf("  Delta: (no changes)\n")
				}
				
				// Service validation
				fmt.Printf("\nService Validation:\n")
				isValid := getBool(deltaReport, "is_valid")
				if isValid {
					fmt.Printf("  Status: ✓ Valid (has exactly one signing component)\n")
				} else {
					fmt.Printf("  Status: ✗ Invalid\n")
					if validationErrors, ok := deltaReport["validation_errors"].([]interface{}); ok {
						for _, errMsg := range validationErrors {
							fmt.Printf("    Error: %v\n", errMsg)
						}
					}
				}
				
				fmt.Printf("\nImpact Analysis:\n")
				
				// Summary
				if summary, ok := deltaReport["summary"].(map[string]interface{}); ok {
					totalAffected := getInt(summary, "total_zones_affected")
					newlyServed := getInt(summary, "zones_newly_served")
					noLongerServed := getInt(summary, "zones_no_longer_served")
					
					fmt.Printf("  Zones affected: %d\n", totalAffected)
					fmt.Printf("    - Zones newly served: %d\n", newlyServed)
					fmt.Printf("    - Zones no longer served: %d\n", noLongerServed)
					fmt.Printf("  Distributions to create: %v\n", getString(summary, "distributions_to_create"))
					fmt.Printf("  Distributions to revoke: %v\n", getString(summary, "distributions_to_revoke"))
					fmt.Printf("  Total nodes affected: %v\n", getString(summary, "total_nodes_affected"))
					
					// Show warning if no zones affected but service has zones
					if totalAffected == 0 {
						fmt.Printf("\n  Note: No zones are affected by this transaction.\n")
						fmt.Printf("        This may mean:\n")
						fmt.Printf("        - No zones are assigned to this service, OR\n")
						fmt.Printf("        - All nodes already serve other components of this service, OR\n")
						fmt.Printf("        - No nodes serve the components being added/removed\n")
					}
				}
				
				// Zones newly served
				if newlyServed, ok := deltaReport["zones_newly_served"].(map[string]interface{}); ok && len(newlyServed) > 0 {
					fmt.Printf("\nZones newly served:\n")
					for zoneName, nodesRaw := range newlyServed {
						if nodes, ok := nodesRaw.([]interface{}); ok {
							nodeStrs := make([]string, len(nodes))
							for i, n := range nodes {
								nodeStrs[i] = fmt.Sprintf("%v", n)
							}
							fmt.Printf("  - %s → nodes: %s\n", zoneName, strings.Join(nodeStrs, ", "))
						}
					}
				}
				
				// Zones no longer served
				if noLongerServed, ok := deltaReport["zones_no_longer_served"].(map[string]interface{}); ok && len(noLongerServed) > 0 {
					fmt.Printf("\nZones no longer served:\n")
					for zoneName, nodesRaw := range noLongerServed {
						if nodes, ok := nodesRaw.([]interface{}); ok {
							nodeStrs := make([]string, len(nodes))
							for i, n := range nodes {
								nodeStrs[i] = fmt.Sprintf("%v", n)
							}
							fmt.Printf("  - %s → nodes: %s\n", zoneName, strings.Join(nodeStrs, ", "))
						}
					}
				}
			}
		} else {
			fmt.Printf("%s\n", resp["msg"])
		}
	},
}

var kdcServiceTxCommitCmd = &cobra.Command{
	Use:   "commit",
	Short: "Commit a transaction (apply changes)",
	Long:  `Applies all pending changes in the transaction and creates key distributions. Use --dry-run to preview without applying.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		txID := cmd.Flag("tx").Value.String()
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		req := map[string]interface{}{
			"command": "commit",
			"tx_id":   txID,
			"dry_run": dryRun,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		
		// If dry-run, show delta report
		if dryRun {
			if deltaReportRaw, ok := resp["delta_report"]; ok {
				if deltaReport, ok := deltaReportRaw.(map[string]interface{}); ok {
					if summary, ok := deltaReport["summary"].(map[string]interface{}); ok {
						fmt.Printf("\nSummary:\n")
						fmt.Printf("  Zones affected: %v\n", getString(summary, "total_zones_affected"))
						fmt.Printf("  Distributions to create: %v\n", getString(summary, "distributions_to_create"))
					}
				}
			}
		}
	},
}

var kdcServiceTxRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Rollback a transaction (cancel changes)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		txID := cmd.Flag("tx").Value.String()

		req := map[string]interface{}{
			"command": "rollback",
			"tx_id":   txID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceTxStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show transaction status and details",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "tx")
		
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		txID := cmd.Flag("tx").Value.String()

		req := map[string]interface{}{
			"command": "get",
			"tx_id":   txID,
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if tx, ok := resp["transaction"].(map[string]interface{}); ok {
			fmt.Printf("Transaction: %s\n", getString(tx, "id"))
			fmt.Printf("Service: %s\n", getString(tx, "service_id"))
			fmt.Printf("State: %s\n", getString(tx, "state"))
			fmt.Printf("Created: %s\n", getString(tx, "created_at"))
			fmt.Printf("Expires: %s\n", getString(tx, "expires_at"))
			if comment := getString(tx, "comment"); comment != "" {
				fmt.Printf("Comment: %s\n", comment)
			}
			
			if changes, ok := tx["changes"].(map[string]interface{}); ok {
				fmt.Printf("\nPending Changes:\n")
				if addComps, ok := changes["add_components"].([]interface{}); ok && len(addComps) > 0 {
					compStrs := make([]string, len(addComps))
					for i, c := range addComps {
						compStrs[i] = fmt.Sprintf("%v", c)
					}
					fmt.Printf("  + Add: %s\n", strings.Join(compStrs, ", "))
				}
				if removeComps, ok := changes["remove_components"].([]interface{}); ok && len(removeComps) > 0 {
					compStrs := make([]string, len(removeComps))
					for i, c := range removeComps {
						compStrs[i] = fmt.Sprintf("%v", c)
					}
					fmt.Printf("  - Remove: %s\n", strings.Join(compStrs, ", "))
				}
				if addComps, ok := changes["add_components"].([]interface{}); ok && len(addComps) == 0 {
					if removeComps, ok := changes["remove_components"].([]interface{}); ok && len(removeComps) == 0 {
						fmt.Printf("  (no changes)\n")
					}
				}
			}
		} else {
			fmt.Printf("%s\n", resp["msg"])
		}
	},
}

var kdcServiceTxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all transactions",
	Long:  `Lists all service modification transactions. Use --state to filter by state (open, committed, rolled_back).`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		stateFilter, _ := cmd.Flags().GetString("state")

		req := map[string]interface{}{
			"command": "list",
		}
		if stateFilter != "" {
			req["state_filter"] = stateFilter
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if transactionsRaw, ok := resp["transactions"]; ok {
			if transactions, ok := transactionsRaw.([]interface{}); ok {
				if len(transactions) == 0 {
					fmt.Printf("No transactions found\n")
					return
				}
				
				// Build table rows for columnize
				var rows []string
				rows = append(rows, "Transaction ID | Service | State | Created | Expires")
				
				for _, txRaw := range transactions {
					if tx, ok := txRaw.(map[string]interface{}); ok {
						txID := getString(tx, "id")
						serviceID := getString(tx, "service_id")
						state := getString(tx, "state")
						createdAt := getString(tx, "created_at")
						expiresAt := getString(tx, "expires_at")
						
						// Parse and format dates
						if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
							createdAt = t.Format("2006-01-02 15:04:05")
						}
						if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
							expiresAt = t.Format("2006-01-02 15:04:05")
						}
						
						rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s", txID, serviceID, state, createdAt, expiresAt))
					}
				}
				
				if len(rows) > 1 {
					fmt.Println(columnize.SimpleFormat(rows))
				}
			}
		} else {
			fmt.Printf("%s\n", resp["msg"])
		}
	},
}

var kdcServiceTxCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Cleanup expired transactions",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "cleanup",
		}

		resp, err := sendKdcRequest(api, "/kdc/service-transaction", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcServiceTxComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage components in a transaction",
}

func init() {
	KdcServiceCmd.AddCommand(kdcServiceAddCmd, kdcServiceListCmd, kdcServiceDeleteCmd, kdcServiceComponentsCmd, KdcServiceComponentCmd, KdcServiceTransactionCmd)
	KdcServiceComponentCmd.AddCommand(kdcServiceComponentAddCmd, kdcServiceComponentDeleteCmd, kdcServiceComponentReplaceCmd)
	KdcServiceTransactionCmd.AddCommand(kdcServiceTxStartCmd, kdcServiceTxViewCmd, kdcServiceTxCommitCmd, kdcServiceTxRollbackCmd, kdcServiceTxStatusCmd, kdcServiceTxListCmd, kdcServiceTxCleanupCmd, kdcServiceTxComponentCmd)
	kdcServiceTxComponentCmd.AddCommand(kdcServiceTxComponentAddCmd, kdcServiceTxComponentDeleteCmd)
	
	// Service command flags
	kdcServiceAddCmd.Flags().String("sid", "", "Service ID")
	kdcServiceAddCmd.Flags().StringP("name", "n", "", "Service name")
	kdcServiceAddCmd.Flags().String("comment", "", "Comment")
	kdcServiceAddCmd.MarkFlagRequired("name")
	kdcServiceAddCmd.MarkFlagRequired("sid")
	kdcServiceDeleteCmd.Flags().String("sid", "", "Service ID")
	kdcServiceDeleteCmd.MarkFlagRequired("sid")
	kdcServiceComponentsCmd.Flags().StringP("name", "n", "", "Service name")
	kdcServiceComponentsCmd.MarkFlagRequired("name")
	
	// Service-component command flags
	kdcServiceComponentAddCmd.Flags().StringP("sname", "s", "", "Service name")
	kdcServiceComponentAddCmd.Flags().StringP("cname", "c", "", "Component name")
	kdcServiceComponentAddCmd.MarkFlagRequired("sname")
	kdcServiceComponentAddCmd.MarkFlagRequired("cname")
	kdcServiceComponentDeleteCmd.Flags().StringP("sname", "s", "", "Service name")
	kdcServiceComponentDeleteCmd.Flags().StringP("cname", "c", "", "Component name")
	kdcServiceComponentDeleteCmd.MarkFlagRequired("sname")
	kdcServiceComponentDeleteCmd.MarkFlagRequired("cname")
	
	kdcServiceComponentReplaceCmd.Flags().StringP("sname", "s", "", "Service name")
	kdcServiceComponentReplaceCmd.Flags().String("old", "", "Old component ID or name")
	kdcServiceComponentReplaceCmd.Flags().String("new", "", "New component ID or name")
	kdcServiceComponentReplaceCmd.MarkFlagRequired("sname")
	kdcServiceComponentReplaceCmd.MarkFlagRequired("old")
	kdcServiceComponentReplaceCmd.MarkFlagRequired("new")
	
	// Service transaction command flags
	kdcServiceTxStartCmd.Flags().String("sid", "", "Service ID")
	kdcServiceTxStartCmd.Flags().String("created-by", "", "User/process that created the transaction")
	kdcServiceTxStartCmd.Flags().String("comment", "", "Optional comment/description")
	kdcServiceTxStartCmd.MarkFlagRequired("sid")
	
	kdcServiceTxComponentAddCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxComponentAddCmd.Flags().String("cid", "", "Component ID")
	kdcServiceTxComponentAddCmd.MarkFlagRequired("tx")
	kdcServiceTxComponentAddCmd.MarkFlagRequired("cid")
	
	kdcServiceTxComponentDeleteCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxComponentDeleteCmd.Flags().String("cid", "", "Component ID")
	kdcServiceTxComponentDeleteCmd.MarkFlagRequired("tx")
	kdcServiceTxComponentDeleteCmd.MarkFlagRequired("cid")
	
	kdcServiceTxViewCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxViewCmd.MarkFlagRequired("tx")
	
	kdcServiceTxCommitCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxCommitCmd.Flags().Bool("dry-run", false, "Preview changes without applying them")
	kdcServiceTxCommitCmd.MarkFlagRequired("tx")
	
	kdcServiceTxRollbackCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxRollbackCmd.MarkFlagRequired("tx")
	
	kdcServiceTxStatusCmd.Flags().String("tx", "", "Transaction ID")
	kdcServiceTxStatusCmd.MarkFlagRequired("tx")
	
	kdcServiceTxListCmd.Flags().String("state", "", "Filter by state (open, committed, rolled_back)")
}
