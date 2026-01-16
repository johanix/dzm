/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API endpoints for tdns-krs management
 */

package krs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	tnm "github.com/johanix/tdns-nm/tnm"
)

// KrsKeysPost represents a request to the KRS keys API
type KrsKeysPost struct {
	Command string `json:"command"` // "list", "get", "get-by-zone", "hash", "purge", "delete"
	KeyID   string `json:"key_id,omitempty"`
	ZoneID  string `json:"zone_id,omitempty"`
	ZoneName string `json:"zone_name,omitempty"` // For purge and delete commands
}

// KrsKeysResponse represents a response from the KRS keys API
type KrsKeysResponse struct {
	Time     time.Time      `json:"time"`
	Error    bool           `json:"error,omitempty"`
	ErrorMsg string         `json:"error_msg,omitempty"`
	Key      *ReceivedKey   `json:"key,omitempty"`
	Keys     []*ReceivedKey `json:"keys,omitempty"`
	Msg      string         `json:"msg,omitempty"` // For hash command
}

// KrsConfigPost represents a request to the KRS config API
type KrsConfigPost struct {
	Command string `json:"command"` // "get"
}

// KrsConfigResponse represents a response from the KRS config API
type KrsConfigResponse struct {
	Time     time.Time              `json:"time"`
	Error    bool                   `json:"error,omitempty"`
	ErrorMsg string                 `json:"error_msg,omitempty"`
	Config   map[string]interface{} `json:"config,omitempty"`
}

// KrsQueryPost represents a request to the KRS query API
type KrsQueryPost struct {
	Command       string `json:"command"`        // "query-kmreq"
	DistributionID string `json:"distribution_id,omitempty"`
	ZoneID        string `json:"zone_id,omitempty"`
}

// KrsQueryResponse represents a response from the KRS query API
type KrsQueryResponse struct {
	Time     time.Time `json:"time"`
	Error    bool      `json:"error,omitempty"`
	ErrorMsg string    `json:"error_msg,omitempty"`
	Msg      string    `json:"msg,omitempty"`
}

// KrsDebugPost represents a request to the KRS debug API
type KrsDebugPost struct {
	Command       string `json:"command"`        // "fetch-distribution"
	DistributionID string `json:"distribution_id,omitempty"`
}

// KrsDebugResponse represents a response from the KRS debug API
type KrsDebugResponse struct {
	Time     time.Time `json:"time"`
	Error    bool      `json:"error,omitempty"`
	ErrorMsg string    `json:"error_msg,omitempty"`
	Msg      string    `json:"msg,omitempty"`
	Content  string    `json:"content,omitempty"` // For clear_text or encrypted_text content
}

// KrsComponentsPost represents a request to the KRS components API
type KrsComponentsPost struct {
	Command string `json:"command"` // "list"
}

// KrsComponentsResponse represents a response from the KRS components API
type KrsComponentsResponse struct {
	Time       time.Time `json:"time"`
	Error      bool      `json:"error,omitempty"`
	ErrorMsg   string    `json:"error_msg,omitempty"`
	Components []string  `json:"components"` // Always include, even if empty
}

// sendJSONError sends a JSON-formatted error response
func sendJSONError(w http.ResponseWriter, statusCode int, errorMsg string) {
	resp := map[string]interface{}{
		"time":      time.Now(),
		"error":     true,
		"error_msg": errorMsg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

// SetupKrsAPIRoutes sets up API routes for KRS management
// tdnsConf is *tdns.Config passed as interface{} to avoid circular import
// pingHandler is the ping endpoint handler function
func SetupKrsAPIRoutes(router *mux.Router, krsDB *KrsDB, conf *tnm.KrsConf, tdnsConf interface{}, pingHandler http.HandlerFunc) {
	// Extract API key from config
	apikey := ""
	if configMap, ok := tdnsConf.(map[string]interface{}); ok {
		if apiServer, ok := configMap["ApiServer"].(map[string]interface{}); ok {
			if key, ok := apiServer["ApiKey"].(string); ok {
				apikey = key
			}
		}
	}
	
	// Create subrouter for KRS routes under /api/v1/krs
	// The router passed in already has /api/v1 routes set up via SetupAPIRouter.
	// We create a subrouter for /api/v1/krs/* with the same API key header requirement.
	var sr *mux.Router
	if apikey != "" {
		// Create subrouter with API key header requirement
		sr = router.PathPrefix("/api/v1/krs").Headers("X-API-Key", apikey).Subrouter()
	} else {
		sr = router.PathPrefix("/api/v1/krs").Subrouter()
	}
	
	// Register KRS routes on the subrouter (paths are relative to the prefix)
	sr.HandleFunc("/keys", APIKrsKeys(krsDB)).Methods("POST")
	sr.HandleFunc("/config", APIKrsConfig(krsDB, conf, tdnsConf)).Methods("POST")
	sr.HandleFunc("/query", APIKrsQuery(krsDB, conf)).Methods("POST")
	sr.HandleFunc("/debug", APIKrsDebug(krsDB, conf)).Methods("POST")
	sr.HandleFunc("/components", APIKrsComponents(krsDB)).Methods("POST")
	
	log.Printf("KRS API routes registered: /api/v1/krs/keys, /api/v1/krs/config, /api/v1/krs/query, /api/v1/krs/debug, /api/v1/krs/components")
}

// APIKrsKeys handles key management endpoints
func APIKrsKeys(krsDB *KrsDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KrsKeysPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KrsKeysResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "list":
			keys, err := krsDB.GetAllReceivedKeys()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Keys = keys
			}

		case "get":
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for get command")
				return
			}
			key, err := krsDB.GetReceivedKey(req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Key = key
			}

		case "get-by-zone":
			if req.ZoneID == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_id is required for get-by-zone command")
				return
			}
			keys, err := krsDB.GetReceivedKeysForZone(req.ZoneID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Keys = keys
			}

		case "hash":
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for hash command")
				return
			}
			key, err := krsDB.GetReceivedKey(req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				hash, err := computeKeyHash(key.PrivateKey)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = hash
				}
			}

		case "purge":
			// Purge keys in "removed" state
			// zone_name is optional - if provided, only purge keys for that zone
			deletedCount, err := krsDB.DeleteKeysByState("removed", req.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				if req.ZoneName != "" {
					resp.Msg = fmt.Sprintf("Deleted %d key(s) in 'removed' state for zone %s", deletedCount, req.ZoneName)
				} else {
					resp.Msg = fmt.Sprintf("Deleted %d key(s) in 'removed' state (all zones)", deletedCount)
				}
			}

		case "delete":
			// Delete a specific key by zone_name and key_id
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for delete command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for delete command")
				return
			}
			err := krsDB.DeleteReceivedKeyByZoneAndKeyID(req.ZoneName, req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Deleted key %s for zone %s", req.KeyID, req.ZoneName)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKrsConfig handles node configuration endpoints
// tdnsConf is *tdns.Config passed as interface{} to avoid circular import
func APIKrsConfig(krsDB *KrsDB, conf *tnm.KrsConf, tdnsConf interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KrsConfigPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KrsConfigResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "get":
			config, err := krsDB.GetNodeConfig()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				// Extract API addresses from tdns config
				apiAddresses := []string{}
				if configMap, ok := tdnsConf.(map[string]interface{}); ok {
					if apiServer, ok := configMap["ApiServer"].(map[string]interface{}); ok {
						if addrs, ok := apiServer["Addresses"].([]string); ok {
							apiAddresses = addrs
						}
					}
				}

				// Don't expose private keys in API response
				configResp := map[string]interface{}{
					"id":            config.ID,
					"kdc_address":   config.KdcAddress,
					"control_zone":   config.ControlZone,
					"registered_at":  config.RegisteredAt,
					"last_seen":      config.LastSeen,
					"dns_addresses":  conf.DnsEngine.Addresses,
					"api_addresses":  apiAddresses,
				}
				resp.Config = configResp
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKrsQuery handles query endpoints (deprecated - kept for compatibility)
func APIKrsQuery(krsDB *KrsDB, conf *tnm.KrsConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KrsQueryPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KrsQueryResponse{
			Time: time.Now(),
		}

		// All query commands are obsolete (KMREQ/KMCTRL are no longer used)
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("Query command '%s' is obsolete - keys are now distributed via NOTIFY + CHUNK", req.Command)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// computeKeyHash computes a SHA-256 hash of the private key material
// Returns hex-encoded hash string
func computeKeyHash(privateKey []byte) (string, error) {
	if len(privateKey) == 0 {
		return "", fmt.Errorf("private key is empty")
	}
	hash := sha256.Sum256(privateKey)
	return hex.EncodeToString(hash[:]), nil
}

// APIKrsDebug handles debug endpoints
func APIKrsDebug(krsDB *KrsDB, conf *tnm.KrsConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KrsDebugPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KrsDebugResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "fetch-distribution":
			if req.DistributionID == "" {
				sendJSONError(w, http.StatusBadRequest, "distribution_id is required for fetch-distribution command")
				return
			}

			// Process the distribution (this will fetch manifest, chunks, reassemble, and process)
			// Pass a pointer to store clear_text or encrypted_text content if present
			var textContent string
			err := ProcessDistribution(krsDB, conf, req.DistributionID, &textContent)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Successfully fetched and processed distribution %s", req.DistributionID)
				if textContent != "" {
					resp.Content = textContent
				}
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKrsComponents handles component management endpoints
func APIKrsComponents(krsDB *KrsDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KrsComponentsPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		log.Printf("APIKrsComponents: /components request: %+v", req)

		resp := KrsComponentsResponse{
			Time:       time.Now(),
			Components: []string{}, // Initialize as empty slice so it's always present in JSON
		}

		switch req.Command {
		case "list":
			components, err := krsDB.GetNodeComponents()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				// Ensure components is never nil (use empty slice if nil)
				if components == nil {
					components = []string{}
				}
				resp.Components = components
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
