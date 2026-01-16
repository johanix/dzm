/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Configuration parsing for tdns-kdc and tdns-krs
 */

package tnm

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	tdns "github.com/johanix/tdns/v2"
	"gopkg.in/yaml.v3"
)

// ParseKdcConfigFromFile reads the config file and extracts the KDC configuration section,
// storing it as YAML bytes in conf.Internal.KdcConf
func ParseKdcConfigFromFile(conf *tdns.Config) error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		return fmt.Errorf("no config file specified")
	}

	// Read the config file
	if tdns.Globals.Debug {
		log.Printf("ParseKdcConfigFromFile: Reading %q", cfgfile)
	}
	data, err := os.ReadFile(cfgfile)
	if err != nil {
		return fmt.Errorf("error reading config file %s: %v", cfgfile, err)
	}

	// Parse YAML into a map
	var configMap map[string]interface{}
	if err := yaml.Unmarshal(data, &configMap); err != nil {
		return fmt.Errorf("error parsing YAML: %v", err)
	}

	// Handle includes if present (similar to tdns processConfigFile)
	configMap, err = processIncludes(configMap, filepath.Dir(cfgfile), 0)
	if err != nil {
		return fmt.Errorf("error processing includes: %v", err)
	}

	// Extract the kdc section
	kdcSection, ok := configMap["kdc"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("KDC configuration section 'kdc' not found or invalid")
	}

	// Marshal the kdc section to YAML bytes
	// We'll unmarshal it into tnm.KdcConf in startKdc() to avoid circular import
	kdcYAML, err := yaml.Marshal(kdcSection)
	if err != nil {
		return fmt.Errorf("failed to marshal KDC config: %v", err)
	}

	// Store YAML bytes - will be unmarshaled in startKdc()
	conf.Internal.KdcConf = kdcYAML

	if tdns.Globals.Debug {
		log.Printf("KDC config section found and stored (will be unmarshaled in startKdc)")
	}

	return nil
}

// ParseKrsConfigFromFile reads the config file and extracts the KRS configuration section,
// storing it as YAML bytes in conf.Internal.KrsConf
// Note: dnsengine config is at top level (like KDC), but we merge it into krs section
func ParseKrsConfigFromFile(conf *tdns.Config) error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		return fmt.Errorf("no config file specified")
	}

	// Read the config file
	if tdns.Globals.Debug {
		log.Printf("ParseKrsConfigFromFile: Reading %q", cfgfile)
	}
	data, err := os.ReadFile(cfgfile)
	if err != nil {
		return fmt.Errorf("error reading config file %s: %v", cfgfile, err)
	}

	// Parse YAML into a map
	var configMap map[string]interface{}
	if err := yaml.Unmarshal(data, &configMap); err != nil {
		return fmt.Errorf("error parsing YAML: %v", err)
	}

	// Handle includes if present (similar to tdns processConfigFile)
	configMap, err = processIncludes(configMap, filepath.Dir(cfgfile), 0)
	if err != nil {
		return fmt.Errorf("error processing includes: %v", err)
	}

	// Extract the krs section
	krsSection, ok := configMap["krs"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("KRS configuration section 'krs' not found or invalid")
	}

	// Extract dnsengine from top level and merge into krs section
	if dnsEngineSection, ok := configMap["dnsengine"].(map[string]interface{}); ok {
		krsSection["dnsengine"] = dnsEngineSection
	}

	// Marshal the krs section (now including dnsengine) to YAML bytes
	// We'll unmarshal it into tnm.KrsConf in startKrs() to avoid circular import
	krsYAML, err := yaml.Marshal(krsSection)
	if err != nil {
		return fmt.Errorf("failed to marshal KRS config: %v", err)
	}

	// Store YAML bytes - will be unmarshaled in startKrs()
	conf.Internal.KrsConf = krsYAML

	if tdns.Globals.Debug {
		log.Printf("KRS config section found and stored (will be unmarshaled in startKrs)")
	}

	return nil
}

// processIncludes handles include directives in the config file
func processIncludes(config map[string]interface{}, baseDir string, depth int) (map[string]interface{}, error) {
	if depth > 10 {
		return nil, fmt.Errorf("maximum include depth exceeded (10 levels)")
	}

	// Handle includes if present
	if includes, ok := config["include"].([]interface{}); ok {
		delete(config, "include")
		for _, inc := range includes {
			if includeFile, ok := inc.(string); ok {
				var fullPath string
				if filepath.IsAbs(includeFile) {
					fullPath = includeFile
				} else {
					fullPath = filepath.Join(baseDir, includeFile)
				}
				fullPath = filepath.Clean(fullPath)

				// Read included file
				data, err := os.ReadFile(fullPath)
				if err != nil {
					return nil, fmt.Errorf("error reading included file %s: %v", fullPath, err)
				}

				// Parse included YAML
				var included map[string]interface{}
				if err := yaml.Unmarshal(data, &included); err != nil {
					return nil, fmt.Errorf("error parsing included file %s: %v", fullPath, err)
				}

				// Recursively process includes in the included file
				included, err = processIncludes(included, filepath.Dir(fullPath), depth+1)
				if err != nil {
					return nil, err
				}

				// Merge included config
				for k, v := range included {
					if existing, exists := config[k]; exists {
						// If both are maps, merge them
						if existingMap, ok1 := existing.(map[string]interface{}); ok1 {
							if newMap, ok2 := v.(map[string]interface{}); ok2 {
								for k2, v2 := range newMap {
									existingMap[k2] = v2
								}
								continue
							}
						}
					}
					// Otherwise just override
					config[k] = v
				}
			}
		}
	}

	return config, nil
}
