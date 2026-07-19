// Package config loads the exporter's YAML config file, which defines named
// modules.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Module defines one named probe configuration.
type Module struct {
	KnownHostsFile    string   `yaml:"known_hosts_file,omitempty"`
	TargetPort        int      `yaml:"target_port,omitempty"`
	Ciphers           []string `yaml:"ciphers,omitempty"`
	HostKeyAlgorithms []string `yaml:"host_key_algorithms,omitempty"`
}

// Config is the top-level YAML structure.
type Config struct {
	KnownHostsFile string            `yaml:"known_hosts_file,omitempty"`
	TargetPort     int               `yaml:"target_port,omitempty"`
	Modules        map[string]Module `yaml:"modules"`
}

// Load reads, resolves defaults, and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if len(cfg.Modules) == 0 {
		return nil, fmt.Errorf("config file defines no modules")
	}
	for name, mod := range cfg.Modules {
		if mod.KnownHostsFile == "" {
			mod.KnownHostsFile = cfg.KnownHostsFile
		}
		if mod.KnownHostsFile == "" {
			return nil, fmt.Errorf("module %q: known_hosts_file is required (no top-level known_hosts_file set either)", name)
		}
		if mod.TargetPort == 0 {
			mod.TargetPort = cfg.TargetPort
		}
		if mod.TargetPort == 0 {
			mod.TargetPort = 22
		}
		cfg.Modules[name] = mod
	}

	return &cfg, nil
}
