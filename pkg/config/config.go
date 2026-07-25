// Package config loads the exporter's YAML configuration and compiles it into
// ready-to-probe Modules, including building host key callbacks.
package config

import (
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultModuleName is the module used when a config file defines none,
// and the module selected when a /probe request omits the module parameter.
const DefaultModuleName = "default"

// rawConfigModule defines one named probe configuration as written in YAML.
type rawConfigModule struct {
	KnownHosts        string   `yaml:"known_hosts,omitempty"`
	KnownHostsFile    string   `yaml:"known_hosts_file,omitempty"`
	TargetPort        int      `yaml:"target_port,omitempty"`
	Ciphers           []string `yaml:"ciphers,omitempty"`
	HostKeyAlgorithms []string `yaml:"host_key_algorithms,omitempty"`
}

// rawConfig is the top-level YAML structure.
type rawConfig struct {
	KnownHosts     string                     `yaml:"known_hosts,omitempty"`
	KnownHostsFile string                     `yaml:"known_hosts_file,omitempty"`
	TargetPort     int                        `yaml:"target_port,omitempty"`
	Modules        map[string]rawConfigModule `yaml:"modules,omitempty"`
}

// loadRawConfig reads, resolves defaults/inheritance, and validates the
// config file at path. It is pure aside from reading the file itself: it
// performs no known_hosts I/O and builds no callbacks.
func loadRawConfig(path string, logger *slog.Logger) (*rawConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg rawConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if len(cfg.Modules) == 0 {
		cfg.Modules = map[string]rawConfigModule{DefaultModuleName: {}}
	}

	for name, mod := range cfg.Modules {
		// known_hosts resolution, most to least specific:
		//   1. module known_hosts (inline)
		//   2. module known_hosts_file
		//   3. default known_hosts (inline)
		//   4. default known_hosts_file
		switch {
		case mod.KnownHosts != "":
			if mod.KnownHostsFile != "" {
				logger.Warn("module sets both known_hosts and known_hosts_file; known_hosts (inline) takes precedence and known_hosts_file is ignored", "module", name, "known_hosts_file", mod.KnownHostsFile)
			}
			mod.KnownHostsFile = ""
		case mod.KnownHostsFile != "":
			// Module explicitly set a file, claim this case so we don't fall to the
			// branch below and wrongly override the file.
		case cfg.KnownHosts != "":
			mod.KnownHosts = cfg.KnownHosts
		default:
			mod.KnownHostsFile = cfg.KnownHostsFile
		}
		if mod.KnownHosts == "" && mod.KnownHostsFile == "" {
			return nil, fmt.Errorf("module %q: known_hosts or known_hosts_file is required (neither set at module level nor in defaults)", name)
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
