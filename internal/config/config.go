// Package config loads the exporter's YAML configuration and compiles it into
// ready-to-probe Modules, including building host key callbacks.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"slices"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// DefaultModuleName is the module used when a config file defines none,
// and the module selected when a /probe request omits the module parameter.
const DefaultModuleName = "default"

// Algorithm names x/crypto/ssh implements. Insecure ones are valid to
// configure, so both sets count as known.
var (
	knownCiphers           = algorithmSet(ssh.SupportedAlgorithms().Ciphers, ssh.InsecureAlgorithms().Ciphers)
	knownHostKeyAlgorithms = algorithmSet(ssh.SupportedAlgorithms().HostKeys, ssh.InsecureAlgorithms().HostKeys)
)

func algorithmSet(lists ...[]string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, list := range lists {
		for _, name := range list {
			set[name] = struct{}{}
		}
	}
	return set
}

// validateAlgorithms rejects names x/crypto/ssh does not implement, which it
// would otherwise drop from the advertised list silently. It reports every
// offending name so a config can be fixed in one pass.
func validateAlgorithms(kind string, names []string, known map[string]struct{}) error {
	var unknown []string
	for _, name := range names {
		if _, ok := known[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	return fmt.Errorf("unknown %s %q (not implemented by golang.org/x/crypto/ssh)", kind, unknown)
}

// rawConfigModule defines one named probe configuration as written in YAML.
type rawConfigModule struct {
	KnownHosts        string   `yaml:"known_hosts,omitempty"`
	KnownHostsFile    string   `yaml:"known_hosts_file,omitempty"`
	AllowedTargets    []string `yaml:"allowed_targets,omitempty"`
	AllowedPorts      []int    `yaml:"allowed_ports,omitempty"`
	TargetPort        int      `yaml:"target_port,omitempty"`
	Ciphers           []string `yaml:"ciphers,omitempty"`
	HostKeyAlgorithms []string `yaml:"host_key_algorithms,omitempty"`
}

// rawConfig is the top-level YAML structure.
type rawConfig struct {
	KnownHosts     string                     `yaml:"known_hosts,omitempty"`
	KnownHostsFile string                     `yaml:"known_hosts_file,omitempty"`
	AllowedTargets []string                   `yaml:"allowed_targets,omitempty"`
	AllowedPorts   []int                      `yaml:"allowed_ports,omitempty"`
	TargetPort     int                        `yaml:"target_port,omitempty"`
	Modules        map[string]rawConfigModule `yaml:"modules,omitempty"`

	// allowAll is set (never from YAML) when --allow-all-targets is passed and
	// no top-level allowed_targets default is configured. It makes modules that
	// inherit the empty default permit any target.
	allowAllTargets bool
}

// loadRawConfig reads, resolves defaults/inheritance, and validates the
// config file at path. It is pure aside from reading the file itself: it
// performs no known_hosts I/O and builds no callbacks.
func loadRawConfig(path string, allowAllTargetsFlag bool, logger *slog.Logger) (*rawConfig, error) {
	//nolint:gosec // G304: reading the operator-supplied config path is the point.
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

	// Enable allow-all only when the flag is set and the operator configured no
	// top-level default. An explicit top-level list always wins, so the flag is
	// inert whenever one is present.
	cfg.allowAllTargets = allowAllTargetsFlag && len(cfg.AllowedTargets) == 0

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

		// allowed_targets: inherit default when the module sets none (nil and
		// empty are treated identically).
		if len(mod.AllowedTargets) == 0 {
			mod.AllowedTargets = cfg.AllowedTargets
		}

		if mod.TargetPort == 0 {
			mod.TargetPort = cfg.TargetPort
		}
		if mod.TargetPort == 0 {
			mod.TargetPort = 22
		}

		// allowed_ports resolution: module, else default, else [target_port].
		if mod.AllowedPorts == nil {
			mod.AllowedPorts = cfg.AllowedPorts
		}
		if len(mod.AllowedPorts) == 0 {
			mod.AllowedPorts = []int{mod.TargetPort}
		}
		for _, p := range mod.AllowedPorts {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("module %q: allowed_ports contains invalid port %d (must be 1-65535)", name, p)
			}
		}
		if !slices.Contains(mod.AllowedPorts, mod.TargetPort) {
			return nil, fmt.Errorf("module %q: target_port %d is not in allowed_ports %v", name, mod.TargetPort, mod.AllowedPorts)
		}

		if err := validateAlgorithms("ciphers", mod.Ciphers, knownCiphers); err != nil {
			return nil, fmt.Errorf("module %q: %w", name, err)
		}
		if err := validateAlgorithms("host key algorithms", mod.HostKeyAlgorithms, knownHostKeyAlgorithms); err != nil {
			return nil, fmt.Errorf("module %q: %w", name, err)
		}

		cfg.Modules[name] = mod
	}

	return &cfg, nil
}
