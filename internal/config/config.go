// Package config loads the exporter's YAML configuration and compiles it into
// ready-to-probe Modules, including building host key callbacks.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	knownKeyExchanges      = algorithmSet(ssh.SupportedAlgorithms().KeyExchanges, ssh.InsecureAlgorithms().KeyExchanges)
	knownMACs              = algorithmSet(ssh.SupportedAlgorithms().MACs, ssh.InsecureAlgorithms().MACs)
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

type rawConfigModule struct {
	KnownHostsFile    string   `yaml:"known_hosts_file,omitempty"`
	AllowedTargets    []string `yaml:"allowed_targets,omitempty"`
	AllowedPorts      []int    `yaml:"allowed_ports,omitempty"`
	TargetPort        int      `yaml:"target_port,omitempty"`
	Ciphers           []string `yaml:"ciphers,omitempty"`
	KeyExchanges      []string `yaml:"kex_algorithms,omitempty"`
	MACs              []string `yaml:"macs,omitempty"`
	HostKeyAlgorithms []string `yaml:"host_key_algorithms,omitempty"`

	StripServerVersionComment bool `yaml:"strip_server_version_comment,omitempty"`
}

type rawConfig struct {
	KnownHostsFile string                     `yaml:"known_hosts_file,omitempty"`
	AllowedTargets []string                   `yaml:"allowed_targets,omitempty"`
	AllowedPorts   []int                      `yaml:"allowed_ports,omitempty"`
	TargetPort     int                        `yaml:"target_port,omitempty"`
	Modules        map[string]rawConfigModule `yaml:"modules,omitempty"`

	// StripServerVersionComment enables stripping for every module. Modules can
	// enable it individually but cannot switch it back off once set here.
	StripServerVersionComment bool `yaml:"strip_server_version_comment,omitempty"`

	allowAllTargets bool
}

// loadRawConfig does no I/O beyond reading path; build reads known_hosts, so
// configs can be validated without the files present.
func loadRawConfig(path string, allowAllTargetsFlag bool) (*rawConfig, error) {
	//nolint:gosec // G304: reading the operator-supplied config path is the point.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Unknown keys are rejected so typos fail loudly; an empty file decodes to
	// io.EOF, i.e. an empty config.
	var cfg rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if len(cfg.Modules) == 0 {
		cfg.Modules = map[string]rawConfigModule{DefaultModuleName: {}}
	}

	// An explicit top-level allowed_targets always wins over --allow-all-targets.
	cfg.allowAllTargets = allowAllTargetsFlag && len(cfg.AllowedTargets) == 0

	for name, mod := range cfg.Modules {
		if mod.KnownHostsFile == "" {
			mod.KnownHostsFile = cfg.KnownHostsFile
		}
		if mod.KnownHostsFile == "" {
			return nil, fmt.Errorf("module %q: known_hosts_file is required (not set at module level or in defaults)", name)
		}

		if len(mod.AllowedTargets) == 0 {
			mod.AllowedTargets = cfg.AllowedTargets
		}

		mod.StripServerVersionComment = mod.StripServerVersionComment || cfg.StripServerVersionComment

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
		if err := validateAlgorithms("kex algorithms", mod.KeyExchanges, knownKeyExchanges); err != nil {
			return nil, fmt.Errorf("module %q: %w", name, err)
		}
		if err := validateAlgorithms("macs", mod.MACs, knownMACs); err != nil {
			return nil, fmt.Errorf("module %q: %w", name, err)
		}
		if err := validateAlgorithms("host key algorithms", mod.HostKeyAlgorithms, knownHostKeyAlgorithms); err != nil {
			return nil, fmt.Errorf("module %q: %w", name, err)
		}

		cfg.Modules[name] = mod
	}

	return &cfg, nil
}
