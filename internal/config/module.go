package config

import (
	"fmt"
	"log/slog"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/probe"
)

// Module is a ready-to-probe configuration. Its known_hosts is parsed into a
// callback, so per-probe requests never touch the filesystem.
type Module struct {
	Options        probe.Options
	AllowedTargets []TargetMatcher
	AllowedPorts   map[int]struct{}
	TargetPort     int
}

// Load reads, resolves, and validates the config file at path, then builds
// all runtime resources (host key callbacks), returning ready-to-probe
// modules keyed by name. It is the single entry point for both initial
// startup and SIGHUP reload.
func Load(configFilePath string, allowAllTargets bool, logger *slog.Logger) (map[string]Module, error) {
	raw, err := loadRawConfig(configFilePath, allowAllTargets)
	if err != nil {
		return nil, fmt.Errorf("loading config file: %w", err)
	}
	return build(raw, logger)
}

// build turns a resolved rawConfig into ready-to-probe modules. This is the
// effectful step: it materializes known_hosts into ssh.HostKeyCallbacks.
func build(raw *rawConfig, logger *slog.Logger) (map[string]Module, error) {
	modules := make(map[string]Module, len(raw.Modules))
	for name, mod := range raw.Modules {
		hostKeyCallback, err := knownhosts.New(mod.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("module %q: loading known_hosts: %w", name, err)
		}

		allowedTargets, err := resolveAllowedTargets(mod.AllowedTargets, raw.allowAllTargets)
		if err != nil {
			return nil, fmt.Errorf("module %q: %w", name, err)
		}

		allowedPorts := make(map[int]struct{}, len(mod.AllowedPorts))
		for _, p := range mod.AllowedPorts {
			allowedPorts[p] = struct{}{}
		}

		modules[name] = Module{
			Options: probe.Options{
				HostKeyCallback:   hostKeyCallback,
				Ciphers:           mod.Ciphers,
				KeyExchanges:      mod.KeyExchanges,
				MACs:              mod.MACs,
				HostKeyAlgorithms: mod.HostKeyAlgorithms,

				StripServerVersionComment: mod.StripServerVersionComment,
				Logger:                    logger,
			},
			AllowedTargets: allowedTargets,
			AllowedPorts:   allowedPorts,
			TargetPort:     mod.TargetPort,
		}
		logger.Info("loaded module",
			"module", name,
			"known_hosts_file", mod.KnownHostsFile,
			"allowed_targets", mod.AllowedTargets,
			"allowed_ports", mod.AllowedPorts,
			"target_port", mod.TargetPort,
			"ciphers", mod.Ciphers,
			"kex_algorithms", mod.KeyExchanges,
			"macs", mod.MACs,
			"host_key_algorithms", mod.HostKeyAlgorithms,
			"strip_server_version_comment", mod.StripServerVersionComment,
		)
	}
	return modules, nil
}
