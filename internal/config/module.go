package config

import (
	"fmt"
	"log/slog"

	"github.com/raphaelthomas/ssh_transport_exporter/internal/knownhosts"
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

// Load reads and validates the config file and builds ready-to-probe modules,
// for both startup and SIGHUP reload.
func Load(configFilePath string, allowAllTargets bool, logger *slog.Logger) (map[string]Module, error) {
	raw, err := loadRawConfig(configFilePath, allowAllTargets)
	if err != nil {
		return nil, fmt.Errorf("loading config file: %w", err)
	}
	return build(raw, logger)
}

func build(raw *rawConfig, logger *slog.Logger) (map[string]Module, error) {
	modules := make(map[string]Module, len(raw.Modules))
	for name, mod := range raw.Modules {
		hostKeyCallback, err := knownhosts.New(mod.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("module %q: loading known_hosts: %w", name, err)
		}
		isCertAuthority, err := knownhosts.CertAuthorities(mod.KnownHostsFile)
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

		p := mod.profile
		modules[name] = Module{
			Options: probe.Options{
				HostKeyCallback:                   hostKeyCallback,
				IsCertAuthority:                   isCertAuthority,
				Ciphers:                           p.ciphers,
				KeyExchanges:                      p.keyExchanges,
				MACs:                              p.macs,
				HostKeyAlgorithms:                 p.hostKeyAlgorithms,
				HostKeyAlgorithmsFixedOrder:       !p.orderByKnownHosts,
				CASignatureAlgorithms:             p.caSignatureAlgorithms,
				HostCertificateNoFallback:         !p.plainKeyFallback,
				HostCertificateExactPrincipals:    !p.wildcardPrincipals,
				HostCertificatePrincipalsOptional: !p.requirePrincipals,
				CertAuthorityLinesMatchPlainKeys:  p.caLinesMatchPlainKeys,

				StripServerIdentificationComments: mod.StripServerIdentificationComments,
				Logger:                            logger,
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
			"profile", p.name,
			"ciphers", p.ciphers,
			"kex_algorithms", p.keyExchanges,
			"macs", p.macs,
			"host_key_algorithms", p.hostKeyAlgorithms,
			"host_key_algorithms_order_by_known_hosts", p.orderByKnownHosts,
			"ca_signature_algorithms", p.caSignatureAlgorithms,
			"host_certificate_allow_plain_key_fallback", p.plainKeyFallback,
			"host_certificate_allow_wildcard_principals", p.wildcardPrincipals,
			"host_certificate_require_principals", p.requirePrincipals,
			"cert_authority_lines_match_plain_keys", p.caLinesMatchPlainKeys,
			"strip_server_identification_comments", mod.StripServerIdentificationComments,
		)
	}
	return modules, nil
}
