package app

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ClientInterface   string      `json:"client_interface"`
	UpstreamInterface string      `json:"upstream_interface"`
	TriggerDomain     string      `json:"trigger_domain"`
	TriggerIPv4       string      `json:"trigger_ipv4"`
	TracerouteBase    uint16      `json:"traceroute_base_port"`
	TracerouteSpan    uint16      `json:"traceroute_port_span"`
	DNSTTLSeconds     uint32      `json:"dns_ttl"`
	Lyrics            []HopConfig `json:"lyrics"`
}

type HopConfig struct {
	Name string `json:"name"`
	IPv4 string `json:"ipv4"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if cfg.TracerouteBase == 0 {
		cfg.TracerouteBase = 33434
	}
	if cfg.TracerouteSpan == 0 {
		cfg.TracerouteSpan = 128
	}
	if cfg.DNSTTLSeconds == 0 {
		cfg.DNSTTLSeconds = 120
	}

	if err := cfg.validate(path); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) validate(origin string) error {
	var errs []string
	if c.ClientInterface == "" {
		errs = append(errs, "client_interface must be set")
	}
	if c.UpstreamInterface == "" {
		errs = append(errs, "upstream_interface must be set")
	}
	if c.TriggerDomain == "" {
		errs = append(errs, "trigger_domain must be set")
	}
	if c.TriggerIPv4 == "" {
		errs = append(errs, "trigger_ipv4 must be set")
	}
	if len(c.Lyrics) == 0 {
		errs = append(errs, "at least one hop must be provided in lyrics")
	}
	for _, hop := range c.Lyrics {
		if hop.Name == "" || hop.IPv4 == "" {
			errs = append(errs, "every hop must have non-empty name and ipv4")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config %s: %s", filepath.Base(origin), strings.Join(errs, "; "))
	}

	if _, err := netip.ParseAddr(c.TriggerIPv4); err != nil {
		return fmt.Errorf("invalid trigger IPv4: %w", err)
	}
	for _, hop := range c.Lyrics {
		if _, err := netip.ParseAddr(hop.IPv4); err != nil {
			return fmt.Errorf("invalid hop IPv4 %q: %w", hop.Name, err)
		}
	}

	return nil
}
