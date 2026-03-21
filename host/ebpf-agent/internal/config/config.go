package config

import (
	"fmt"
	"os"
	"time"

	"go.yaml.in/yaml/v2"
)

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type BasicAuthConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ServerConfig struct {
	Port        int             `yaml:"port"`
	MetricsPath string          `yaml:"metrics_path"`
	TLS         TLSConfig       `yaml:"tls"`
	BasicAuth   BasicAuthConfig `yaml:"basic_auth"`
}

type TracepointConfig struct {
	Group   string `yaml:"group"`
	Name    string `yaml:"name"`
	Program string `yaml:"program"`
}

type MetricConfig struct {
	Name   string `yaml:"name"`
	Help   string `yaml:"help"`
	BPFMap string `yaml:"bpf_map"`
}

type Config struct {
	Server       ServerConfig       `yaml:"server"`
	PollInterval time.Duration      `yaml:"poll_interval"`
	BPFObject    string             `yaml:"bpf_object"`
	Tracepoints  []TracepointConfig `yaml:"tracepoints"`
	Metrics      []MetricConfig     `yaml:"metrics"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{
		Server: ServerConfig{
			Port:        9110,
			MetricsPath: "/metrics",
		},
		PollInterval: time.Second,
		BPFObject:    "bpf/exec.bpf.o",
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", cfg.Server.Port)
	}

	if len(cfg.Metrics) == 0 {
		return nil, fmt.Errorf("no metrics defined in config")
	}

	if len(cfg.Tracepoints) == 0 {
		return nil, fmt.Errorf("no tracepoints defined in config")
	}

	return cfg, nil
}
