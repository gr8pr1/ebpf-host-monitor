package config

import (
	"fmt"
	"os"
	"strings"
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

type BaselineConfig struct {
	LearningDuration      time.Duration `yaml:"learning_duration"`
	AggregationWindow     time.Duration `yaml:"aggregation_window"`
	RecalibrationInterval time.Duration `yaml:"recalibration_interval"`
	EWMAAlpha             float64       `yaml:"ewma_alpha"`
	MinStdDev             float64       `yaml:"min_stddev"`
	StateFile             string        `yaml:"state_file"`
}

type ScoringConfig struct {
	ZScoreThreshold      float64 `yaml:"zscore_threshold"`
	QuantileThreshold    float64 `yaml:"quantile_threshold"`
	MinimumSamples       int     `yaml:"minimum_samples"`
	ColdStartSeverity    string  `yaml:"cold_start_severity"`
}

type HostConfig struct {
	ID     string            `yaml:"id"`
	Labels map[string]string `yaml:"labels"`
}

type ContainerConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CgroupRoot string `yaml:"cgroup_root"`
}

type DimensionsConfig struct {
	PerUser      bool `yaml:"per_user"`
	PerProcess   bool `yaml:"per_process"`
	PerContainer bool `yaml:"per_container"`
	Network      bool `yaml:"network"`
	FileSystem   bool `yaml:"filesystem"`
	Scheduling   bool `yaml:"scheduling"`
}

type Config struct {
	Server       ServerConfig       `yaml:"server"`
	PollInterval time.Duration      `yaml:"poll_interval"`
	BPFObject    string             `yaml:"bpf_object"`
	Tracepoints  []TracepointConfig `yaml:"tracepoints"`
	Metrics      []MetricConfig     `yaml:"metrics"`
	Baseline     BaselineConfig     `yaml:"baseline"`
	Scoring      ScoringConfig      `yaml:"scoring"`
	Host         HostConfig         `yaml:"host"`
	Container    ContainerConfig    `yaml:"container_monitoring"`
	Dimensions   DimensionsConfig   `yaml:"dimensions"`
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
		Baseline: BaselineConfig{
			LearningDuration:      168 * time.Hour,
			AggregationWindow:     time.Minute,
			RecalibrationInterval: 24 * time.Hour,
			EWMAAlpha:             0.01,
			MinStdDev:             1.0,
			StateFile:             "/var/lib/ebpf-agent/baseline.db",
		},
		Scoring: ScoringConfig{
			ZScoreThreshold:   3.0,
			QuantileThreshold: 0.99,
			MinimumSamples:    60,
			ColdStartSeverity: "warning",
		},
		Container: ContainerConfig{
			CgroupRoot: "/sys/fs/cgroup",
		},
		Dimensions: DimensionsConfig{
			PerUser:      true,
			PerProcess:   true,
			PerContainer: false,
			Network:      true,
			FileSystem:   true,
			Scheduling:   true,
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", cfg.Server.Port)
	}

	if len(cfg.Tracepoints) == 0 {
		return nil, fmt.Errorf("no tracepoints defined in config")
	}

	if cfg.Baseline.EWMAAlpha <= 0 || cfg.Baseline.EWMAAlpha >= 1 {
		return nil, fmt.Errorf("ewma_alpha must be in (0, 1), got %f", cfg.Baseline.EWMAAlpha)
	}

	if cfg.Host.ID == "" {
		cfg.Host.ID = detectHostID()
	}

	return cfg, nil
}

func detectHostID() string {
	data, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id
		}
	}

	hostname, err := os.Hostname()
	if err == nil {
		return hostname
	}

	return "unknown"
}
