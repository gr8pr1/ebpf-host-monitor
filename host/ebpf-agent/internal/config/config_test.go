package config

import (
	"os"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	content := `
server:
  port: 9110
  metrics_path: /metrics
poll_interval: 1s
bpf_object: bpf/exec.bpf.o
tracepoints:
  - group: syscalls
    name: sys_enter_execve
    program: trace_exec
metrics:
  - name: ebpf_exec_events_total
    help: "Total exec events"
    bpf_map: exec_counter
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Port != 9110 {
		t.Errorf("expected port 9110, got %d", cfg.Server.Port)
	}
	if len(cfg.Metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(cfg.Metrics))
	}
	if cfg.Metrics[0].BPFMap != "exec_counter" {
		t.Errorf("expected bpf_map exec_counter, got %s", cfg.Metrics[0].BPFMap)
	}
	if len(cfg.Tracepoints) != 1 {
		t.Errorf("expected 1 tracepoint, got %d", len(cfg.Tracepoints))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidPort(t *testing.T) {
	content := `
server:
  port: 99999
tracepoints:
  - group: syscalls
    name: sys_enter_execve
    program: trace_exec
metrics:
  - name: test
    help: test
    bpf_map: test
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestLoadNoMetrics(t *testing.T) {
	content := `
server:
  port: 9110
tracepoints:
  - group: syscalls
    name: sys_enter_execve
    program: trace_exec
metrics: []
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("expected error for empty metrics")
	}
}

func TestLoadNoTracepoints(t *testing.T) {
	content := `
server:
  port: 9110
tracepoints: []
metrics:
  - name: test
    help: test
    bpf_map: test
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("expected error for empty tracepoints")
	}
}

func TestLoadWithTLSAndBasicAuth(t *testing.T) {
	content := `
server:
  port: 9110
  metrics_path: /metrics
  tls:
    enabled: true
    cert_file: /path/to/cert.pem
    key_file: /path/to/key.pem
  basic_auth:
    enabled: true
    username: admin
    password: secret
tracepoints:
  - group: syscalls
    name: sys_enter_execve
    program: trace_exec
metrics:
  - name: test
    help: test
    bpf_map: test
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.Server.TLS.Enabled {
		t.Error("expected TLS enabled")
	}
	if !cfg.Server.BasicAuth.Enabled {
		t.Error("expected basic auth enabled")
	}
	if cfg.Server.BasicAuth.Username != "admin" {
		t.Errorf("expected username admin, got %s", cfg.Server.BasicAuth.Username)
	}
}
