# Monitoring Stack

This directory contains the complete monitoring infrastructure for the eBPF Security Monitoring System.

## Components

- **Prometheus**: Time-series database and alerting engine
- **Grafana**: Visualization and dashboards

## Quick Start

```bash
cd Docker/compose

# IMPORTANT: Configure your host IPs first
nano prometheus/prometheus.yml
# Replace YOUR_HOST_IP with actual IP addresses

# Start the stack
docker-compose up -d

# Verify services are running
docker-compose ps
```

You should see output similar to:
```
NAME      IMAGE                    STATUS
grafana   grafana/grafana:latest   Up
prom      prom/prometheus:latest   Up
```

## Configuration

### Prometheus

Configuration file: `Docker/compose/prometheus/prometheus.yml`

**Required**: Before starting the stack, update the target hosts to match your environment:

```yaml
scrape_configs:
  - job_name: 'ebpf_agent'
    static_configs:
      - targets: ['YOUR_HOST_IP:9110']  # Replace with your actual host IP
```

Example with real IP:
```yaml
scrape_configs:
  - job_name: 'ebpf_agent'
    static_configs:
      - targets: ['192.168.1.100:9110']
```

### Alert Rules

Alert rules are defined in `Docker/compose/prometheus/rules/alerts.yml`.

To add custom alerts, edit this file and restart Prometheus:

```bash
docker-compose restart prometheus
```

### Grafana

Default credentials:
- Username: `admin`
- Password: `admin` (you'll be prompted to change this on first login)

Prometheus is pre-configured as a datasource.

**Creating Your First Dashboard:**

See the [main README screenshots](../README.md#screenshots) for examples of dashboard layouts. The Grafana dashboard screenshot shows a complete monitoring setup with multiple panels.

## Accessing Services

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000

## Creating Grafana Dashboards

1. Log in to Grafana (http://localhost:3000)
2. Click "+" → "Dashboard"
3. Add panels with PromQL queries:

Example queries:
```promql
# Execution rate
rate(ebpf_exec_events_total[5m])

# Sudo events over time
increase(ebpf_sudo_events_total[1h])

# /etc/passwd read attempts
ebpf_passwd_read_events_total
```

## Monitoring Multiple Hosts

To monitor multiple hosts, add them to the Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'ebpf_agent'
    static_configs:
      - targets: 
          - '192.168.1.100:9110'  # Host 1
          - '192.168.1.101:9110'  # Host 2
          - '192.168.1.102:9110'  # Host 3
```

## Troubleshooting

### Check service status
```bash
docker-compose ps
```

### View logs
```bash
docker-compose logs prometheus
docker-compose logs grafana
```

### Restart services
```bash
docker-compose restart
```

### Stop all services
```bash
docker-compose down
```

## Data Persistence

Prometheus and Grafana data are stored in Docker volumes:
- `prometheus-data`: Prometheus time-series data
- `grafana-data`: Grafana dashboards and settings

These volumes persist across container restarts.
