# Deployment Guide

This guide walks you through deploying the eBPF Security Monitoring System in a production environment.

## Architecture Overview

```
┌─────────────────┐         ┌─────────────────┐
│   Host Server   │         │ Monitoring      │
│  (YOUR_HOST_IP) │────────▶│   Server        │
│                 │         │                 │
│  eBPF Agent     │  :9110  │  Prometheus     │
│  (Port 9110)    │         │  Grafana        │
└─────────────────┘         └─────────────────┘
```

## Prerequisites

### Host Server Requirements
- Linux kernel 5.8 or higher
- Root access
- 100MB disk space
- Minimal CPU/memory overhead

### Monitoring Server Requirements
- Docker and Docker Compose installed
- 2GB RAM minimum
- 10GB disk space for metrics storage
- Network access to all monitored hosts

## Step 1: Deploy the Monitoring Stack

On your monitoring server:

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ebpf-host-monitor.git
cd ebpf-host-monitor/monitoring/Docker/compose

# Configure target hosts
nano prometheus/prometheus.yml
# Update the targets list with your host IPs

# Start the stack
docker-compose up -d

# Verify services are running
docker-compose ps

# Check logs
docker-compose logs -f
```

Access the services:
- Prometheus: http://MONITORING_SERVER:9090
- Grafana: http://MONITORING_SERVER:3000

## Step 2: Deploy the eBPF Agent

On each host you want to monitor:

```bash
# Install dependencies
sudo apt update
sudo apt install -y linux-headers-$(uname -r) clang llvm golang-go

# Clone the repository
git clone https://github.com/YOUR_USERNAME/ebpf-host-monitor.git
cd ebpf-host-monitor/host/ebpf-agent

# Build and install
make install

# Verify it's running
sudo systemctl status ebpf-agent

# Check metrics
curl http://localhost:9110/metrics
```

## Step 3: Create Grafana Dashboards

1. Log in to Grafana (default: admin/admin)
2. Change the default password
3. Go to Dashboards → New Dashboard
4. Add panels with these queries:

**Execution Rate Panel:**
```promql
rate(ebpf_exec_events_total[5m])
```

**Sudo Events Panel:**
```promql
increase(ebpf_sudo_events_total[1h])
```

**Password File Access Panel:**
```promql
ebpf_passwd_read_events_total
```

**Multi-Host Overview:**
```promql
sum by (instance) (rate(ebpf_exec_events_total[5m]))
```

## Step 4: Test the System

### Test Metrics Collection

On a monitored host:
```bash
# Generate some events
ls
sudo ls
cat /etc/passwd
```

Check Prometheus:
- Go to http://MONITORING_SERVER:9090
- Query: `ebpf_exec_events_total`
- You should see the counter increasing

### Test Alerts

Generate high execution rate:
```bash
for i in {1..200}; do ls > /dev/null; done
```

Check alerts:
- Prometheus: http://MONITORING_SERVER:9090/alerts

## Production Hardening

### 1. Secure the Monitoring Stack

Add authentication to Prometheus:

```yaml
# docker-compose.yml
services:
  prometheus:
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--web.config.file=/etc/prometheus/web-config.yml'
```

Create `prometheus/web-config.yml`:
```yaml
basic_auth_users:
  admin: $2y$10$HASHED_PASSWORD
```

### 2. Use TLS for Metrics

Configure the eBPF agent to use TLS:
- Generate certificates
- Update the agent to serve HTTPS
- Update Prometheus scrape config

### 3. Firewall Rules

On monitored hosts:
```bash
# Allow only monitoring server
sudo ufw allow from MONITORING_SERVER_IP to any port 9110
sudo ufw enable
```

On monitoring server:
```bash
# Allow access to dashboards from trusted networks only
sudo ufw allow from TRUSTED_NETWORK to any port 3000
sudo ufw allow from TRUSTED_NETWORK to any port 9090
```

### 4. Resource Limits

Set resource limits in `docker-compose.yml`:

```yaml
services:
  prometheus:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

### 5. Data Retention

Configure Prometheus retention:

```yaml
services:
  prometheus:
    command:
      - '--storage.tsdb.retention.time=30d'
      - '--storage.tsdb.retention.size=10GB'
```

## Monitoring Multiple Environments

For multiple environments (dev, staging, prod), use labels:

```yaml
scrape_configs:
  - job_name: 'ebpf_agent'
    static_configs:
      - targets: ['10.10.10.11:9110']
        labels:
          environment: 'production'
          datacenter: 'us-east-1'
      
      - targets: ['10.10.20.11:9110']
        labels:
          environment: 'staging'
          datacenter: 'us-west-1'
```

## Backup and Recovery

### Backup Prometheus Data

```bash
# Stop Prometheus
docker-compose stop prometheus

# Backup data
tar -czf prometheus-backup-$(date +%Y%m%d).tar.gz \
  /var/lib/docker/volumes/compose_prometheus-data

# Restart Prometheus
docker-compose start prometheus
```

### Backup Grafana Dashboards

```bash
# Export dashboards via API
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:3000/api/dashboards/db/dashboard-name \
  > dashboard-backup.json
```

## Troubleshooting

### Agent Not Sending Metrics

```bash
# Check agent status
sudo systemctl status ebpf-agent

# View logs
sudo journalctl -u ebpf-agent -f

# Test metrics endpoint
curl http://localhost:9110/metrics

# Check network connectivity
telnet MONITORING_SERVER 9090
```

### Prometheus Not Scraping

```bash
# Check Prometheus targets
# Visit http://MONITORING_SERVER:9090/targets

# Check Prometheus logs
docker-compose logs prometheus

# Verify network connectivity
docker-compose exec prometheus wget -O- http://HOST_IP:9110/metrics
```

### Alerts Not Firing

```bash
# Check alert rules
# Visit http://MONITORING_SERVER:9090/rules

# Check Prometheus logs
docker-compose logs prometheus

# Verify alert rules are loaded
# Visit http://MONITORING_SERVER:9090/alerts
```

## Scaling

### Horizontal Scaling

For large deployments, consider:
- Prometheus federation for multiple Prometheus instances
- Thanos for long-term storage and global view
- Cortex for multi-tenant Prometheus

### Vertical Scaling

Increase resources in `docker-compose.yml`:
```yaml
services:
  prometheus:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
```

## Maintenance

### Update the Agent

```bash
cd ebpf-host-monitor/host/ebpf-agent
git pull
make all
sudo systemctl restart ebpf-agent
```

### Update the Monitoring Stack

```bash
cd monitoring/Docker/compose
docker-compose pull
docker-compose up -d
```

## Support

For issues or questions:
- Check the troubleshooting section
- Review logs on both host and monitoring server
- Open an issue on GitHub
