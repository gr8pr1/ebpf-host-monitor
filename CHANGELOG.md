# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-21

### Added
- Initial release of eBPF Security Monitoring System
- eBPF agent for monitoring execve syscalls
- Detection of sudo privilege escalation attempts
- Detection of /etc/passwd read attempts
- Prometheus metrics exporter
- Docker Compose monitoring stack with Prometheus and Grafana
- Pre-configured security alerts
- Systemd service file for production deployment
- Automated quick-start installation script
- Comprehensive documentation and deployment guides
- CI/CD pipeline with GitHub Actions
- BPF map inspection capabilities
- Per-CPU map support for high performance

### Features
- Real-time kernel-level monitoring using eBPF
- Zero-overhead event tracking
- Prometheus metrics integration
- Grafana dashboard support
- Multi-host monitoring capability
- Security alert rules for suspicious activities

### Documentation
- Main README with architecture overview
- Deployment guide for production environments
- Contributing guidelines
- Individual component documentation
- Screenshots and visual examples

## [Unreleased]

### Planned
- Additional security event detection (network connections, file modifications)
- Enhanced Grafana dashboards with pre-built templates
- Support for additional alert notification channels
- Performance metrics and benchmarking
- Container-specific monitoring
- Process tree visualization
- Historical event analysis

---

[1.0.0]: https://github.com/gr8pr1/ebpf-host-monitor/releases/tag/v1.0.0
