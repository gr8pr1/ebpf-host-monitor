# Contributing to eBPF Security Monitoring System

Thanks for your interest in contributing! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/ebpf-host-monitor.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Commit with clear messages: `git commit -m "Add feature: description"`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Open a Pull Request

## Development Setup

### Host Agent Development

```bash
cd host/ebpf-agent

# Install dependencies
go mod download

# Build
make all

# Test
sudo ./ebpf-agent
```

### Monitoring Stack Development

```bash
cd monitoring/Docker/compose

# Start services
docker-compose up -d

# View logs
docker-compose logs -f
```

## Code Style

### Go Code
- Follow standard Go conventions
- Run `go fmt` before committing
- Add comments for exported functions
- Keep functions focused and small

### eBPF Code
- Follow Linux kernel coding style
- Add comments explaining complex logic
- Keep programs simple and verifiable
- Test thoroughly (eBPF verifier is strict)

### YAML/Config Files
- Use 2-space indentation
- Add comments for non-obvious settings
- Validate syntax before committing

## Testing

### Testing the eBPF Agent

```bash
# Start the agent
sudo ./ebpf-agent

# In another terminal, trigger events
ls
sudo ls
cat /etc/passwd

# Check metrics
curl http://localhost:9110/metrics
```

### Testing Alerts

```bash
# Generate high execution rate
for i in {1..100}; do ls > /dev/null; done

# Check Prometheus alerts
# Visit http://localhost:9090/alerts
```

## Adding New Features

### Adding a New eBPF Monitor

1. Update `bpf/exec.bpf.c`:
   - Add a new map
   - Add detection logic
   - Update the tracepoint handler

2. Update `exporter/metrics.go`:
   - Add a new Prometheus metric

3. Update `cmd/agent/main.go`:
   - Read the new map
   - Update the metric

4. Update documentation

### Adding New Alerts

1. Edit `monitoring/Docker/compose/prometheus/rules/alerts.yml`
2. Add your alert rule
3. Test with `promtool check rules alerts.yml`
4. Restart Prometheus: `docker-compose restart prometheus`

## Pull Request Guidelines

- **Title**: Clear and descriptive
- **Description**: Explain what and why
- **Testing**: Describe how you tested
- **Documentation**: Update relevant docs
- **Commits**: Keep them logical and atomic

## Reporting Issues

When reporting bugs, include:
- OS and kernel version
- Go version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

## Feature Requests

For feature requests, describe:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered
- How it benefits other users

## Questions?

Feel free to open an issue for questions or discussions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
