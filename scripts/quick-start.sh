#!/bin/bash
set -e

echo "=========================================="
echo "eBPF Security Monitoring - Quick Start"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Error: Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS"
echo ""

# Install dependencies
echo "Installing dependencies..."
case $OS in
    ubuntu|debian)
        apt-get update
        apt-get install -y linux-headers-$(uname -r) clang llvm golang-go curl
        ;;
    centos|rhel|fedora)
        yum install -y kernel-devel clang llvm golang curl
        ;;
    *)
        echo "Warning: Unsupported OS. Please install dependencies manually:"
        echo "  - linux-headers / kernel-devel"
        echo "  - clang and llvm"
        echo "  - golang"
        exit 1
        ;;
esac

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
REQUIRED_VERSION=5.8

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$KERNEL_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Error: Kernel version $KERNEL_VERSION is too old. Requires 5.8+"
    exit 1
fi

echo "Kernel version: $KERNEL_VERSION ✓"
echo ""

# Build the agent
echo "Building eBPF agent..."
cd "$(dirname "$0")/../host/ebpf-agent"

make clean
make all

if [ ! -f ebpf-agent ]; then
    echo "Error: Build failed"
    exit 1
fi

echo "Build successful ✓"
echo ""

# Ask user if they want to install as service
read -p "Install as systemd service? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    make install
    echo ""
    echo "Service installed and started ✓"
    echo ""
    echo "Check status with: sudo systemctl status ebpf-agent"
    echo "View logs with: sudo journalctl -u ebpf-agent -f"
else
    echo ""
    echo "To run manually: sudo ./ebpf-agent"
fi

echo ""
echo "=========================================="
echo "Installation complete!"
echo "=========================================="
echo ""
echo "Metrics endpoint: http://localhost:9110/metrics"
echo ""
echo "Test it with: curl http://localhost:9110/metrics"
echo ""
echo "Next steps:"
echo "1. Deploy the monitoring stack (see monitoring/README.md)"
echo "2. Configure Prometheus to scrape this host"
echo "3. Set up Grafana dashboards"
echo ""
