.PHONY: all build clean bpf install

# Build everything
all: bpf build

# Compile eBPF program
bpf:
	cd bpf && clang -O2 -g -target bpf -c exec.bpf.c -o exec.bpf.o
	cp bpf/exec.bpf.o cmd/agent/bpf/

# Build Go binary
build:
	go build -o ebpf-agent ./cmd/agent

# Clean build artifacts
clean:
	rm -f ebpf-agent
	rm -f bpf/exec.bpf.o
	rm -f cmd/agent/bpf/exec.bpf.o

# Install systemd service (requires root)
install: all
	sudo cp ebpf-agent /usr/local/bin/
	sudo cp ebpf-agent.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable ebpf-agent
	sudo systemctl start ebpf-agent
	@echo "eBPF agent installed and started"

# Uninstall
uninstall:
	sudo systemctl stop ebpf-agent || true
	sudo systemctl disable ebpf-agent || true
	sudo rm -f /etc/systemd/system/ebpf-agent.service
	sudo rm -f /usr/local/bin/ebpf-agent
	sudo systemctl daemon-reload
	@echo "eBPF agent uninstalled"
