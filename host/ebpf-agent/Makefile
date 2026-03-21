.PHONY: all build clean bpf install uninstall test

# Feature flags — all enabled by default
# Disable a feature: make bpf MONITOR_EXEC=0
MONITOR_EXEC   ?= 1
MONITOR_SUDO   ?= 1
MONITOR_PASSWD  ?= 1
MONITOR_CONNECT ?= 1
MONITOR_PTRACE  ?= 1
MONITOR_OPENAT  ?= 1
MONITOR_SETUID  ?= 1

BPF_FLAGS :=
ifeq ($(MONITOR_EXEC),1)
  BPF_FLAGS += -DMONITOR_EXEC
endif
ifeq ($(MONITOR_SUDO),1)
  BPF_FLAGS += -DMONITOR_SUDO
endif
ifeq ($(MONITOR_PASSWD),1)
  BPF_FLAGS += -DMONITOR_PASSWD
endif
ifeq ($(MONITOR_CONNECT),1)
  BPF_FLAGS += -DMONITOR_CONNECT
endif
ifeq ($(MONITOR_PTRACE),1)
  BPF_FLAGS += -DMONITOR_PTRACE
endif
ifeq ($(MONITOR_OPENAT),1)
  BPF_FLAGS += -DMONITOR_OPENAT
endif
ifeq ($(MONITOR_SETUID),1)
  BPF_FLAGS += -DMONITOR_SETUID
endif

# Build everything
all: bpf build

# Compile eBPF program with feature flags
bpf:
	cd bpf && clang -O2 -g -target bpf $(BPF_FLAGS) -c exec.bpf.c -o exec.bpf.o
	cp bpf/exec.bpf.o cmd/agent/bpf/

# Build Go binary
build:
	go build -o ebpf-agent ./cmd/agent

# Run Go unit tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -f ebpf-agent
	rm -f bpf/exec.bpf.o
	rm -f cmd/agent/bpf/exec.bpf.o

# Install systemd service (requires root)
install: all
	sudo cp ebpf-agent /usr/local/bin/
	sudo cp config.yaml /etc/ebpf-agent/config.yaml
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
	sudo rm -rf /etc/ebpf-agent
	sudo systemctl daemon-reload
	@echo "eBPF agent uninstalled"
