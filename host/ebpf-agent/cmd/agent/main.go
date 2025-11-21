package main

import (
	"bytes"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ebpf-agent/exporter"
)

import _ "embed"

//go:embed bpf/exec.bpf.o
var bpfProgram []byte

func main() {

	// Load BPF object from embedded bytes
	spec, err := ebpf.LoadCollectionSpecFromReader(
		bytes.NewReader(bpfProgram),
	)
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	// Create collection (maps + programs)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating BPF collection: %v", err)
	}
	defer coll.Close()

	// Link the eBPF program to execve tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", coll.Programs["trace_exec"], nil)
	if err != nil {
		log.Fatalf("linking tracepoint: %v", err)
	}
	defer tp.Close()

	// Register Prometheus metrics
	prometheus.MustRegister(exporter.ExecEvents)
	prometheus.MustRegister(exporter.SudoEvents)
	prometheus.MustRegister(exporter.PasswdReadEvents)

	// HTTP /metrics endpoint
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("Serving /metrics on :9110")
		http.ListenAndServe(":9110", nil)
	}()

	log.Println("eBPF exec tracer active on tracepoint sys_enter_execve")

	// Poll the eBPF maps every second
	key := uint32(0)
	execMap := coll.Maps["exec_counter"]
	sudoMap := coll.Maps["sudo_counter"]
	passwdReadMap := coll.Maps["passwd_read_counter"]
	var lastExecTotal uint64
	var lastSudoTotal uint64
	var lastPasswdReadTotal uint64

	cpuCount := runtime.NumCPU()
	execValues := make([]uint64, cpuCount)
	sudoValues := make([]uint64, cpuCount)
	passwdReadValues := make([]uint64, cpuCount)

	for {
		// Read exec counter
		if err := execMap.Lookup(&key, &execValues); err == nil {
			// Sum up all CPU counters
			total := uint64(0)
			nonZeroCount := 0
			for _, v := range execValues {
				total += v
				if v > 0 {
					nonZeroCount++
				}
			}

			// Calculate delta since last read
			if total >= lastExecTotal {
				delta := total - lastExecTotal
				if delta > 0 {
					exporter.ExecEvents.Add(float64(delta))
					log.Printf("Added %d exec events to Prometheus (from %d CPUs)", delta, nonZeroCount)
				}
				lastExecTotal = total
			}
		} else {
			log.Printf("Error reading exec PERCPU map: %v", err)
		}

		// Read sudo counter
		if err := sudoMap.Lookup(&key, &sudoValues); err == nil {
			// Sum up all CPU counters
			total := uint64(0)
			nonZeroCount := 0
			for _, v := range sudoValues {
				total += v
				if v > 0 {
					nonZeroCount++
				}
			}

			// Calculate delta since last read
			if total >= lastSudoTotal {
				delta := total - lastSudoTotal
				if delta > 0 {
					exporter.SudoEvents.Add(float64(delta))
					log.Printf("Added %d sudo events to Prometheus (from %d CPUs)", delta, nonZeroCount)
				}
				lastSudoTotal = total
			}
		} else {
			log.Printf("Error reading sudo PERCPU map: %v", err)
		}

		// Read passwd_read counter
		if err := passwdReadMap.Lookup(&key, &passwdReadValues); err == nil {
			// Sum up all CPU counters
			total := uint64(0)
			nonZeroCount := 0
			for _, v := range passwdReadValues {
				total += v
				if v > 0 {
					nonZeroCount++
				}
			}

			// Calculate delta since last read
			if total >= lastPasswdReadTotal {
				delta := total - lastPasswdReadTotal
				if delta > 0 {
					exporter.PasswdReadEvents.Add(float64(delta))
					log.Printf("Added %d /etc/passwd read events to Prometheus (from %d CPUs)", delta, nonZeroCount)
				}
				lastPasswdReadTotal = total
			}
		} else {
			log.Printf("Error reading passwd_read PERCPU map: %v", err)
		}

		time.Sleep(1 * time.Second)
	}
}
