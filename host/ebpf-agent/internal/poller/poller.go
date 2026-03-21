package poller

import (
	"log"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

// MetricPoller reads a per-CPU BPF map and feeds deltas into a Prometheus counter.
type MetricPoller struct {
	Name      string
	BPFMap    *ebpf.Map
	Counter   prometheus.Counter
	lastTotal uint64
	values    []uint64
}

// NewMetricPoller creates a poller for the given BPF map and Prometheus counter.
func NewMetricPoller(name string, bpfMap *ebpf.Map, counter prometheus.Counter) *MetricPoller {
	return &MetricPoller{
		Name:   name,
		BPFMap: bpfMap,
		Counter: counter,
		values: make([]uint64, runtime.NumCPU()),
	}
}

// Poll reads the per-CPU map, sums values across CPUs, and adds the delta to the Prometheus counter.
func (p *MetricPoller) Poll() {
	key := uint32(0)
	if err := p.BPFMap.Lookup(&key, &p.values); err != nil {
		log.Printf("Error reading PERCPU map %s: %v", p.Name, err)
		return
	}

	var total uint64
	var nonZero int
	for _, v := range p.values {
		total += v
		if v > 0 {
			nonZero++
		}
	}

	if total >= p.lastTotal {
		delta := total - p.lastTotal
		if delta > 0 {
			p.Counter.Add(float64(delta))
			log.Printf("[%s] +%d events (from %d CPUs)", p.Name, delta, nonZero)
		}
		p.lastTotal = total
	}
}
