package aggregator

import (
	"sync"
	"time"

	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
)

// DimensionKey uniquely identifies a metric dimension for baselining.
type DimensionKey struct {
	MetricName string
	User       string
	Process    string
	Container  string
}

// Window holds aggregated counts for a single time window.
type Window struct {
	Start    time.Time
	End      time.Time
	Counts   map[DimensionKey]float64
}

// Aggregator collects enriched events into time-bucketed windows.
type Aggregator struct {
	windowSize time.Duration
	perUser    bool
	perProcess bool
	perCont    bool

	mu      sync.Mutex
	current *Window
}

func New(windowSize time.Duration, perUser, perProcess, perContainer bool) *Aggregator {
	now := time.Now()
	return &Aggregator{
		windowSize: windowSize,
		perUser:    perUser,
		perProcess: perProcess,
		perCont:    perContainer,
		current: &Window{
			Start:  now,
			End:    now.Add(windowSize),
			Counts: make(map[DimensionKey]float64),
		},
	}
}

func (a *Aggregator) Add(ev *enricher.EnrichedEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	metricName := eventTypeToMetric(ev.Raw.EventType, ev.Raw.Flags)

	key := DimensionKey{MetricName: metricName}
	if a.perUser {
		key.User = ev.Username
	}
	if a.perProcess {
		key.Process = ev.Raw.CommString()
	}
	if a.perCont && ev.Container != "" {
		key.Container = ev.Container
	}

	a.current.Counts[key]++

	hostKey := DimensionKey{MetricName: metricName}
	if key != hostKey {
		a.current.Counts[hostKey]++
	}
}

// Rotate closes the current window and returns it, starting a new one.
func (a *Aggregator) Rotate() *Window {
	a.mu.Lock()
	defer a.mu.Unlock()

	finished := a.current
	now := time.Now()
	a.current = &Window{
		Start:  now,
		End:    now.Add(a.windowSize),
		Counts: make(map[DimensionKey]float64),
	}
	return finished
}

func eventTypeToMetric(evType uint8, flags uint8) string {
	switch evType {
	case ringbuf.EventExec:
		if flags&ringbuf.FlagSudo != 0 {
			return "sudo"
		}
		if flags&ringbuf.FlagPasswdRead != 0 {
			return "passwd_read"
		}
		return "exec"
	case ringbuf.EventConnect:
		if flags&ringbuf.FlagSuspiciousPort != 0 {
			return "suspicious_connect"
		}
		return "connect"
	case ringbuf.EventPtrace:
		return "ptrace"
	case ringbuf.EventOpenat:
		return "sensitive_file"
	case ringbuf.EventSetuid:
		return "setuid"
	case ringbuf.EventSetgid:
		return "setgid"
	case ringbuf.EventFork:
		return "fork"
	case ringbuf.EventExit:
		return "exit"
	case ringbuf.EventBind:
		return "bind"
	case ringbuf.EventDNS:
		return "dns"
	case ringbuf.EventCapset:
		return "capset"
	default:
		return "unknown"
	}
}
