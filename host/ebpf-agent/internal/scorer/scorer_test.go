package scorer

import (
	"testing"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
)

func TestCeilingTriggersAnomaly(t *testing.T) {
	eng := baseline.NewEngine(0.01, 2)
	w0 := &aggregator.Window{
		Start: time.Now(),
		End:   time.Now().Add(time.Minute),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "ptrace"}: 1,
		},
	}
	eng.Ingest(w0)
	eng.Ingest(w0)

	s := New(eng, 3.0, 1.0, "warning", map[string]float64{"ptrace": 5}, false)

	w := &aggregator.Window{
		Start: time.Now(),
		End:   time.Now().Add(time.Minute),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "ptrace"}: 10,
		},
	}
	res := s.Score(w)
	if len(res) != 1 || !res[0].Anomaly || res[0].Severity != "critical" {
		t.Fatalf("expected ceiling anomaly, got %+v", res)
	}
}
