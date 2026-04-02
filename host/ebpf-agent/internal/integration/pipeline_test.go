//go:build integration

package integration_test

import (
	"testing"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
	"ebpf-agent/internal/scorer"
)

func TestPipelineSyntheticWindow(t *testing.T) {
	eng := baseline.NewEngine(0.01, 1)
	agg := aggregator.New(time.Minute, false, false, false, true, true, true)
	for i := 0; i < 3; i++ {
		w := agg.Rotate()
		w.Counts[aggregator.DimensionKey{MetricName: "exec"}] = 10
		eng.Ingest(w)
	}
	sc := scorer.New(eng, 3.0, 1.0, "warning", nil, false)
	w := agg.Rotate()
	w.Counts[aggregator.DimensionKey{MetricName: "exec"}] = 10
	_ = sc.Score(w)
}
