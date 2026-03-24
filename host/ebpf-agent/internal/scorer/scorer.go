package scorer

import (
	"math"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
)

// Result holds the anomaly scoring output for a single dimension.
type Result struct {
	Key      aggregator.DimensionKey
	Observed float64
	Mean     float64
	StdDev   float64
	ZScore   float64
	Anomaly  bool
}

// Scorer evaluates completed windows against the baseline.
type Scorer struct {
	engine    *baseline.Engine
	threshold float64
}

func New(engine *baseline.Engine, zscoreThreshold float64) *Scorer {
	return &Scorer{
		engine:    engine,
		threshold: zscoreThreshold,
	}
}

// Score evaluates a window and returns results for all dimensions.
func (s *Scorer) Score(w *aggregator.Window) []Result {
	hour := w.Start.Hour()
	dow := int(w.Start.Weekday())

	var results []Result
	for key, observed := range w.Counts {
		mean, stddev, _, ready := s.engine.Lookup(key, hour, dow)
		if !ready {
			continue
		}

		var zscore float64
		if stddev > 0 {
			zscore = (observed - mean) / stddev
		} else if observed > mean {
			zscore = math.Inf(1)
		}

		results = append(results, Result{
			Key:      key,
			Observed: observed,
			Mean:     mean,
			StdDev:   stddev,
			ZScore:   zscore,
			Anomaly:  math.Abs(zscore) > s.threshold,
		})
	}

	// Also check for dimensions that normally have events but didn't in this window
	// (potential suppression / evasion detection)
	for _, dk := range s.engine.AllDimensions() {
		if _, exists := w.Counts[dk]; exists {
			continue
		}
		mean, stddev, _, ready := s.engine.Lookup(dk, hour, dow)
		if !ready || mean < 1.0 {
			continue
		}

		var zscore float64
		if stddev > 0 {
			zscore = -mean / stddev
		}

		if math.Abs(zscore) > s.threshold {
			results = append(results, Result{
				Key:      dk,
				Observed: 0,
				Mean:     mean,
				StdDev:   stddev,
				ZScore:   zscore,
				Anomaly:  true,
			})
		}
	}

	return results
}

// Threshold returns the configured z-score threshold.
func (s *Scorer) Threshold() float64 {
	return s.threshold
}

// TimeBucket returns the seasonal index for a given time.
func TimeBucket(t time.Time) (hour, dow int) {
	return t.Hour(), int(t.Weekday())
}
