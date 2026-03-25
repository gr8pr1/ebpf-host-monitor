package scorer

import (
	"math"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
)

type Result struct {
	Key      aggregator.DimensionKey
	Observed float64
	Mean     float64
	StdDev   float64
	ZScore   float64
	Anomaly  bool
	Severity string
	ColdStart bool
}

type Scorer struct {
	engine            *baseline.Engine
	threshold         float64
	minStdDev         float64
	coldStartSeverity string
}

func New(engine *baseline.Engine, zscoreThreshold, minStdDev float64, coldStartSeverity string) *Scorer {
	if minStdDev <= 0 {
		minStdDev = 1.0
	}
	if coldStartSeverity == "" {
		coldStartSeverity = "warning"
	}
	return &Scorer{
		engine:            engine,
		threshold:         zscoreThreshold,
		minStdDev:         minStdDev,
		coldStartSeverity: coldStartSeverity,
	}
}

func (s *Scorer) Score(w *aggregator.Window) []Result {
	hour := w.Start.Hour()
	dow := int(w.Start.Weekday())

	var results []Result

	knownDimensions := make(map[aggregator.DimensionKey]struct{})
	for _, dk := range s.engine.AllDimensions() {
		knownDimensions[dk] = struct{}{}
	}

	for key, observed := range w.Counts {
		if _, known := knownDimensions[key]; !known {
			results = append(results, Result{
				Key:       key,
				Observed:  observed,
				Anomaly:   true,
				Severity:  s.coldStartSeverity,
				ColdStart: true,
			})
			continue
		}

		mean, stddev, _, ready := s.engine.Lookup(key, hour, dow)
		if !ready {
			continue
		}

		effStdDev := stddev
		if effStdDev < s.minStdDev {
			effStdDev = s.minStdDev
		}

		zscore := (observed - mean) / effStdDev

		severity := ""
		isAnomaly := math.Abs(zscore) > s.threshold
		if isAnomaly {
			severity = "warning"
			if math.Abs(zscore) > 5.0 {
				severity = "critical"
			}
		}

		results = append(results, Result{
			Key:      key,
			Observed: observed,
			Mean:     mean,
			StdDev:   stddev,
			ZScore:   zscore,
			Anomaly:  isAnomaly,
			Severity: severity,
		})
	}

	for dk := range knownDimensions {
		if _, exists := w.Counts[dk]; exists {
			continue
		}
		mean, stddev, _, ready := s.engine.Lookup(dk, hour, dow)
		if !ready || mean < 1.0 {
			continue
		}

		effStdDev := stddev
		if effStdDev < s.minStdDev {
			effStdDev = s.minStdDev
		}

		zscore := -mean / effStdDev

		if math.Abs(zscore) > s.threshold {
			severity := "warning"
			if math.Abs(zscore) > 5.0 {
				severity = "critical"
			}
			results = append(results, Result{
				Key:      dk,
				Observed: 0,
				Mean:     mean,
				StdDev:   stddev,
				ZScore:   zscore,
				Anomaly:  true,
				Severity: severity,
			})
		}
	}

	return results
}

func (s *Scorer) Threshold() float64 {
	return s.threshold
}

func TimeBucket(t time.Time) (hour, dow int) {
	return t.Hour(), int(t.Weekday())
}
