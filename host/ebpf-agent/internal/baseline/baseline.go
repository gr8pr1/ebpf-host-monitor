package baseline

import (
	"math"
	"sync"

	"ebpf-agent/internal/aggregator"
)

// HourlyBuckets is the number of seasonal buckets: 24 hours * 7 days.
const HourlyBuckets = 168

// BucketStats holds running statistics for a single seasonal bucket.
type BucketStats struct {
	Count    int
	Sum      float64
	SumSq    float64
	Min      float64
	Max      float64
	EWMA     float64
	ewmaInit bool
}

func (b *BucketStats) Mean() float64 {
	if b.Count == 0 {
		return 0
	}
	return b.Sum / float64(b.Count)
}

func (b *BucketStats) StdDev() float64 {
	if b.Count < 2 {
		return 0
	}
	mean := b.Mean()
	variance := (b.SumSq / float64(b.Count)) - (mean * mean)
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

// DimensionBaseline holds 168 hourly buckets for one metric dimension.
type DimensionBaseline struct {
	Buckets [HourlyBuckets]BucketStats
}

// Engine manages baselines for all dimensions.
type Engine struct {
	alpha     float64
	minSample int
	mu        sync.RWMutex
	baselines map[aggregator.DimensionKey]*DimensionBaseline
}

func NewEngine(ewmaAlpha float64, minSamples int) *Engine {
	return &Engine{
		alpha:     ewmaAlpha,
		minSample: minSamples,
		baselines: make(map[aggregator.DimensionKey]*DimensionBaseline),
	}
}

// SeasonalIndex computes the 0–167 bucket from wall clock time.
func SeasonalIndex(hour, dayOfWeek int) int {
	return dayOfWeek*24 + hour
}

// Ingest adds a window's data points to the baseline.
func (e *Engine) Ingest(w *aggregator.Window) {
	hour := w.Start.Hour()
	dow := int(w.Start.Weekday())
	idx := SeasonalIndex(hour, dow)

	e.mu.Lock()
	defer e.mu.Unlock()

	for key, value := range w.Counts {
		bl, ok := e.baselines[key]
		if !ok {
			bl = &DimensionBaseline{}
			e.baselines[key] = bl
		}

		b := &bl.Buckets[idx]
		b.Count++
		b.Sum += value
		b.SumSq += value * value
		if b.Count == 1 || value < b.Min {
			b.Min = value
		}
		if value > b.Max {
			b.Max = value
		}

		if !b.ewmaInit {
			b.EWMA = value
			b.ewmaInit = true
		} else {
			b.EWMA = e.alpha*value + (1-e.alpha)*b.EWMA
		}
	}
}

// Lookup returns the stats for a dimension at a given seasonal index.
func (e *Engine) Lookup(key aggregator.DimensionKey, hour, dow int) (mean, stddev, ewma float64, ready bool) {
	idx := SeasonalIndex(hour, dow)

	e.mu.RLock()
	defer e.mu.RUnlock()

	bl, ok := e.baselines[key]
	if !ok {
		return 0, 0, 0, false
	}

	b := &bl.Buckets[idx]
	if b.Count < e.minSample {
		return b.Mean(), b.StdDev(), b.EWMA, false
	}

	return b.Mean(), b.StdDev(), b.EWMA, true
}

// AllDimensions returns all tracked dimension keys.
func (e *Engine) AllDimensions() []aggregator.DimensionKey {
	e.mu.RLock()
	defer e.mu.RUnlock()

	keys := make([]aggregator.DimensionKey, 0, len(e.baselines))
	for k := range e.baselines {
		keys = append(keys, k)
	}
	return keys
}

// TotalSamples returns the total number of windows ingested across
// all buckets for a dimension.
func (e *Engine) TotalSamples(key aggregator.DimensionKey) int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	bl, ok := e.baselines[key]
	if !ok {
		return 0
	}

	total := 0
	for i := range bl.Buckets {
		total += bl.Buckets[i].Count
	}
	return total
}

// Snapshot returns a copy of the entire baseline state for persistence.
type DimensionSnapshot struct {
	Key     aggregator.DimensionKey
	Buckets [HourlyBuckets]BucketStats
}

func (e *Engine) Snapshot() []DimensionSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	snaps := make([]DimensionSnapshot, 0, len(e.baselines))
	for k, bl := range e.baselines {
		snaps = append(snaps, DimensionSnapshot{
			Key:     k,
			Buckets: bl.Buckets,
		})
	}
	return snaps
}

// Restore loads a snapshot back into the engine.
func (e *Engine) Restore(snaps []DimensionSnapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, s := range snaps {
		bl := &DimensionBaseline{Buckets: s.Buckets}
		e.baselines[s.Key] = bl
	}
}
