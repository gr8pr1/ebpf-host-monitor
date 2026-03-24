package phase

import (
	"log"
	"sync"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
	"ebpf-agent/internal/scorer"
	"ebpf-agent/internal/store"
)

const (
	PhaseLearning  = 1
	PhaseMonitoring = 2
)

// Manager controls the learning-to-monitoring phase transition.
type Manager struct {
	engine    *baseline.Engine
	scorer    *scorer.Scorer
	store     *store.Store

	learningDuration time.Duration
	recalibInterval  time.Duration
	learningStart    time.Time
	lastRecalib      time.Time

	mu    sync.RWMutex
	phase int

	onScore func([]scorer.Result)
}

func NewManager(
	engine *baseline.Engine,
	sc *scorer.Scorer,
	st *store.Store,
	learningDuration time.Duration,
	recalibInterval time.Duration,
	onScore func([]scorer.Result),
) *Manager {
	m := &Manager{
		engine:           engine,
		scorer:           sc,
		store:            st,
		learningDuration: learningDuration,
		recalibInterval:  recalibInterval,
		learningStart:    time.Now(),
		lastRecalib:      time.Now(),
		phase:            PhaseLearning,
		onScore:          onScore,
	}

	if st != nil {
		snaps, err := st.LoadBaseline()
		if err != nil {
			log.Printf("WARN: failed to load persisted baseline: %v", err)
		} else if len(snaps) > 0 {
			engine.Restore(snaps)
			phaseStr, _ := st.GetMeta("phase")
			if phaseStr == "monitoring" {
				m.phase = PhaseMonitoring
				log.Printf("Restored baseline with %d dimensions, entering monitoring phase", len(snaps))
			} else {
				log.Printf("Restored baseline with %d dimensions, continuing learning phase", len(snaps))
			}
		}
	}

	return m
}

func (m *Manager) Phase() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.phase
}

func (m *Manager) Progress() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.phase == PhaseMonitoring {
		return 1.0
	}
	elapsed := time.Since(m.learningStart)
	p := elapsed.Seconds() / m.learningDuration.Seconds()
	if p > 1.0 {
		p = 1.0
	}
	return p
}

// ProcessWindow handles a completed aggregation window.
func (m *Manager) ProcessWindow(w *aggregator.Window) {
	m.engine.Ingest(w)

	m.mu.Lock()
	currentPhase := m.phase

	if currentPhase == PhaseLearning {
		if time.Since(m.learningStart) >= m.learningDuration {
			m.phase = PhaseMonitoring
			currentPhase = PhaseMonitoring
			log.Printf("Learning phase complete, transitioning to monitoring")
			m.persist("monitoring")
		} else {
			m.mu.Unlock()
			return
		}
	}

	if time.Since(m.lastRecalib) >= m.recalibInterval {
		m.lastRecalib = time.Now()
		m.mu.Unlock()
		m.persist("monitoring")
	} else {
		m.mu.Unlock()
	}

	if currentPhase == PhaseMonitoring {
		results := m.scorer.Score(w)
		if m.onScore != nil {
			m.onScore(results)
		}
	}
}

// Reset re-enters the learning phase.
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase = PhaseLearning
	m.learningStart = time.Now()
	log.Printf("Baseline reset, entering learning phase")
}

func (m *Manager) persist(phaseName string) {
	if m.store == nil {
		return
	}
	snaps := m.engine.Snapshot()
	if err := m.store.SaveBaseline(snaps); err != nil {
		log.Printf("WARN: failed to persist baseline: %v", err)
		return
	}
	if err := m.store.SetMeta("phase", phaseName); err != nil {
		log.Printf("WARN: failed to persist phase: %v", err)
	}
}
