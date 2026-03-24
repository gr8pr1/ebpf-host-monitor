package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
	"ebpf-agent/internal/config"
	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/phase"
	"ebpf-agent/internal/poller"
	"ebpf-agent/internal/ringbuf"
	"ebpf-agent/internal/scorer"
	"ebpf-agent/internal/store"
)

import _ "embed"

//go:embed bpf/exec.bpf.o
var bpfProgram []byte

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	hostID := cfg.Host.ID
	hostLabel := prometheus.Labels{"host": hostID}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgram))
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating BPF collection: %v", err)
	}
	defer coll.Close()

	// --- Attach tracepoints ---
	var tracepoints []link.Link
	for _, tp := range cfg.Tracepoints {
		prog, ok := coll.Programs[tp.Program]
		if !ok {
			log.Printf("WARN: BPF program %q not found, skipping tracepoint %s/%s", tp.Program, tp.Group, tp.Name)
			continue
		}
		l, err := link.Tracepoint(tp.Group, tp.Name, prog, nil)
		if err != nil {
			log.Printf("WARN: failed to attach tracepoint %s/%s: %v", tp.Group, tp.Name, err)
			continue
		}
		tracepoints = append(tracepoints, l)
		log.Printf("Attached tracepoint %s/%s -> %s", tp.Group, tp.Name, tp.Program)
	}
	defer func() {
		for _, tp := range tracepoints {
			tp.Close()
		}
	}()
	if len(tracepoints) == 0 {
		log.Fatalf("no tracepoints attached, exiting")
	}

	// --- Counter pollers (backward-compat raw counters with host label) ---
	var pollers []*poller.MetricPoller
	for _, m := range cfg.Metrics {
		bpfMap, ok := coll.Maps[m.BPFMap]
		if !ok {
			log.Printf("WARN: BPF map %q not found, skipping metric %s", m.BPFMap, m.Name)
			continue
		}

		cv := prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: m.Name,
			Help: m.Help,
		}, []string{"host"})
		prometheus.MustRegister(cv)
		counter := cv.With(hostLabel)

		pollers = append(pollers, poller.NewMetricPoller(m.Name, bpfMap, counter))
		log.Printf("Registered metric %s -> map %s", m.Name, m.BPFMap)
	}
	if len(pollers) == 0 {
		log.Fatalf("no metrics registered, exiting")
	}

	// --- Baseline/anomaly Prometheus metrics ---
	baselinePhaseGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_baseline_phase",
		Help: "Current phase: 1=learning, 2=monitoring",
	}, []string{"host"})
	baselineProgressGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_baseline_progress",
		Help: "Learning phase progress 0.0 to 1.0",
	}, []string{"host"})
	baselineMeanGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_baseline_mean",
		Help: "Current baseline mean for a metric dimension",
	}, []string{"host", "metric", "dimension"})
	baselineStddevGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_baseline_stddev",
		Help: "Current baseline standard deviation",
	}, []string{"host", "metric", "dimension"})
	baselineUpperGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_baseline_upper_bound",
		Help: "Upper bound: mean + threshold * stddev",
	}, []string{"host", "metric", "dimension"})
	anomalyScoreGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_anomaly_score",
		Help: "Latest z-score for a metric dimension",
	}, []string{"host", "metric", "dimension"})
	anomalyTotalCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_anomaly_total",
		Help: "Total anomalies detected",
	}, []string{"host", "metric", "dimension", "severity"})

	prometheus.MustRegister(
		baselinePhaseGauge, baselineProgressGauge,
		baselineMeanGauge, baselineStddevGauge, baselineUpperGauge,
		anomalyScoreGauge, anomalyTotalCounter,
	)

	// --- Baseline pipeline ---
	blEngine := baseline.NewEngine(cfg.Baseline.EWMAAlpha, cfg.Scoring.MinimumSamples)

	var st *store.Store
	st, err = store.New(cfg.Baseline.StateFile)
	if err != nil {
		log.Printf("WARN: could not open state store at %s: %v (running without persistence)", cfg.Baseline.StateFile, err)
		st = nil
	}
	if st != nil {
		defer st.Close()
	}

	sc := scorer.New(blEngine, cfg.Scoring.ZScoreThreshold)

	var scoreMu sync.Mutex
	onScore := func(results []scorer.Result) {
		scoreMu.Lock()
		defer scoreMu.Unlock()
		for _, r := range results {
			dim := dimensionLabel(r.Key)
			anomalyScoreGauge.WithLabelValues(hostID, r.Key.MetricName, dim).Set(r.ZScore)
			baselineMeanGauge.WithLabelValues(hostID, r.Key.MetricName, dim).Set(r.Mean)
			baselineStddevGauge.WithLabelValues(hostID, r.Key.MetricName, dim).Set(r.StdDev)
			upper := r.Mean + cfg.Scoring.ZScoreThreshold*r.StdDev
			baselineUpperGauge.WithLabelValues(hostID, r.Key.MetricName, dim).Set(upper)

			if r.Anomaly {
				severity := "warning"
				if math.Abs(r.ZScore) > 5.0 {
					severity = "critical"
				}
				anomalyTotalCounter.WithLabelValues(hostID, r.Key.MetricName, dim, severity).Inc()
				log.Printf("ANOMALY [%s] %s/%s z=%.2f (mean=%.2f stddev=%.2f observed=%.0f)",
					severity, r.Key.MetricName, dim, r.ZScore, r.Mean, r.StdDev, r.Observed)
			}
		}
	}

	phaseMgr := phase.NewManager(
		blEngine, sc, st,
		cfg.Baseline.LearningDuration,
		cfg.Baseline.RecalibrationInterval,
		onScore,
	)

	enrich := enricher.New(cfg.Container.CgroupRoot)
	agg := aggregator.New(
		cfg.Baseline.AggregationWindow,
		cfg.Dimensions.PerUser,
		cfg.Dimensions.PerProcess,
		cfg.Dimensions.PerContainer,
	)

	// --- Ringbuf consumer ---
	var rbConsumer *ringbuf.Consumer
	eventsMap, hasRingbuf := coll.Maps["events"]
	if hasRingbuf {
		rbConsumer, err = ringbuf.NewConsumer(eventsMap, 4096)
		if err != nil {
			log.Printf("WARN: failed to create ringbuf consumer: %v (baseline features disabled)", err)
			hasRingbuf = false
		}
	}

	if hasRingbuf && rbConsumer != nil {
		go rbConsumer.Run()
		defer rbConsumer.Close()

		go func() {
			for ev := range rbConsumer.Events() {
				enriched := enrich.Enrich(ev)
				agg.Add(enriched)
			}
		}()
	}

	// --- HTTP server ---
	mux := http.NewServeMux()
	handler := promhttp.Handler()
	if cfg.Server.BasicAuth.Enabled {
		handler = basicAuth(handler, cfg.Server.BasicAuth.Username, cfg.Server.BasicAuth.Password)
	}
	mux.Handle(cfg.Server.MetricsPath, handler)

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		log.Printf("Serving %s on %s", cfg.Server.MetricsPath, addr)
		var srvErr error
		if cfg.Server.TLS.Enabled {
			srvErr = srv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		} else {
			srvErr = srv.ListenAndServe()
		}
		if srvErr != nil && srvErr != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", srvErr)
		}
	}()

	phaseStr := "learning"
	if phaseMgr.Phase() == phase.PhaseMonitoring {
		phaseStr = "monitoring"
	}
	log.Printf("eBPF adaptive agent active — host=%s phase=%s tracepoints=%d metrics=%d",
		hostID, phaseStr, len(tracepoints), len(pollers))

	// --- Graceful shutdown ---
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Main loop ---
	pollTicker := time.NewTicker(cfg.PollInterval)
	defer pollTicker.Stop()

	windowTicker := time.NewTicker(cfg.Baseline.AggregationWindow)
	defer windowTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(shutdownCtx)
			return

		case <-pollTicker.C:
			for _, p := range pollers {
				p.Poll()
			}
			baselinePhaseGauge.With(hostLabel).Set(float64(phaseMgr.Phase()))
			baselineProgressGauge.With(hostLabel).Set(phaseMgr.Progress())

		case <-windowTicker.C:
			if hasRingbuf {
				w := agg.Rotate()
				phaseMgr.ProcessWindow(w)
			}
		}
	}
}

func dimensionLabel(key aggregator.DimensionKey) string {
	parts := []string{"host"}
	if key.User != "" {
		parts = append(parts, "user:"+key.User)
	}
	if key.Process != "" {
		parts = append(parts, "proc:"+key.Process)
	}
	if key.Container != "" {
		parts = append(parts, "ctr:"+key.Container)
	}
	if len(parts) == 1 {
		return "host"
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += "," + p
	}
	return result
}

func basicAuth(next http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
