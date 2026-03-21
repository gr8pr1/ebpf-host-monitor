package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ebpf-agent/internal/config"
	"ebpf-agent/internal/poller"
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

	// Load BPF object from embedded bytes
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgram))
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating BPF collection: %v", err)
	}
	defer coll.Close()

	// Attach tracepoints from config
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

	// Build pollers from config
	var pollers []*poller.MetricPoller
	for _, m := range cfg.Metrics {
		bpfMap, ok := coll.Maps[m.BPFMap]
		if !ok {
			log.Printf("WARN: BPF map %q not found, skipping metric %s", m.BPFMap, m.Name)
			continue
		}

		counter := prometheus.NewCounter(prometheus.CounterOpts{
			Name: m.Name,
			Help: m.Help,
		})
		prometheus.MustRegister(counter)

		pollers = append(pollers, poller.NewMetricPoller(m.Name, bpfMap, counter))
		log.Printf("Registered metric %s -> map %s", m.Name, m.BPFMap)
	}

	if len(pollers) == 0 {
		log.Fatalf("no metrics registered, exiting")
	}

	// HTTP server with optional basic auth and TLS
	mux := http.NewServeMux()
	handler := promhttp.Handler()

	if cfg.Server.BasicAuth.Enabled {
		user := cfg.Server.BasicAuth.Username
		pass := cfg.Server.BasicAuth.Password
		handler = basicAuth(handler, user, pass)
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

	log.Printf("eBPF security agent active — %d tracepoints, %d metrics", len(tracepoints), len(pollers))

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Poll loop
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(shutdownCtx)
			return
		case <-ticker.C:
			for _, p := range pollers {
				p.Poll()
			}
		}
	}
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
