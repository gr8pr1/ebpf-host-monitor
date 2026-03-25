package enricher

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"ebpf-agent/internal/ringbuf"
)

type EnrichedEvent struct {
	Raw       *ringbuf.Event
	Binary    string
	Username  string
	Container string
	Resolved  bool
}

type pidEntry struct {
	binary  string
	expires time.Time
}

const (
	pidCacheMaxSize = 4096
	pidCacheTTL     = 10 * time.Second
)

type Enricher struct {
	cgroupRoot string

	userCache map[uint32]string
	userMu    sync.RWMutex

	pidCache map[uint32]pidEntry
	pidMu    sync.Mutex
}

func New(cgroupRoot string) *Enricher {
	e := &Enricher{
		cgroupRoot: cgroupRoot,
		userCache:  make(map[uint32]string),
		pidCache:   make(map[uint32]pidEntry),
	}
	e.loadUsers()
	return e
}

func (e *Enricher) Enrich(ev *ringbuf.Event) *EnrichedEvent {
	binary, resolved := e.resolveBinary(ev.PID)
	return &EnrichedEvent{
		Raw:       ev,
		Binary:    binary,
		Username:  e.resolveUser(ev.UID),
		Container: e.resolveContainer(ev.CgroupID),
		Resolved:  resolved,
	}
}

func (e *Enricher) resolveBinary(pid uint32) (string, bool) {
	e.pidMu.Lock()
	if entry, ok := e.pidCache[pid]; ok && time.Now().Before(entry.expires) {
		e.pidMu.Unlock()
		return entry.binary, entry.binary != ""
	}
	e.pidMu.Unlock()

	path := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(path)
	resolved := err == nil && target != ""

	e.pidMu.Lock()
	if len(e.pidCache) >= pidCacheMaxSize {
		e.evictExpired()
	}
	e.pidCache[pid] = pidEntry{
		binary:  target,
		expires: time.Now().Add(pidCacheTTL),
	}
	e.pidMu.Unlock()

	return target, resolved
}

func (e *Enricher) evictExpired() {
	now := time.Now()
	for pid, entry := range e.pidCache {
		if now.After(entry.expires) {
			delete(e.pidCache, pid)
		}
	}
	if len(e.pidCache) >= pidCacheMaxSize {
		for pid := range e.pidCache {
			delete(e.pidCache, pid)
			if len(e.pidCache) < pidCacheMaxSize/2 {
				break
			}
		}
	}
}

func (e *Enricher) resolveUser(uid uint32) string {
	e.userMu.RLock()
	name, ok := e.userCache[uid]
	e.userMu.RUnlock()
	if ok {
		return name
	}
	return fmt.Sprintf("uid:%d", uid)
}

func (e *Enricher) resolveContainer(cgroupID uint64) string {
	if cgroupID == 0 || cgroupID == 1 {
		return ""
	}
	return fmt.Sprintf("cgroup:%d", cgroupID)
}

func (e *Enricher) loadUsers() {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return
	}
	e.userMu.Lock()
	defer e.userMu.Unlock()
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 3 {
			continue
		}
		var uid uint32
		if _, err := fmt.Sscanf(parts[2], "%d", &uid); err == nil {
			e.userCache[uid] = parts[0]
		}
	}
}
