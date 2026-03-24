package enricher

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"ebpf-agent/internal/ringbuf"
)

type EnrichedEvent struct {
	Raw       *ringbuf.Event
	Binary    string
	Username  string
	Container string
}

type Enricher struct {
	cgroupRoot string
	userCache  map[uint32]string
	mu         sync.RWMutex
}

func New(cgroupRoot string) *Enricher {
	e := &Enricher{
		cgroupRoot: cgroupRoot,
		userCache:  make(map[uint32]string),
	}
	e.loadUsers()
	return e
}

func (e *Enricher) Enrich(ev *ringbuf.Event) *EnrichedEvent {
	return &EnrichedEvent{
		Raw:       ev,
		Binary:    e.resolveBinary(ev.PID),
		Username:  e.resolveUser(ev.UID),
		Container: e.resolveContainer(ev.CgroupID),
	}
}

func (e *Enricher) resolveBinary(pid uint32) string {
	path := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return target
}

func (e *Enricher) resolveUser(uid uint32) string {
	e.mu.RLock()
	name, ok := e.userCache[uid]
	e.mu.RUnlock()
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
	e.mu.Lock()
	defer e.mu.Unlock()
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
