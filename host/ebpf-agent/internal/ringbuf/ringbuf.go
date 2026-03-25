package ringbuf

import (
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf"
	cringbuf "github.com/cilium/ebpf/ringbuf"
)

const EventSize = 48

const (
	EventExec    uint8 = 1
	EventConnect uint8 = 2
	EventPtrace  uint8 = 3
	EventOpenat  uint8 = 4
	EventSetuid  uint8 = 5
	EventSetgid  uint8 = 6
	EventFork    uint8 = 7
	EventExit    uint8 = 8
	EventBind    uint8 = 9
	EventDNS     uint8 = 10
	EventCapset  uint8 = 11
)

const (
	FlagSudo           uint8 = 1 << 0
	FlagSuspiciousPort uint8 = 1 << 1
	FlagSensitiveFile  uint8 = 1 << 2
	FlagPasswdRead     uint8 = 1 << 3
)

type Event struct {
	TimestampNs uint64
	PID         uint32
	UID         uint32
	CgroupID    uint64
	EventType   uint8
	Flags       uint8
	DestPort    uint16
	DestIP      uint32
	Comm        [16]byte
}

func (e *Event) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

func parseEvent(data []byte) (*Event, error) {
	if len(data) < EventSize {
		return nil, errors.New("record too short")
	}
	e := &Event{
		TimestampNs: binary.LittleEndian.Uint64(data[0:8]),
		PID:         binary.LittleEndian.Uint32(data[8:12]),
		UID:         binary.LittleEndian.Uint32(data[12:16]),
		CgroupID:    binary.LittleEndian.Uint64(data[16:24]),
		EventType:   data[24],
		Flags:       data[25],
		DestPort:    binary.LittleEndian.Uint16(data[26:28]),
		DestIP:      binary.LittleEndian.Uint32(data[28:32]),
	}
	copy(e.Comm[:], data[32:48])
	return e, nil
}

type Consumer struct {
	reader *cringbuf.Reader
	out    chan *Event
	done   chan struct{}
	onDrop func()
}

func NewConsumer(eventsMap *ebpf.Map, bufSize int) (*Consumer, error) {
	rd, err := cringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, err
	}

	c := &Consumer{
		reader: rd,
		out:    make(chan *Event, bufSize),
		done:   make(chan struct{}),
	}
	return c, nil
}

func (c *Consumer) SetDropCallback(fn func()) {
	c.onDrop = fn
}

func (c *Consumer) Events() <-chan *Event {
	return c.out
}

// Run blocks, reading from the ringbuf and pushing to the channel.
// Call Close() to stop.
func (c *Consumer) Run() {
	defer close(c.out)
	for {
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, cringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read error: %v", err)
			continue
		}

		ev, err := parseEvent(record.RawSample)
		if err != nil {
			log.Printf("ringbuf parse error: %v", err)
			continue
		}

		select {
		case c.out <- ev:
		default:
			if c.onDrop != nil {
				c.onDrop()
			}
		}
	}
}

func (c *Consumer) Close() error {
	return c.reader.Close()
}
