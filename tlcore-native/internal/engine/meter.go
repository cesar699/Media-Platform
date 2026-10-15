package engine

import (
	"net"
	"sync"
	"sync/atomic"
)

// TrafficMeter accumulates per-inbound traffic counters for the panel.
// The zero value is not usable; construct with NewTrafficMeter. A nil
// meter is accepted everywhere and counts nothing.
type TrafficMeter struct {
	mu   sync.Mutex
	tags map[string]*tagCounters
}

type tagCounters struct {
	up     atomic.Int64 // bytes received from clients (requests / uploads)
	down   atomic.Int64 // bytes sent to clients (responses / downloads)
	active atomic.Int64 // currently open sessions
	total  atomic.Int64 // sessions since start
}

// NewTrafficMeter creates an empty meter.
func NewTrafficMeter() *TrafficMeter {
	return &TrafficMeter{tags: make(map[string]*tagCounters)}
}

func (m *TrafficMeter) counters(tag string) *tagCounters {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.tags[tag]
	if !ok {
		c = &tagCounters{}
		m.tags[tag] = c
	}
	return c
}

// Open records the start of a session (TCP connection or UDP session).
func (m *TrafficMeter) Open(tag string) {
	if c := m.counters(tag); c != nil {
		c.active.Add(1)
		c.total.Add(1)
	}
}

// Close records the end of a session.
func (m *TrafficMeter) Close(tag string) {
	if c := m.counters(tag); c != nil {
		c.active.Add(-1)
	}
}

// AddUp records n bytes received from a client.
func (m *TrafficMeter) AddUp(tag string, n int) {
	if c := m.counters(tag); c != nil && n > 0 {
		c.up.Add(int64(n))
	}
}

// AddDown records n bytes sent to a client.
func (m *TrafficMeter) AddDown(tag string, n int) {
	if c := m.counters(tag); c != nil && n > 0 {
		c.down.Add(int64(n))
	}
}

// TagTraffic is a point-in-time snapshot of one inbound's counters.
type TagTraffic struct {
	UpBytes     int64 `json:"up_bytes"`
	DownBytes   int64 `json:"down_bytes"`
	ActiveConns int64 `json:"active_conns"`
	TotalConns  int64 `json:"total_conns"`
}

// Snapshot returns all per-tag counters.
func (m *TrafficMeter) Snapshot() map[string]TagTraffic {
	out := make(map[string]TagTraffic)
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for tag, c := range m.tags {
		out[tag] = TagTraffic{
			UpBytes:     c.up.Load(),
			DownBytes:   c.down.Load(),
			ActiveConns: c.active.Load(),
			TotalConns:  c.total.Load(),
		}
	}
	return out
}

// Seed restores cumulative byte/session counters (e.g. after a restart,
// from persisted panel state). Active counts always start at zero.
func (m *TrafficMeter) Seed(tag string, up, down, total int64) {
	if c := m.counters(tag); c != nil {
		c.up.Store(up)
		c.down.Store(down)
		c.total.Store(total)
	}
}

// meteredConn counts stream bytes as they pass through.
type meteredConn struct {
	net.Conn
	meter *TrafficMeter
	tag   string
}

func (c *meteredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.meter.AddUp(c.tag, n)
	}
	return n, err
}

func (c *meteredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.meter.AddDown(c.tag, n)
	}
	return n, err
}

// wrapConn returns conn instrumented for tag, or conn unchanged when
// the meter is nil.
func (m *TrafficMeter) wrapConn(tag string, conn net.Conn) net.Conn {
	if m == nil {
		return conn
	}
	return &meteredConn{Conn: conn, meter: m, tag: tag}
}
