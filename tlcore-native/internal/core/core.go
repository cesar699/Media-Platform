// Package core drives the native engine from panel state: it translates
// enabled inbounds into engine specs, applies them with rollback to the
// last working set on failure, and remembers when the core started.
package core

import (
	"fmt"
	"sync"
	"time"

	"tlcore-native/internal/engine"
	"tlcore-native/internal/proto"
	"tlcore-native/internal/store"
)

// Manager owns the engine lifecycle.
type Manager struct {
	mu        sync.Mutex
	eng       *engine.Engine
	meter     *engine.TrafficMeter
	dataDir   string
	lastGood  []engine.InboundSpec
	startedAt time.Time
	err       error
}

// New creates a Manager bound to a data directory.
func New(dataDir string) *Manager {
	meter := engine.NewTrafficMeter()
	return &Manager{eng: &engine.Engine{Meter: meter}, meter: meter, dataDir: dataDir}
}

// Meter exposes the traffic meter (panel stats + persistence).
func (m *Manager) Meter() *engine.TrafficMeter { return m.meter }

// SeedTraffic restores cumulative counters persisted by a previous run.
func (m *Manager) SeedTraffic(records map[string]*store.TrafficRecord) {
	for tag, rec := range records {
		if rec != nil {
			m.meter.Seed(tag, rec.Up, rec.Down, rec.Total)
		}
	}
}

// TrafficRecords snapshots cumulative counters in store form.
func (m *Manager) TrafficRecords() map[string]*store.TrafficRecord {
	out := make(map[string]*store.TrafficRecord)
	for tag, t := range m.meter.Snapshot() {
		out[tag] = &store.TrafficRecord{Up: t.UpBytes, Down: t.DownBytes, Total: t.TotalConns}
	}
	return out
}

// BuildSpecs translates state into engine specs (enabled inbounds only).
func (m *Manager) BuildSpecs(st *store.State) ([]engine.InboundSpec, error) {
	var specs []engine.InboundSpec
	for i := range st.Inbounds {
		in := st.Inbounds[i]
		if !in.Enabled {
			continue
		}
		spec, err := proto.BuildSpec(in, m.dataDir)
		if err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// Apply builds specs from the candidate state and swaps the running
// engine to them. On failure it restarts the last working set and
// returns the error, so the running core never diverges from what the
// panel has persisted.
func (m *Manager) Apply(st *store.State) error {
	specs, err := m.BuildSpecs(st)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eng.Stop()
	if err := m.eng.Start(specs); err != nil {
		// Roll back to the last working set.
		if m.lastGood != nil {
			if rbErr := m.eng.Start(m.lastGood); rbErr == nil {
				m.err = fmt.Errorf("%w (rolled back to previous config)", err)
				return m.err
			}
		}
		m.err = err
		return err
	}
	m.lastGood = specs
	m.startedAt = time.Now()
	m.err = nil
	return nil
}

// Stop halts the engine.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eng.Stop()
}

// Restart re-applies the given state.
func (m *Manager) Restart(st *store.State) error { return m.Apply(st) }

// Status reports the engine state for the panel dashboard.
func (m *Manager) Status() (running bool, startedAt time.Time, lastErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eng.Running(), m.startedAt, m.err
}
