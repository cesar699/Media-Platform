// Package store persists TLCore state (admin, settings, inbounds) as JSON.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Inbound is one panel-managed sing-box inbound.
type Inbound struct {
	ID        string            `json:"id"`
	Tag       string            `json:"tag"`
	Protocol  string            `json:"protocol"`
	Port      int               `json:"port"`
	Remark    string            `json:"remark"`
	Enabled   bool              `json:"enabled"`
	Params    map[string]string `json:"params"`
	CreatedAt int64             `json:"created_at"`
}

// TrafficRecord is one inbound's persisted cumulative counters.
type TrafficRecord struct {
	Up    int64 `json:"up"`
	Down  int64 `json:"down"`
	Total int64 `json:"total"`
}

// State is the whole persisted document.
type State struct {
	AdminUser     string                    `json:"admin_user"`
	AdminPassHash string                    `json:"admin_pass_hash"`
	ServerAddr    string                    `json:"server_addr"`
	SubToken      string                    `json:"sub_token,omitempty"`
	Inbounds      []*Inbound                `json:"inbounds"`
	Traffic       map[string]*TrafficRecord `json:"traffic,omitempty"`
}

// Store guards State with a mutex and writes through to disk on change.
type Store struct {
	mu    sync.Mutex
	path  string
	state *State
}

// Load reads state from path; a missing file yields a fresh empty state.
func Load(path string) (*Store, error) {
	s := &Store{path: path, state: &State{AdminUser: "admin"}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s.state); err != nil {
		return nil, err
	}
	if s.state.Inbounds == nil {
		s.state.Inbounds = []*Inbound{}
	}
	return s, nil
}

// Save writes the state atomically (tmp file + rename).
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Snapshot returns a copy of the current state.
func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := *s.state
	out.Inbounds = make([]*Inbound, len(s.state.Inbounds))
	for i, in := range s.state.Inbounds {
		cp := *in
		params := make(map[string]string, len(in.Params))
		for k, v := range in.Params {
			params[k] = v
		}
		cp.Params = params
		out.Inbounds[i] = &cp
	}
	sort.Slice(out.Inbounds, func(i, j int) bool { return out.Inbounds[i].CreatedAt < out.Inbounds[j].CreatedAt })
	return out
}

// SetAdmin records the admin username and bcrypt password hash.
func (s *Store) SetAdmin(user, passHash string) error {
	s.mu.Lock()
	s.state.AdminUser = user
	s.state.AdminPassHash = passHash
	s.mu.Unlock()
	return s.Save()
}

// SetServerAddr records the public address used in share links.
func (s *Store) SetServerAddr(addr string) error {
	s.mu.Lock()
	s.state.ServerAddr = addr
	s.mu.Unlock()
	return s.Save()
}

// SetSubToken records the subscription access token.
func (s *Store) SetSubToken(token string) error {
	s.mu.Lock()
	s.state.SubToken = token
	s.mu.Unlock()
	return s.Save()
}

// SaveTraffic persists cumulative per-inbound traffic counters. It
// updates only the traffic map of the live state, so it never clobbers
// concurrent inbound edits.
func (s *Store) SaveTraffic(records map[string]*TrafficRecord) error {
	s.mu.Lock()
	s.state.Traffic = records
	s.mu.Unlock()
	return s.Save()
}

// AddInbound appends a new inbound (ID and timestamp assigned here).
func (s *Store) AddInbound(in *Inbound) error {
	s.mu.Lock()
	if in.ID == "" {
		in.ID = NewID()
	}
	in.CreatedAt = time.Now().Unix()
	s.state.Inbounds = append(s.state.Inbounds, in)
	s.mu.Unlock()
	return s.Save()
}

// RemoveInbound deletes an inbound by ID.
func (s *Store) RemoveInbound(id string) (bool, error) {
	s.mu.Lock()
	found := false
	kept := s.state.Inbounds[:0]
	for _, in := range s.state.Inbounds {
		if in.ID == id {
			found = true
			continue
		}
		kept = append(kept, in)
	}
	s.state.Inbounds = kept
	s.mu.Unlock()
	if !found {
		return false, nil
	}
	return true, s.Save()
}

// SetEnabled flips an inbound's enabled flag.
func (s *Store) SetEnabled(id string, enabled bool) (bool, error) {
	s.mu.Lock()
	found := false
	for _, in := range s.state.Inbounds {
		if in.ID == id {
			in.Enabled = enabled
			found = true
		}
	}
	s.mu.Unlock()
	if !found {
		return false, nil
	}
	return true, s.Save()
}

// Replace swaps the whole state (used after a config change has been
// validated and applied, so disk state never diverges from the core).
func (s *Store) Replace(state State) error {
	s.mu.Lock()
	cp := state
	s.state = &cp
	s.mu.Unlock()
	return s.Save()
}

// NewID returns a random hex identifier.
func NewID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
