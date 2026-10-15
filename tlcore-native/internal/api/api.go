// Package api serves the TLCore management HTTP API and the embedded UI.
package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	qrcode "github.com/skip2/go-qrcode"

	"tlcore-native/internal/core"
	"tlcore-native/internal/proto"
	"tlcore-native/internal/store"
	"tlcore-native/internal/web"
)

// Server wires the store, the core manager and HTTP handlers together.
type Server struct {
	store    *store.Store
	mgr      *core.Manager
	dataDir  string
	version  string
	sessions map[string]time.Time
	mu       sync.Mutex
}

// New creates the HTTP handler for the panel.
func New(st *store.Store, mgr *core.Manager, dataDir, version string) http.Handler {
	s := &Server{store: st, mgr: mgr, dataDir: dataDir, version: version, sessions: map[string]time.Time{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/bootstrap", s.handleBootstrap)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("GET /api/protocols", s.requireAuth(s.handleProtocols))
	mux.HandleFunc("GET /api/inbounds", s.requireAuth(s.handleListInbounds))
	mux.HandleFunc("POST /api/inbounds", s.requireAuth(s.handleCreateInbound))
	mux.HandleFunc("DELETE /api/inbounds/{id}", s.requireAuth(s.handleDeleteInbound))
	mux.HandleFunc("POST /api/inbounds/{id}/toggle", s.requireAuth(s.handleToggleInbound))
	mux.HandleFunc("GET /api/inbounds/{id}/qr", s.requireAuth(s.handleQR))
	mux.HandleFunc("POST /api/core/restart", s.requireAuth(s.handleCoreRestart))
	mux.HandleFunc("POST /api/core/stop", s.requireAuth(s.handleCoreStop))
	mux.HandleFunc("GET /api/settings", s.requireAuth(s.handleGetSettings))
	mux.HandleFunc("POST /api/settings", s.requireAuth(s.handleSaveSettings))
	mux.HandleFunc("POST /api/settings/password", s.requireAuth(s.handleChangePassword))
	mux.HandleFunc("GET /api/subscription", s.requireAuth(s.handleGetSubscription))
	mux.HandleFunc("POST /api/subscription/reset", s.requireAuth(s.handleResetSubscription))
	mux.HandleFunc("GET /api/subscription/qr", s.requireAuth(s.handleSubscriptionQR))
	mux.HandleFunc("GET /api/stats", s.requireAuth(s.handleStats))
	mux.HandleFunc("GET /sub/{token}", s.handleSubscription)
	mux.Handle("/", web.Handler())
	return mux
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v)
}

func (s *Server) newSession(w http.ResponseWriter) {
	var b [32]byte
	_, _ = rand.Read(b[:])
	token := hex.EncodeToString(b[:])
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(7 * 24 * time.Hour)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "tlcore_session", Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 3600,
	})
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie("tlcore_session")
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	return ok && time.Now().Before(exp)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		next(w, r)
	}
}

// applyState validates and applies a candidate state; on success it is
// persisted. The native manager builds engine specs from the state and
// rolls back to the last working set on failure.
func (s *Server) applyState(candidate store.State) error {
	if err := s.mgr.Apply(&candidate); err != nil {
		return err
	}
	if err := s.store.Replace(candidate); err != nil {
		return err
	}
	// Persist the latest traffic counters alongside config changes.
	_ = s.store.SaveTraffic(s.mgr.TrafficRecords())
	return nil
}

func findInbound(state *store.State, id string) *store.Inbound {
	for _, in := range state.Inbounds {
		if in.ID == id {
			return in
		}
	}
	return nil
}

// --- handlers ---

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	writeJSON(w, 200, map[string]any{"admin_set": snap.AdminPassHash != "", "version": s.version})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	if snap.AdminPassHash != "" {
		writeErr(w, 403, "admin already initialized")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil || body.Username == "" || len(body.Password) < 6 {
		writeErr(w, 400, "username required, password at least 6 chars")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := s.store.SetAdmin(body.Username, string(hash)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.newSession(w)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	snap := s.store.Snapshot()
	if body.Username != snap.AdminUser ||
		bcrypt.CompareHashAndPassword([]byte(snap.AdminPassHash), []byte(body.Password)) != nil {
		writeErr(w, 401, "wrong username or password")
		return
	}
	s.newSession(w)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("tlcore_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "tlcore_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	enabled := 0
	for _, in := range snap.Inbounds {
		if in.Enabled {
			enabled++
		}
	}
	running, startedAt, _ := s.mgr.Status()
	var started any
	if running {
		started = startedAt.Format(time.RFC3339)
	}
	writeJSON(w, 200, map[string]any{
		"version": s.version, "running": running, "started_at": started,
		"inbounds_total": len(snap.Inbounds), "inbounds_enabled": enabled,
		"server_addr": snap.ServerAddr,
	})
}

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, proto.Specs())
}

func (s *Server) inboundView(in *store.Inbound, serverAddr string) map[string]any {
	return map[string]any{
		"id": in.ID, "tag": in.Tag, "protocol": in.Protocol, "port": in.Port,
		"remark": in.Remark, "enabled": in.Enabled, "created_at": in.CreatedAt,
		"params": in.Params, "link": proto.ShareLink(in, serverAddr),
	}
}

func (s *Server) handleListInbounds(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	out := []map[string]any{}
	for _, in := range snap.Inbounds {
		out = append(out, s.inboundView(in, snap.ServerAddr))
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleCreateInbound(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Remark   string `json:"remark"`
		SNI      string `json:"sni"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	spec, ok := proto.SpecByID(body.Protocol)
	if !ok {
		writeErr(w, 400, "unknown protocol")
		return
	}
	if body.Port == 0 {
		body.Port = spec.DefaultPort
	}
	if body.Port < 1 || body.Port > 65535 {
		writeErr(w, 400, "invalid port")
		return
	}
	if body.SNI == "" {
		body.SNI = "www.microsoft.com"
	}
	if body.Remark == "" {
		body.Remark = spec.Name
	}
	snap := s.store.Snapshot()
	for _, in := range snap.Inbounds {
		if in.Port == body.Port {
			writeErr(w, 400, fmt.Sprintf("port %d already used by %s", body.Port, in.Tag))
			return
		}
	}
	params, err := proto.NewParams(body.Protocol, body.SNI, s.dataDir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	in := &store.Inbound{
		ID:       store.NewID(),
		Tag:      fmt.Sprintf("%s-%d", body.Protocol, body.Port),
		Protocol: body.Protocol, Port: body.Port, Remark: body.Remark,
		Enabled: true, Params: params,
	}
	candidate := snap
	candidate.Inbounds = append(append([]*store.Inbound{}, snap.Inbounds...), in)
	if err := s.applyState(candidate); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, s.inboundView(in, snap.ServerAddr))
}

func (s *Server) mutateInbound(w http.ResponseWriter, id string, mutate func(*store.State) bool) {
	snap := s.store.Snapshot()
	candidate := snap
	candidate.Inbounds = append([]*store.Inbound{}, snap.Inbounds...)
	if !mutate(&candidate) {
		writeErr(w, 404, "inbound not found")
		return
	}
	if err := s.applyState(candidate); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleDeleteInbound(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mutateInbound(w, id, func(state *store.State) bool {
		kept := state.Inbounds[:0]
		found := false
		for _, in := range state.Inbounds {
			if in.ID == id {
				found = true
				continue
			}
			kept = append(kept, in)
		}
		state.Inbounds = kept
		return found
	})
}

func (s *Server) handleToggleInbound(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	s.mutateInbound(w, id, func(state *store.State) bool {
		in := findInbound(state, id)
		if in == nil {
			return false
		}
		in.Enabled = body.Enabled
		return true
	})
}

func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	in := findInbound(&snap, r.PathValue("id"))
	if in == nil {
		writeErr(w, 404, "inbound not found")
		return
	}
	link := proto.ShareLink(in, snap.ServerAddr)
	png, err := qrcode.Encode(link, qrcode.Medium, 512)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

func (s *Server) handleCoreRestart(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	if err := s.mgr.Apply(&snap); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleCoreStop(w http.ResponseWriter, r *http.Request) {
	s.mgr.Stop()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	writeJSON(w, 200, map[string]any{"server_addr": snap.ServerAddr, "admin_user": snap.AdminUser})
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ServerAddr string `json:"server_addr"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	addr := strings.TrimSpace(body.ServerAddr)
	if addr == "" || strings.ContainsAny(addr, "/: ") {
		writeErr(w, 400, "server_addr must be an IP or domain without scheme/port")
		return
	}
	if err := s.store.SetServerAddr(addr); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := readJSON(r, &body); err != nil || len(body.New) < 6 {
		writeErr(w, 400, "new password at least 6 chars")
		return
	}
	snap := s.store.Snapshot()
	if bcrypt.CompareHashAndPassword([]byte(snap.AdminPassHash), []byte(body.Old)) != nil {
		writeErr(w, 401, "old password wrong")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.New), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := s.store.SetAdmin(snap.AdminUser, string(hash)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// --- subscription + stats ---

// ensureSubToken returns the subscription token, generating and
// persisting one when unset.
func (s *Server) ensureSubToken() (string, error) {
	snap := s.store.Snapshot()
	if snap.SubToken != "" {
		return snap.SubToken, nil
	}
	token := store.NewID() + store.NewID()
	if err := s.store.SetSubToken(token); err != nil {
		return "", err
	}
	return token, nil
}

// subscriptionURL builds the public subscription URL for this request.
func (s *Server) subscriptionURL(r *http.Request, token string) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/sub/" + token
}

// handleSubscription serves the public subscription document: the
// base64-encoded share links of all enabled inbounds (the universal
// format understood by v2rayN/v2rayNG/Shadowrocket/Streisand et al).
// Access is by unguessable token only.
func (s *Server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	token := r.PathValue("token")
	if snap.SubToken == "" || token == "" ||
		subtle.ConstantTimeCompare([]byte(token), []byte(snap.SubToken)) != 1 {
		http.NotFound(w, r)
		return
	}
	if snap.ServerAddr == "" {
		http.Error(w, "server_addr not configured", http.StatusServiceUnavailable)
		return
	}
	var links []string
	for _, in := range snap.Inbounds {
		if !in.Enabled {
			continue
		}
		if link := proto.ShareLink(in, snap.ServerAddr); link != "" {
			links = append(links, link)
		}
	}
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="tlcore-sub.txt"`)
	_, _ = w.Write([]byte(body))
}

func (s *Server) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	token, err := s.ensureSubToken()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"token": token,
		"path":  "/sub/" + token,
		"url":   s.subscriptionURL(r, token),
	})
}

func (s *Server) handleResetSubscription(w http.ResponseWriter, r *http.Request) {
	token := store.NewID() + store.NewID()
	if err := s.store.SetSubToken(token); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"token": token,
		"path":  "/sub/" + token,
		"url":   s.subscriptionURL(r, token),
	})
}

func (s *Server) handleSubscriptionQR(w http.ResponseWriter, r *http.Request) {
	token, err := s.ensureSubToken()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	png, err := qrcode.Encode(s.subscriptionURL(r, token), qrcode.Medium, 512)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

// handleStats returns per-inbound traffic counters and panel totals.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	meter := s.mgr.Meter().Snapshot()
	per := make(map[string]any)
	var totalUp, totalDown int64
	for _, in := range snap.Inbounds {
		t := meter[in.Tag]
		per[in.Tag] = t
		totalUp += t.UpBytes
		totalDown += t.DownBytes
	}
	writeJSON(w, 200, map[string]any{
		"per_inbound": per,
		"total_up":    totalUp,
		"total_down":  totalDown,
	})
}
