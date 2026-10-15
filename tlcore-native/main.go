// TLCore-Native — a multi-protocol proxy core developed from scratch,
// with a visual management panel.
//
// Unlike TLCore (which embeds sing-box), TLCore-Native implements its
// protocols itself in internal/engine: Shadowsocks 2022, Trojan, VLESS
// and VMess (AEAD), each verified for interoperability against the
// reference implementations. The web panel creates and manages inbounds
// without hand-writing configuration.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"

	"tlcore-native/internal/api"
	"tlcore-native/internal/core"
	"tlcore-native/internal/store"
)

// Version is shown in the panel and /api/status.
const Version = "TLCore-Native 0.2.0 · 自研内核"

func main() {
	addr := flag.String("addr", "0.0.0.0:8080", "panel listen address")
	dataDir := flag.String("data", "./data", "data directory")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatal(err)
	}
	st, err := store.Load(filepath.Join(*dataDir, "state.json"))
	if err != nil {
		log.Fatalf("load state: %v", err)
	}

	// Optional pre-seeded admin via environment (first run only).
	if st.Snapshot().AdminPassHash == "" {
		if user, pass := os.Getenv("TLCORE_ADMIN_USER"), os.Getenv("TLCORE_ADMIN_PASSWORD"); pass != "" {
			if user == "" {
				user = "admin"
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
			if err != nil {
				log.Fatal(err)
			}
			if err := st.SetAdmin(user, string(hash)); err != nil {
				log.Fatal(err)
			}
			log.Printf("admin %q created from TLCORE_ADMIN_* environment", user)
		}
	}

	mgr := core.New(*dataDir)
	// Restore cumulative traffic counters persisted by previous runs.
	mgr.SeedTraffic(st.Snapshot().Traffic)
	// Bring the core up with whatever inbounds are already configured.
	if snap := st.Snapshot(); len(snap.Inbounds) > 0 {
		if err := mgr.Apply(&snap); err != nil {
			log.Printf("core not started: %v", err)
		}
	}
	// Persist traffic counters periodically so they survive restarts.
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for range tick.C {
			if err := st.SaveTraffic(mgr.TrafficRecords()); err != nil {
				log.Printf("save traffic: %v", err)
			}
		}
	}()

	handler := api.New(st, mgr, *dataDir, Version)
	fmt.Printf("%s\nPanel: http://%s  (data: %s)\n", Version, *addr, *dataDir)
	if st.Snapshot().AdminPassHash == "" {
		fmt.Println("First run: open the panel and create the admin account.")
	}
	log.Fatal(http.ListenAndServe(*addr, handler))
}
