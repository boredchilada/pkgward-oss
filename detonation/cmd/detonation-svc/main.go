// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"detonation/internal/api"
	"detonation/internal/intel"
)

func main() {
	socketPath := flag.String("socket", "/var/run/detonation/detonation.sock", "UNIX socket path")
	listenAddr := flag.String("listen", "", "TCP listen address (overrides socket)")
	baseDir := flag.String("base-dir", "/var/lib/detonation", "base directory for overlays and traces")
	maxConcurrent := flag.Int("max-concurrent", 2, "max concurrent detonations")
	tetragonLog := flag.String("tetragon-log", "/var/log/tetragon/tetragon.log",
		"Tetragon JSONL export log path (read for trace events during each detonation)")
	flag.Parse()

	// Load intel pack (baseline + optional PKGSENTRY_INTEL_PATH overlay).
	intel.Load()

	cfg := api.Config{
		MaxConcurrent:   *maxConcurrent,
		BaseDir:         *baseDir,
		TetragonLogPath: *tetragonLog,
	}

	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	} else {
		cfg.SocketPath = *socketPath
	}

	srv := api.NewServer(cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down")
		os.Exit(0)
	}()

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
