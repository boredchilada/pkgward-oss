// SPDX-License-Identifier: AGPL-3.0-or-later
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"detonation/internal/baseline"
	"detonation/internal/rules"
	"detonation/internal/sandbox"
	"detonation/internal/trace"
)

type Config struct {
	MaxConcurrent   int
	BaseDir         string
	SocketPath      string
	ListenAddr      string
	TetragonLogPath string
}

type Server struct {
	config Config
	mux    *http.ServeMux
	engine *rules.Engine
	active atomic.Int32
	mu     sync.Mutex
}

type DetonateRequest struct {
	Ecosystem      string `json:"ecosystem"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	ArchivePath    string `json:"archive_path"`
	ArchiveKind    string `json:"archive_kind"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

type DetonateResponse struct {
	ID           string                 `json:"id"`
	Status       string                 `json:"status"`
	InstallPhase *sandbox.PhaseResult   `json:"install_phase,omitempty"`
	ImportPhase  *sandbox.PhaseResult   `json:"import_phase,omitempty"`
	Findings     []trace.DynFinding     `json:"findings"`
	TraceEvents  []trace.TraceEvent     `json:"trace_events"`
	TraceSummary map[string]interface{} `json:"trace_summary"`
}

func NewServer(cfg Config) *Server {
	s := &Server{
		config: cfg,
		mux:    http.NewServeMux(),
		engine: rules.NewEngine(rules.AllRules()),
	}
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/detonate", s.handleDetonate)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}
	resp := map[string]interface{}{
		"status":             "ok",
		"active_detonations": s.active.Load(),
		"max_concurrent":     s.config.MaxConcurrent,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleDetonate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}

	var req DetonateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), 400)
		return
	}
	if req.Ecosystem == "" || req.Name == "" || req.Version == "" || req.ArchivePath == "" {
		http.Error(w, "missing required fields: ecosystem, name, version, archive_path", 400)
		return
	}

	profile := sandbox.GetProfile(req.Ecosystem)
	if profile == nil {
		http.Error(w, fmt.Sprintf("unsupported ecosystem: %s", req.Ecosystem), 400)
		return
	}

	if int(s.active.Load()) >= s.config.MaxConcurrent {
		http.Error(w, "too many concurrent detonations", 429)
		return
	}

	s.active.Add(1)
	defer s.active.Add(-1)

	resp := s.runDetonation(r.Context(), req)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) runDetonation(ctx context.Context, req DetonateRequest) DetonateResponse {
	sb, err := sandbox.New(req.Ecosystem, req.ArchivePath, s.config.BaseDir)
	if err != nil {
		return DetonateResponse{Status: "error", Findings: []trace.DynFinding{},
			TraceSummary: map[string]interface{}{"error": err.Error()}}
	}

	if err := sb.Setup(); err != nil {
		return DetonateResponse{ID: sb.Config.ID, Status: "error", Findings: []trace.DynFinding{},
			TraceSummary: map[string]interface{}{"error": "setup failed: " + err.Error()}}
	}
	defer sb.Destroy()

	// Mark the window we'll use to filter Tetragon events.
	traceStart := time.Now().UTC()

	installResult, err := sb.RunInstall(ctx, req.Name, req.Version)
	if err != nil {
		return DetonateResponse{
			ID: sb.Config.ID, Status: "error",
			Findings:     []trace.DynFinding{},
			TraceSummary: map[string]interface{}{"error": "install failed: " + err.Error()},
		}
	}
	// Boundary between the install and import phases — events on or before this
	// instant are attributed to install, later events to import.
	installEnd := time.Now().UTC()

	importResult, err := sb.RunImport(ctx, req.Name)
	if err != nil {
		importResult = &sandbox.PhaseResult{ExitCode: -1, Duration: 0, TimedOut: false}
	}
	importEnd := time.Now().UTC()

	// Trace events: read Tetragon's JSONL log filtered to the install/import
	// time window. targetNS=0 skips PID-namespace filtering — the noise
	// filter strips pip/cargo/npm host activity, the host is otherwise idle.
	rawEvents := trace.CollectFromTetragonLog(
		s.config.TetragonLogPath,
		traceStart,
		importEnd,
		0,
	)
	// Tag each event with its phase before rule evaluation — dyn_install_exfil
	// and dyn_import_exfil key off TraceEvent.Phase, which the collector leaves
	// empty.
	trace.AssignPhase(rawEvents, installEnd)
	filtered := baseline.Filter(req.Ecosystem, rawEvents)
	findings := s.engine.Evaluate(filtered)
	if findings == nil {
		findings = []trace.DynFinding{}
	}

	status := "completed"
	if installResult.TimedOut || (importResult != nil && importResult.TimedOut) {
		status = "timeout"
	}

	categoryCounts := map[string]int{}
	for _, evt := range filtered {
		categoryCounts[evt.Category]++
	}

	return DetonateResponse{
		ID:           sb.Config.ID,
		Status:       status,
		InstallPhase: installResult,
		ImportPhase:  importResult,
		Findings:     findings,
		TraceEvents:  filtered,
		TraceSummary: map[string]interface{}{
			"total_events":       len(rawEvents),
			"events_by_category": categoryCounts,
		},
	}
}

func (s *Server) ListenAndServe() error {
	httpServer := &http.Server{Handler: s}

	if s.config.SocketPath != "" {
		os.Remove(s.config.SocketPath)
		ln, err := net.Listen("unix", s.config.SocketPath)
		if err != nil {
			return fmt.Errorf("listen unix %s: %w", s.config.SocketPath, err)
		}
		os.Chmod(s.config.SocketPath, 0o660)
		log.Printf("listening on unix://%s", s.config.SocketPath)
		return httpServer.Serve(ln)
	}

	addr := s.config.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:9100"
	}
	log.Printf("listening on %s", addr)
	httpServer.Addr = addr
	return httpServer.ListenAndServe()
}
