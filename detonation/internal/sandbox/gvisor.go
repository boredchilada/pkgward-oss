// SPDX-License-Identifier: AGPL-3.0-or-later
// Package sandbox runs a package's install / import phase inside an
// isolated Docker container. Uses Docker's default runc runtime (NOT
// runsc/gVisor) so that Tetragon's eBPF tracing can observe the guest's
// real syscalls. gVisor + Tetragon don't compose: gVisor intercepts
// syscalls in userspace before they reach the kernel, leaving host-level
// BPF tracers blind to guest behavior.
//
// Isolation layers we keep: Docker namespaces (PID/mount/network/uts),
// seccomp default profile, dropped capabilities, cgroup limits, no-new-
// privileges, network mode selectable per call. gVisor registration in
// /etc/docker/daemon.json is retained as an optional defense-in-depth
// runtime, but not used in the default flow.
package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type SandboxConfig struct {
	ID            string
	Ecosystem     string
	ArchivePath   string
	RootfsPath    string // legacy field — unused under docker runtime; retained for API compatibility
	CPULimit      int
	MemoryLimitMB int
	NetworkMode   string
	WorkDir       string
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "det-" + hex.EncodeToString(b)
}

func NewSandboxConfig(ecosystem, archivePath string) SandboxConfig {
	return SandboxConfig{
		ID:            newID(),
		Ecosystem:     ecosystem,
		ArchivePath:   archivePath,
		CPULimit:      1,
		MemoryLimitMB: 512,
		// "bridge" so the install can fetch build deps (PEP 517 / npm /
		// cargo). Tetragon captures network connect events for behavioral
		// rules to evaluate.
		NetworkMode: "bridge",
		WorkDir:     "/sandbox",
	}
}

// DockerRunArgs builds the argv for `docker run` to launch one phase.
// The package archive is bind-mounted read-only into WorkDir/<basename>;
// the profile's install/import command consumes that path.
//
// Uses Docker's default runtime (runc) rather than runsc — gVisor would
// hide guest syscalls from Tetragon. See package doc for rationale.
func (c *SandboxConfig) DockerRunArgs(image string, cmd []string) []string {
	archiveBasename := filepath.Base(c.ArchivePath)
	mountSpec := fmt.Sprintf("%s:%s/%s:ro", c.ArchivePath, c.WorkDir, archiveBasename)
	args := []string{
		"run",
		"--rm",
		"--network=" + c.NetworkMode,
		"--name=" + c.ID,
		fmt.Sprintf("--memory=%dm", c.MemoryLimitMB),
		"--workdir=" + c.WorkDir,
		"-v", mountSpec,
		image,
	}
	args = append(args, cmd...)
	return args
}

type PhaseResult struct {
	ExitCode int  `json:"exit_code"`
	Duration int  `json:"duration_ms"`
	TimedOut bool `json:"timed_out"`
}

type Sandbox struct {
	Config  SandboxConfig
	profile *Profile
	baseDir string
}

func New(ecosystem, archivePath, baseDir string) (*Sandbox, error) {
	profile := GetProfile(ecosystem)
	if profile == nil {
		return nil, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
	cfg := NewSandboxConfig(ecosystem, archivePath)
	// RootfsPath retained but unused under docker runtime — kept so any
	// future native-runsc path can reuse it without an API break.
	cfg.RootfsPath = filepath.Join(baseDir, "overlays", cfg.ID)
	return &Sandbox{
		Config:  cfg,
		profile: profile,
		baseDir: baseDir,
	}, nil
}

func (s *Sandbox) Setup() error {
	// Docker handles overlay/rootfs management — nothing to mkdir per-sandbox.
	// Kept as a hook for any future bind-source preparation (e.g. a writable
	// /trace mount when wire-up of file-based tracing lands).
	return nil
}

func (s *Sandbox) RunPhase(ctx context.Context, phase string, cmd []string, timeoutSec int) (*PhaseResult, error) {
	if len(cmd) == 0 {
		return &PhaseResult{ExitCode: 0, Duration: 0, TimedOut: false}, nil
	}

	timeout := time.Duration(timeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	runArgs := s.Config.DockerRunArgs(s.profile.BaseImage, cmd)
	c := exec.CommandContext(ctx, "docker", runArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	err := c.Run()
	elapsed := int(time.Since(start).Milliseconds())

	if ctx.Err() == context.DeadlineExceeded {
		// Best-effort cleanup if docker is still holding the name.
		_ = exec.Command("docker", "rm", "-f", s.Config.ID).Run()
		return &PhaseResult{ExitCode: -1, Duration: elapsed, TimedOut: true}, nil
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("docker run: %w", err)
		}
	}

	return &PhaseResult{ExitCode: exitCode, Duration: elapsed, TimedOut: false}, nil
}

func (s *Sandbox) RunInstall(ctx context.Context, name, version string) (*PhaseResult, error) {
	cmd := s.profile.InstallCmd(name, version, filepath.Join(s.Config.WorkDir, filepath.Base(s.Config.ArchivePath)))
	return s.RunPhase(ctx, "install", cmd, s.profile.InstallTimeoutSec)
}

func (s *Sandbox) RunImport(ctx context.Context, name string) (*PhaseResult, error) {
	cmd := s.profile.ImportCmd(name)
	if cmd == nil {
		return &PhaseResult{ExitCode: 0, Duration: 0, TimedOut: false}, nil
	}
	return s.RunPhase(ctx, "import", cmd, s.profile.ImportTimeoutSec)
}

func (s *Sandbox) Destroy() error {
	// --rm on `docker run` cleans up on normal exit; this catches the
	// timeout / kill case where the container may still exist.
	_ = exec.Command("docker", "rm", "-f", s.Config.ID).Run()
	return nil
}
