// SPDX-License-Identifier: AGPL-3.0-or-later
package dnslog

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// Manager runs the dns-forwarder container on the detonation bridge network and
// resolves connect-destination IPs back to the hostnames the sandbox looked up.
//
// Lookups go over the rootless Docker socket (`docker exec det-dnslog
// /dns-forwarder lookup <ip>`), NOT a host TCP port. The detonation service runs
// as a confined systemd unit (init_t) which the host denies from connecting to
// rootless-published loopback ports (EACCES), while the docker control channel it
// already uses to run sandboxes works fine — so we reuse it for lookups too.
//
// Best-effort by design: if the forwarder can't be started, Enabled() is false,
// sandboxes fall back to a public resolver, and the DNS-aware filter degrades to
// IP matching. It can never break detonation.
type Manager struct {
	containerName string
	image         string
	binPath       string // forwarder binary path inside the container
	bridgeIP      string // forwarder's bridge IP — sandboxes are pointed here via --dns
	enabled       bool
}

// StartManager (re)creates the forwarder container and discovers its bridge IP.
// Returns a disabled Manager (not an error) if anything fails — detonation must
// keep working without DNS capture.
func StartManager(image string) *Manager {
	m := &Manager{
		containerName: "det-dnslog",
		image:         image,
		binPath:       "/dns-forwarder",
	}
	if image == "" {
		return m
	}
	_ = run("docker", "rm", "-f", m.containerName) // clear any stale instance
	if out, err := runOut("docker", "run", "-d", "--name", m.containerName,
		"--network", "bridge", "--restart", "unless-stopped", m.image); err != nil {
		log.Printf("dnslog: forwarder run failed: %v: %s", err, out)
		return m // disabled
	}
	// Wait for the bridge IP to be assigned — rootless Docker populates it a beat
	// after `run -d` returns.
	var ip string
	for i := 0; i < 20; i++ {
		ip, _ = inspect(m.containerName, "{{.NetworkSettings.Networks.bridge.IPAddress}}")
		if ip != "" {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if ip == "" {
		log.Printf("dnslog: forwarder bridge IP not ready")
		return m
	}
	m.bridgeIP = ip
	m.enabled = true
	return m
}

// Enabled reports whether DNS capture is live.
func (m *Manager) Enabled() bool { return m != nil && m.enabled }

// DNSServer returns the forwarder's bridge IP to pass to a sandbox via --dns, or
// "" if disabled.
func (m *Manager) DNSServer() string {
	if !m.Enabled() {
		return ""
	}
	return m.bridgeIP
}

// Lookup returns the hostname the sandbox resolved for a destination IP, querying
// the running forwarder's in-memory map via `docker exec`. Fails safe.
func (m *Manager) Lookup(ip string) (string, bool) {
	if !m.Enabled() || ip == "" {
		return "", false
	}
	out, err := dockerExecOut(m.containerName, m.binPath, "lookup", ip)
	if err != nil {
		return "", false
	}
	// stdout is "<ip> <host>" (empty when the IP isn't in the map).
	fields := strings.Fields(out)
	if len(fields) >= 2 && fields[0] == ip {
		return fields[1], true
	}
	return "", false
}

// Stop removes the forwarder container.
func (m *Manager) Stop() {
	if m != nil && m.containerName != "" {
		_ = run("docker", "rm", "-f", m.containerName)
	}
}

func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

func runOut(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func inspect(container, format string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", format, container).Output()
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", container, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func dockerExecOut(container string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	full := append([]string{"exec", container}, args...)
	out, err := exec.CommandContext(ctx, "docker", full...).Output()
	return strings.TrimSpace(string(out)), err
}
