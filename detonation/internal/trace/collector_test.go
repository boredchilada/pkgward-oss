// SPDX-License-Identifier: AGPL-3.0-or-later
package trace

import (
	"strings"
	"testing"
)

const sandboxCID = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"

// Tetragon truncates the container id; the sandbox cidfile yields the full id.
const sandboxCIDShort = "abc123def456abc123def456abc123"

func TestParseProcessExec(t *testing.T) {
	raw := `{"process_exec":{"process":{"pid":12345,"binary":"/usr/bin/curl","arguments":"http://evil.com","docker":"` + sandboxCIDShort + `"},"parent":{"pid":12340,"binary":"/bin/sh"}},"node_name":"worker1","time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, []string{sandboxCID})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Category != "process" {
		t.Errorf("category = %q, want process", events[0].Category)
	}
	if events[0].Operation != "exec" {
		t.Errorf("operation = %q, want exec", events[0].Operation)
	}
	binary, _ := events[0].Detail["binary"].(string)
	if binary != "/usr/bin/curl" {
		t.Errorf("binary = %q, want /usr/bin/curl", binary)
	}
	if events[0].Docker != sandboxCIDShort {
		t.Errorf("docker = %q, want %q", events[0].Docker, sandboxCIDShort)
	}
}

func TestParseForeignContainerDropped(t *testing.T) {
	raw := `{"process_exec":{"process":{"pid":12345,"binary":"/usr/bin/curl","docker":"ffffffffffffffffffffffffffffff"}},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, []string{sandboxCID})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for a foreign container, got %d", len(events))
	}
}

func TestParseEmptyContainerSetKeepsAll(t *testing.T) {
	raw := `{"process_exec":{"process":{"pid":12345,"binary":"/usr/bin/curl","docker":"whatever"}},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("empty container set should keep all events, got %d", len(events))
	}
}

func TestParseKprobeConnect(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":12345,"binary":"/usr/bin/python3","docker":"` + sandboxCIDShort + `"},"function_name":"tcp_connect","args":[{"sock_arg":{"family":"AF_INET","type":"SOCK_STREAM","daddr":"45.33.32.156","dport":443}}]},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, []string{sandboxCID})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Category != "network" {
		t.Errorf("category = %q, want network", events[0].Category)
	}
	if events[0].Operation != "connect" {
		t.Errorf("operation = %q, want connect", events[0].Operation)
	}
	addr, _ := events[0].Detail["addr"].(string)
	if addr != "45.33.32.156" {
		t.Errorf("addr = %q, want 45.33.32.156", addr)
	}
}

func TestParseKprobeFileOpen(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":12345,"binary":"/usr/bin/python3","docker":"` + sandboxCIDShort + `"},"function_name":"__x64_sys_openat","args":[{"string_arg":"/root/.ssh/id_rsa"}]},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, []string{sandboxCID})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Category != "file" {
		t.Errorf("category = %q, want file", events[0].Category)
	}
	if events[0].Operation != "open" {
		t.Errorf("operation = %q, want open", events[0].Operation)
	}
}

// Regression for the Azure cross-container FP: a gomod sandbox got blamed for a
// concurrent npm container's /root/.npmrc read (and the scanner's own opengrep
// activity) because trace events were not attributed per container. Only the
// sandbox's own events must survive.
func TestCollectFiltersForeignContainers(t *testing.T) {
	const npmCID = "1111111111111111111111111111111"
	const scannerCID = "2222222222222222222222222222222"
	lines := strings.NewReader(
		`{"process_exec":{"process":{"pid":1,"binary":"/usr/local/go/bin/go","docker":"` + sandboxCIDShort + `"}},"time":"2024-01-01T00:00:01Z"}` + "\n" +
			`{"process_kprobe":{"process":{"pid":2,"binary":"/usr/bin/node","docker":"` + npmCID + `"},"function_name":"__x64_sys_openat","args":[{"string_arg":"/root/.npmrc"}]},"time":"2024-01-01T00:00:02Z"}` + "\n" +
			`{"process_exec":{"process":{"pid":3,"binary":"/root/.cache/opengrep/bin/opengrep-core","docker":"` + scannerCID + `"}},"time":"2024-01-01T00:00:03Z"}` + "\n",
	)

	events := CollectFromReader(lines, []string{sandboxCID})
	if len(events) != 1 {
		t.Fatalf("expected only the sandbox's 1 event, got %d", len(events))
	}
	if events[0].Docker != sandboxCIDShort {
		t.Errorf("surviving event docker = %q, want sandbox %q", events[0].Docker, sandboxCIDShort)
	}
}
