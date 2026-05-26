// SPDX-License-Identifier: AGPL-3.0-or-later
package trace

import (
	"strings"
	"testing"
)

func TestParseProcessExec(t *testing.T) {
	raw := `{"process_exec":{"process":{"pid":12345,"binary":"/usr/bin/curl","arguments":"http://evil.com","ns":{"pid_for_children":99}},"parent":{"pid":12340,"binary":"/bin/sh"}},"node_name":"worker1","time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, 99)
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
}

func TestParseWrongNamespace(t *testing.T) {
	raw := `{"process_exec":{"process":{"pid":12345,"binary":"/usr/bin/curl","ns":{"pid_for_children":88}}},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, 99)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for wrong namespace, got %d", len(events))
	}
}

func TestParseKprobeConnect(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":12345,"binary":"/usr/bin/python3","ns":{"pid_for_children":99}},"function_name":"tcp_connect","args":[{"sock_arg":{"family":"AF_INET","type":"SOCK_STREAM","daddr":"45.33.32.156","dport":443}}]},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, 99)
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
	raw := `{"process_kprobe":{"process":{"pid":12345,"binary":"/usr/bin/python3","ns":{"pid_for_children":99}},"function_name":"__x64_sys_openat","args":[{"string_arg":"/root/.ssh/id_rsa"}]},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, 99)
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

func TestCollectFromReader(t *testing.T) {
	lines := strings.NewReader(
		`{"process_exec":{"process":{"pid":1,"binary":"/usr/bin/python3","ns":{"pid_for_children":99}}},"time":"2024-01-01T00:00:00Z"}` + "\n" +
			`{"process_exec":{"process":{"pid":2,"binary":"/usr/bin/curl","ns":{"pid_for_children":99}}},"time":"2024-01-01T00:00:01Z"}` + "\n" +
			`{"process_exec":{"process":{"pid":3,"binary":"/usr/bin/ls","ns":{"pid_for_children":88}}},"time":"2024-01-01T00:00:02Z"}` + "\n",
	)

	events := CollectFromReader(lines, 99)
	if len(events) != 2 {
		t.Errorf("expected 2 events (filtered by ns), got %d", len(events))
	}
}

func TestTargetNSZeroSkipsFiltering(t *testing.T) {
	// targetNS=0 means "accept all namespaces" — used when the host is
	// dedicated to detonation and the noise filter handles separation.
	lines := strings.NewReader(
		`{"process_exec":{"process":{"pid":1,"binary":"/usr/bin/python3","ns":{"pid_for_children":99}}},"time":"2024-01-01T00:00:00Z"}` + "\n" +
			`{"process_exec":{"process":{"pid":2,"binary":"/usr/bin/curl","ns":{"pid_for_children":88}}},"time":"2024-01-01T00:00:01Z"}` + "\n" +
			`{"process_exec":{"process":{"pid":3,"binary":"/usr/bin/ls","ns":{"pid_for_children":77}}},"time":"2024-01-01T00:00:02Z"}` + "\n",
	)
	events := CollectFromReader(lines, 0)
	if len(events) != 3 {
		t.Errorf("expected 3 events (no ns filtering), got %d", len(events))
	}
}
