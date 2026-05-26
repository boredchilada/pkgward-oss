// SPDX-License-Identifier: AGPL-3.0-or-later
package trace

import (
	"testing"
	"time"
)

func TestAssignPhase(t *testing.T) {
	installEnd := time.Date(2024, 1, 1, 0, 0, 10, 0, time.UTC)
	events := []TraceEvent{
		{Timestamp: "2024-01-01T00:00:05Z"}, // before boundary -> install
		{Timestamp: "2024-01-01T00:00:10Z"}, // exactly boundary -> install
		{Timestamp: "2024-01-01T00:00:15Z"}, // after boundary -> import
		{Timestamp: "not-a-timestamp"},      // unparseable -> install (conservative)
	}

	AssignPhase(events, installEnd)

	want := []string{"install", "install", "import", "install"}
	for i, w := range want {
		if events[i].Phase != w {
			t.Errorf("event %d phase = %q, want %q", i, events[i].Phase, w)
		}
	}
}

func TestParseKprobePtraceNormalizesOperation(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":12345,"binary":"/usr/bin/python3","ns":{"pid_for_children":99}},"function_name":"sys_ptrace","args":[{"int_arg":16}]},"time":"2024-01-01T00:00:00Z"}`

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
	// dyn_proc_inject keys off Operation "ptrace", not the raw syscall name.
	if events[0].Operation != "ptrace" {
		t.Errorf("operation = %q, want ptrace", events[0].Operation)
	}
}

func TestParseSecurityFilePermissionFileArg(t *testing.T) {
	// security_file_permission carries the path as a file_arg, not string_arg.
	raw := `{"process_kprobe":{"process":{"pid":12345,"binary":"/usr/bin/python3","ns":{"pid_for_children":99}},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/root/.bashrc"}},{"int_arg":2}]},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, 99)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Category != "file" || events[0].Operation != "write" {
		t.Errorf("got %s/%s, want file/write", events[0].Category, events[0].Operation)
	}
	if path, _ := events[0].Detail["path"].(string); path != "/root/.bashrc" {
		t.Errorf("path = %q, want /root/.bashrc", path)
	}
}

func TestParseMemfdCreate(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":12345,"binary":"/usr/bin/python3","ns":{"pid_for_children":99}},"function_name":"__x64_sys_memfd_create","args":[{"string_arg":"payload"},{"int_arg":1}]},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, 99)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 || events[0].Operation != "memfd_create" {
		t.Fatalf("expected process/memfd_create, got %+v", events)
	}
	if name, _ := events[0].Detail["name"].(string); name != "payload" {
		t.Errorf("name = %q, want payload", name)
	}
}

func TestParseExecveatFileless(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":12345,"binary":"/usr/bin/python3","ns":{"pid_for_children":99}},"function_name":"__x64_sys_execveat","args":[{"int_arg":3},{"string_arg":""},{"int_arg":4096}]},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, 99)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 || events[0].Operation != "fileless_exec" {
		t.Fatalf("expected process/fileless_exec, got %+v", events)
	}
}

func TestParseKprobeProcessVmWritev(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":12345,"binary":"/usr/bin/python3","ns":{"pid_for_children":99}},"function_name":"__x64_sys_process_vm_writev","args":[]},"time":"2024-01-01T00:00:00Z"}`

	events, err := ParseTetragonLine(raw, 99)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Operation != "process_vm_writev" {
		t.Errorf("operation = %q, want process_vm_writev", events[0].Operation)
	}
}
