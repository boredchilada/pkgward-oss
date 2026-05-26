// SPDX-License-Identifier: AGPL-3.0-or-later
package trace

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"
)

type tetragonEvent struct {
	ProcessExec   *tetragonProcessExec   `json:"process_exec,omitempty"`
	ProcessKprobe *tetragonProcessKprobe `json:"process_kprobe,omitempty"`
	Time          string                 `json:"time"`
}

type tetragonProcessExec struct {
	Process tetragonProcess  `json:"process"`
	Parent  *tetragonProcess `json:"parent,omitempty"`
}

type tetragonProcessKprobe struct {
	Process      tetragonProcess     `json:"process"`
	FunctionName string              `json:"function_name"`
	Args         []tetragonKprobeArg `json:"args"`
}

type tetragonProcess struct {
	PID       int               `json:"pid"`
	Binary    string            `json:"binary"`
	Arguments string            `json:"arguments"`
	NS        tetragonNamespace `json:"ns"`
}

type tetragonNamespace struct {
	PIDForChildren int `json:"pid_for_children"`
}

type tetragonKprobeArg struct {
	SockArg   *tetragonSockArg `json:"sock_arg,omitempty"`
	StringArg string           `json:"string_arg,omitempty"`
	IntArg    *int64           `json:"int_arg,omitempty"`
	FileArg   *tetragonFileArg `json:"file_arg,omitempty"`
}

// tetragonFileArg is how Tetragon renders a `type: file` argument (e.g. the
// first arg of security_file_permission). The path lives under "path".
type tetragonFileArg struct {
	Path string `json:"path"`
}

type tetragonSockArg struct {
	Family string `json:"family"`
	Type   string `json:"type"`
	DAddr  string `json:"daddr"`
	DPort  int    `json:"dport"`
}

func ParseTetragonLine(line string, targetNS int) ([]TraceEvent, error) {
	var raw tetragonEvent
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, err
	}

	var events []TraceEvent

	if raw.ProcessExec != nil {
		proc := raw.ProcessExec.Process
		if proc.NS.PIDForChildren != targetNS {
			return nil, nil
		}
		events = append(events, TraceEvent{
			Category:  "process",
			Operation: "exec",
			PID:       proc.PID,
			Binary:    proc.Binary,
			Timestamp: raw.Time,
			Detail: map[string]interface{}{
				"binary":    proc.Binary,
				"arguments": proc.Arguments,
			},
		})
	}

	if raw.ProcessKprobe != nil {
		proc := raw.ProcessKprobe.Process
		if proc.NS.PIDForChildren != targetNS {
			return nil, nil
		}

		fn := raw.ProcessKprobe.FunctionName

		switch {
		case fn == "tcp_connect" || fn == "udp_sendmsg":
			for _, arg := range raw.ProcessKprobe.Args {
				if arg.SockArg != nil {
					events = append(events, TraceEvent{
						Category:  "network",
						Operation: "connect",
						PID:       proc.PID,
						Binary:    proc.Binary,
						Timestamp: raw.Time,
						Detail: map[string]interface{}{
							"addr":   arg.SockArg.DAddr,
							"port":   float64(arg.SockArg.DPort),
							"family": arg.SockArg.Family,
						},
					})
				}
			}

		case fn == "__x64_sys_openat" || fn == "security_file_open":
			for _, arg := range raw.ProcessKprobe.Args {
				if arg.StringArg != "" {
					events = append(events, TraceEvent{
						Category:  "file",
						Operation: "open",
						PID:       proc.PID,
						Binary:    proc.Binary,
						Timestamp: raw.Time,
						Detail: map[string]interface{}{
							"path": arg.StringArg,
						},
					})
				}
			}

		case fn == "__x64_sys_write" || fn == "security_file_permission":
			// security_file_permission carries the path as a file arg, not a
			// string arg; __x64_sys_write uses a string arg. Accept either.
			for _, arg := range raw.ProcessKprobe.Args {
				path := arg.StringArg
				if path == "" && arg.FileArg != nil {
					path = arg.FileArg.Path
				}
				if path != "" {
					events = append(events, TraceEvent{
						Category:  "file",
						Operation: "write",
						PID:       proc.PID,
						Binary:    proc.Binary,
						Timestamp: raw.Time,
						Detail: map[string]interface{}{
							"path": path,
						},
					})
				}
			}

		case fn == "sys_ptrace" || fn == "__x64_sys_process_vm_writev":
			// dyn_proc_inject keys off Operation "ptrace"/"process_vm_writev".
			// process_vm_writev has no bare kernel symbol, so the policy hooks
			// the syscall form; normalize both names to the rule's vocabulary.
			op := "ptrace"
			if fn == "__x64_sys_process_vm_writev" {
				op = "process_vm_writev"
			}
			events = append(events, TraceEvent{
				Category:  "process",
				Operation: op,
				PID:       proc.PID,
				Binary:    proc.Binary,
				Timestamp: raw.Time,
				Detail:    map[string]interface{}{},
			})

		case fn == "__x64_sys_memfd_create":
			// Anonymous executable memory — a building block of fileless exec.
			name := ""
			for _, arg := range raw.ProcessKprobe.Args {
				if arg.StringArg != "" {
					name = arg.StringArg
					break
				}
			}
			events = append(events, TraceEvent{
				Category:  "process",
				Operation: "memfd_create",
				PID:       proc.PID,
				Binary:    proc.Binary,
				Timestamp: raw.Time,
				Detail:    map[string]interface{}{"name": name},
			})

		case fn == "__x64_sys_execveat":
			// Policy filters to AT_EMPTY_PATH, i.e. execve directly from an fd
			// (often a memfd) with no backing file on disk — fileless exec.
			events = append(events, TraceEvent{
				Category:  "process",
				Operation: "fileless_exec",
				PID:       proc.PID,
				Binary:    proc.Binary,
				Timestamp: raw.Time,
				Detail:    map[string]interface{}{},
			})
		}
	}

	return events, nil
}

func CollectFromReader(r io.Reader, targetNS int) []TraceEvent {
	var all []TraceEvent
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		events, err := ParseTetragonLine(line, targetNS)
		if err != nil {
			continue
		}
		all = append(all, events...)
	}
	return all
}

// CollectFromTetragonLog reads a Tetragon JSONL log and returns all
// events with `time` between since and until (inclusive). Pass targetNS=0
// to skip PID-namespace filtering — useful when the host is dedicated to
// detonation and the noise filter handles container-vs-host separation.
func CollectFromTetragonLog(path string, since, until time.Time, targetNS int) []TraceEvent {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []TraceEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Cheap timestamp pre-check before full JSON parse — Tetragon's
		// `time` field is RFC3339Nano and appears near the start of each
		// line. Find it and short-circuit if it's outside the window.
		if t, ok := extractTetragonTime(line); ok {
			if t.Before(since) || t.After(until) {
				continue
			}
		}

		events, err := ParseTetragonLine(line, targetNS)
		if err != nil {
			continue
		}
		out = append(out, events...)
	}
	return out
}

func extractTetragonTime(line string) (time.Time, bool) {
	idx := strings.Index(line, `"time":"`)
	if idx < 0 {
		return time.Time{}, false
	}
	start := idx + len(`"time":"`)
	end := strings.IndexByte(line[start:], '"')
	if end <= 0 {
		return time.Time{}, false
	}
	ts := line[start : start+end]
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
