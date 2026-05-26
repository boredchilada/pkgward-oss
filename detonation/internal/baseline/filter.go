// SPDX-License-Identifier: AGPL-3.0-or-later
package baseline

import (
	"strings"

	"detonation/internal/intel"
	"detonation/internal/trace"
)

func isNoisyFile(path string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

func isNoisyExec(binary string, patterns []string) bool {
	for _, p := range patterns {
		if strings.HasSuffix(binary, p) || strings.Contains(binary, p) {
			return true
		}
	}
	return false
}

func Filter(ecosystem string, events []trace.TraceEvent) []trace.TraceEvent {
	noise := intel.Current().Noise
	var fileNoise, execNoise []string

	switch ecosystem {
	case "pypi":
		fileNoise = noise.PypiFileNoise
		execNoise = noise.PypiExecNoise
	case "npm":
		fileNoise = noise.NpmFileNoise
		execNoise = noise.NpmExecNoise
	case "crates":
		fileNoise = noise.CratesFileNoise
		execNoise = noise.CratesExecNoise
	default:
		return events
	}

	var out []trace.TraceEvent
	for _, evt := range events {
		if evt.Category == "file" {
			path, _ := evt.Detail["path"].(string)
			if isNoisyFile(path, fileNoise) {
				continue
			}
		}
		if evt.Category == "process" && evt.Operation == "exec" {
			binary, _ := evt.Detail["binary"].(string)
			if isNoisyExec(binary, execNoise) {
				continue
			}
		}
		out = append(out, evt)
	}
	return out
}
