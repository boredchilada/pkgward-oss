// Package intel loads detection-content data (sensitive path/env lists,
// shell binaries, per-ecosystem noise filters) from TOML files.
//
// At startup it always loads the embedded baseline (compiled into the
// binary). If PKGSENTRY_INTEL_PATH is set, it additionally loads any
// matching files under $PKGSENTRY_INTEL_PATH/detonation/ and UNION-merges
// their lists into the baseline. This mirrors the Python engine's
// pkgsentry/intel/__init__.py behavior — same env var, same merge model.
package intel

import (
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

//go:embed baseline/rules_data.toml baseline/noise_baseline.toml
var baselineFS embed.FS

// RulesData is the data half of the detonation behavioral rules.
// The closures that actually match these against trace events live in
// internal/rules — this struct is just the tunable inputs.
type RulesData struct {
	SensitivePathPrefixes []string `toml:"sensitive_path_prefixes"`
	SensitiveEnvPrefixes  []string `toml:"sensitive_env_prefixes"`
	ShellBinaries         []string `toml:"shell_binaries"`
}

// NoiseFilters is the per-ecosystem noise-event filter data.
// The Filter function in internal/baseline reads these to drop expected,
// normal pip/npm/cargo behavior from the trace stream.
type NoiseFilters struct {
	PypiFileNoise   []string `toml:"pypi_file_noise"`
	PypiExecNoise   []string `toml:"pypi_exec_noise"`
	NpmFileNoise    []string `toml:"npm_file_noise"`
	NpmExecNoise    []string `toml:"npm_exec_noise"`
	CratesFileNoise []string `toml:"crates_file_noise"`
	CratesExecNoise []string `toml:"crates_exec_noise"`
}

// Pack holds everything intel.Load() returns.
type Pack struct {
	Rules  RulesData
	Noise  NoiseFilters
	Source string // human-readable label: "baseline" or "baseline+overlay"
}

var loaded *Pack

// Load reads baseline + overlay, merges, and caches the result.
// Idempotent — subsequent calls return the same Pack.
func Load() *Pack {
	if loaded != nil {
		return loaded
	}

	pack := &Pack{Source: "baseline"}

	// Embedded baseline — always loaded.
	if err := unmarshalEmbedded("baseline/rules_data.toml", &pack.Rules); err != nil {
		log.Printf("intel: failed to parse embedded baseline rules_data.toml: %v", err)
	}
	if err := unmarshalEmbedded("baseline/noise_baseline.toml", &pack.Noise); err != nil {
		log.Printf("intel: failed to parse embedded baseline noise_baseline.toml: %v", err)
	}

	// Optional overlay from PKGSENTRY_INTEL_PATH/detonation/.
	overlayRoot := os.Getenv("PKGSENTRY_INTEL_PATH")
	if overlayRoot != "" {
		overlayDir := filepath.Join(overlayRoot, "detonation")
		if dirExists(overlayDir) {
			var overlayRules RulesData
			rulesPath := filepath.Join(overlayDir, "rules_data.toml")
			if fileExists(rulesPath) {
				if _, err := toml.DecodeFile(rulesPath, &overlayRules); err != nil {
					log.Printf("intel: failed to parse overlay %s: %v", rulesPath, err)
				} else {
					pack.Rules = mergeRules(pack.Rules, overlayRules)
					pack.Source = "baseline+overlay"
				}
			}
			var overlayNoise NoiseFilters
			noisePath := filepath.Join(overlayDir, "noise_baseline.toml")
			if fileExists(noisePath) {
				if _, err := toml.DecodeFile(noisePath, &overlayNoise); err != nil {
					log.Printf("intel: failed to parse overlay %s: %v", noisePath, err)
				} else {
					pack.Noise = mergeNoise(pack.Noise, overlayNoise)
					pack.Source = "baseline+overlay"
				}
			}
		}
	}

	log.Printf(
		"intel_loaded source=%s sensitive_paths=%d sensitive_envs=%d shells=%d pypi_file_noise=%d crates_file_noise=%d",
		pack.Source,
		len(pack.Rules.SensitivePathPrefixes),
		len(pack.Rules.SensitiveEnvPrefixes),
		len(pack.Rules.ShellBinaries),
		len(pack.Noise.PypiFileNoise),
		len(pack.Noise.CratesFileNoise),
	)

	loaded = pack
	return pack
}

// Current returns the loaded pack, calling Load() lazily if needed.
func Current() *Pack {
	if loaded == nil {
		return Load()
	}
	return loaded
}

// Reset clears the cached pack — test-only helper.
func Reset() {
	loaded = nil
}

func unmarshalEmbedded(name string, dst any) error {
	data, err := baselineFS.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read embedded %s: %w", name, err)
	}
	return toml.Unmarshal(data, dst)
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func mergeRules(base, overlay RulesData) RulesData {
	return RulesData{
		SensitivePathPrefixes: unionStrings(base.SensitivePathPrefixes, overlay.SensitivePathPrefixes),
		SensitiveEnvPrefixes:  unionStrings(base.SensitiveEnvPrefixes, overlay.SensitiveEnvPrefixes),
		ShellBinaries:         unionStrings(base.ShellBinaries, overlay.ShellBinaries),
	}
}

func mergeNoise(base, overlay NoiseFilters) NoiseFilters {
	return NoiseFilters{
		PypiFileNoise:   unionStrings(base.PypiFileNoise, overlay.PypiFileNoise),
		PypiExecNoise:   unionStrings(base.PypiExecNoise, overlay.PypiExecNoise),
		NpmFileNoise:    unionStrings(base.NpmFileNoise, overlay.NpmFileNoise),
		NpmExecNoise:    unionStrings(base.NpmExecNoise, overlay.NpmExecNoise),
		CratesFileNoise: unionStrings(base.CratesFileNoise, overlay.CratesFileNoise),
		CratesExecNoise: unionStrings(base.CratesExecNoise, overlay.CratesExecNoise),
	}
}

func unionStrings(base, overlay []string) []string {
	seen := make(map[string]struct{}, len(base)+len(overlay))
	out := make([]string, 0, len(base)+len(overlay))
	for _, v := range base {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range overlay {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
