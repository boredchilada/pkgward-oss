// SPDX-License-Identifier: AGPL-3.0-or-later
package sandbox

import "detonation/internal/honeytokens"

// decoyEnvArgs plants the decoy-credential environment (see internal/honeytokens).
// Container env never appears in a guest exec argv, so it's safe for the canary.
func decoyEnvArgs() []string {
	return honeytokens.EnvArgs()
}

// decoyFileMounts bind-mounts the shared host decoy home (read-only) into the
// guest. Nothing is written inside the container, so no decoy value lands in an
// exec argv (which would false-trigger dyn_honeytoken_exfil on our own seeding).
func decoyFileMounts(decoyHome, workDir string) []string {
	if decoyHome == "" {
		return nil
	}
	return honeytokens.FileMounts(decoyHome, workDir)
}
