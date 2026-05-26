// SPDX-License-Identifier: AGPL-3.0-or-later
package trace

import "time"

// AssignPhase tags each event's Phase by comparing its Timestamp against the
// install/import boundary. Events at or before installEnd belong to the
// "install" phase; later events belong to "import". Events whose Timestamp
// cannot be parsed default to "install" — the conservative choice, since
// install-phase findings (e.g. dyn_install_exfil) score as critical rather
// than high.
//
// This is the single point where Phase is set: the collector emits events
// with an empty Phase, and the rules in internal/rules key off it
// (dyn_install_exfil vs dyn_import_exfil), so detonation server must call this
// after collecting the combined window and before evaluating rules.
func AssignPhase(events []TraceEvent, installEnd time.Time) {
	for i := range events {
		t, err := time.Parse(time.RFC3339Nano, events[i].Timestamp)
		if err != nil || !t.After(installEnd) {
			events[i].Phase = "install"
			continue
		}
		events[i].Phase = "import"
	}
}
