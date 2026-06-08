// opengrep --test fixtures for buildrs_include_executable.
// Lines tagged `ruleid:` MUST match; `ok:` MUST NOT.

// ruleid: buildrs_include_executable
static PAYLOAD: &[u8] = include_bytes!("dropper.exe");

// ok: buildrs_include_executable
static TABLE: &[u8] = include_bytes!("lookup_table.bin");

fn main() {}
