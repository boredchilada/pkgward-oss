package pkitool

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"testing"
)

// Fixture: a base64-encoded native executable embedded in a *test* file so the
// parser can be exercised against a real PE header. The binary is decoded and
// written to a temp file, then PARSED (extractHeader) — it is never launched as a
// process; the file contains no subprocess or process-launch primitive at all.
// This is the smallstep/cli winpe_test.go shape: an embedded resource, not a dropper.
func TestExtract(t *testing.T) {
	tmp, err := os.CreateTemp("", "pkitool-parse-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	dec := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(sampleExe))
	if _, err := io.Copy(tmp, dec); err != nil {
		t.Fatal(err)
	}
	if err := extractHeader(tmp.Name()); err != nil {
		t.Fatal(err)
	}
}

// Synthetic PE (MZ magic + filler), base64-encoded — test fixture only.
var sampleExe = []byte(`TVqQAAMAAAAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABA=`)

func extractHeader(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hdr := make([]byte, 2)
	_, err = f.Read(hdr)
	return err
}
