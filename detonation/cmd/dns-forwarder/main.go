// SPDX-License-Identifier: AGPL-3.0-or-later
//
// dns-forwarder runs inside a container on the detonation bridge network. The
// detonation sandboxes are pointed at it (`docker run --dns <this>`), so every
// name a package resolves passes through here. It forwards each query verbatim
// to an upstream resolver and records resolved-IP -> hostname, served over a
// small in-container HTTP API the detonation service queries via `docker exec`
// (the `lookup` subcommand) to tag each outbound connect with the *domain* it
// resolved.
//
// It must run as a container (not in the detonation service) because the rootless
// Docker bridge gateway lives inside the rootlesskit network namespace, which the
// host-side service can't bind.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"detonation/internal/dnslog"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// runLookup is the client side of `docker exec det-dnslog /dns-forwarder lookup
// <ip>...`. It queries the running server's in-memory map over the container's
// own loopback and prints "<ip> <host>" per resolved IP. The detonation service
// invokes this over the docker socket instead of a host TCP port — the confined
// service is denied from connecting to rootless-published loopback ports.
func runLookup(ips []string) {
	httpAddr := env("DNS_HTTP", ":8080")
	base := "http://127.0.0.1" + httpAddr
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	for _, ip := range ips {
		resp, err := client.Get(base + "/lookup?ip=" + ip)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			if host := strings.TrimSpace(string(b)); host != "" {
				fmt.Printf("%s %s\n", ip, host)
			}
		}
		resp.Body.Close()
	}
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "lookup" {
		runLookup(os.Args[2:])
		return
	}

	listen := env("DNS_LISTEN", ":53")     // bridge-reachable DNS
	upstream := env("DNS_UPSTREAM", "1.1.1.1:53")
	httpAddr := env("DNS_HTTP", ":8080")   // lookup API (queried in-container via docker exec)

	fwd, err := dnslog.New(listen, upstream)
	if err != nil {
		log.Fatalf("dns-forwarder: listen %s: %v", listen, err)
	}
	go fwd.Serve()
	log.Printf("dns-forwarder: DNS on %s -> %s, lookup API on %s", listen, upstream, httpAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/lookup", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if host, ok := fwd.Lookup(ip); ok {
			_, _ = w.Write([]byte(host))
			return
		}
		http.Error(w, "", http.StatusNotFound)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	log.Fatal(http.ListenAndServe(httpAddr, mux))
}
