# SPDX-License-Identifier: AGPL-3.0-or-later
# Build context = the detonation module root.
#   docker build -t pkgward-dnsforwarder -f deploy/dns-forwarder.Dockerfile .
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /dns-forwarder ./cmd/dns-forwarder

FROM scratch
COPY --from=build /dns-forwarder /dns-forwarder
# Runs as root inside the container's own user namespace so it can bind :53;
# it has no host privileges (rootless Docker).
ENTRYPOINT ["/dns-forwarder"]
