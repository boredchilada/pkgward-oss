BINARY := detonation-svc
GOOS := linux
GOARCH := amd64
VERSION := 0.1.0

.PHONY: build forwarder-image test lint clean deploy

build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -buildvcs=false -o bin/$(BINARY) ./cmd/detonation-svc/

# Build the DNS forwarder image. On the detonation host it must land in the
# *rootless* store, so run it as the detonation user with DOCKER_HOST pointing at
# the rootless socket (bootstrap.sh/setup.sh do this automatically on deploy).
forwarder-image:
	docker build -t pkgward-dnsforwarder -f deploy/dns-forwarder.Dockerfile .

test:
	go test ./... -v

test-short:
	go test ./... -short

lint:
	go vet ./...

clean:
	rm -rf bin/

# Deploy to a remote host. Override DEPLOY_TARGET on the command line:
#   make deploy DEPLOY_TARGET=user@host
DEPLOY_TARGET ?= $(error DEPLOY_TARGET not set — pass DEPLOY_TARGET=user@host)

deploy: build
	scp bin/$(BINARY) $(DEPLOY_TARGET):/home/detonation/bin/$(BINARY)
	ssh $(DEPLOY_TARGET) 'sudo systemctl restart detonation-svc'
