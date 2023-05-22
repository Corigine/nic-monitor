SHELL = /bin/bash

REGISTRY = corigine
RELEASE_TAG = $(shell cat VERSION)
VERSION = $(shell echo $${VERSION:-$(RELEASE_TAG)})
COMMIT = git-$(shell git rev-parse --short HEAD)
DATE = $(shell date +"%Y-%m-%d_%H:%M:%S")
GOLDFLAGS = "-w -s -extldflags '-z now' -X github.com/corigine/nic-monitor/versions.COMMIT=$(COMMIT) -X github.com/corigine/nic-monitor/versions.VERSION=$(RELEASE_TAG) -X github.com/corigine/nic-monitor/versions.BUILDDATE=$(DATE)"

# ARCH could be amd64,arm64
ARCH = amd64

.PHONY: build-go
build-go:
	go mod tidy
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=pie -o $(CURDIR)/images/nic-monitor -ldflags $(GOLDFLAGS) -v ./daemon
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=pie -o $(CURDIR)/images/flow -ldflags $(GOLDFLAGS) -v ./flow

.PHONY: build-go-arm
build-go-arm:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -buildmode=pie -o $(CURDIR)/images/nic-monitor -ldflags $(GOLDFLAGS) -v ./flow
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -buildmode=pie -o $(CURDIR)/images/flow -ldflags $(GOLDFLAGS) -v ./daemon

.PHONY: nic-monitor
nic-monitor:
	docker buildx build --platform linux/amd64 --build-arg ARCH=amd64 -t $(REGISTRY)/nic-monitor:$(RELEASE_TAG) -o type=docker -f Dockerfile images/

.PHONY: release
release: lint nic_monitor

.PHONY: release-arm
release-arm: build-go-arm
	docker buildx build --platform linux/arm64 --build-arg ARCH=arm64 -t $(REGISTRY)/nic-monitor:$(RELEASE_TAG) -o type=docker -f Dockerfile images/

.PHONY: push-release
push-release: release
	docker push $(REGISTRY)/kube-ovn:$(RELEASE_TAG)

.PHONY: lint
lint:
	@gofmt -d .
	@if [ $$(gofmt -l . | wc -l) -ne 0 ]; then \
		echo "Code differs from gofmt's style" 1>&2 && exit 1; \
	fi
	@GOOS=linux go vet ./...
	@GOOS=linux gosec -exclude=G204,G306,G404,G601,G301 -exclude-dir=test -exclude-dir=pkg/client ./...

.PHONY: scan
scan:
	trivy image --exit-code=1 --ignore-unfixed --security-checks vuln $(REGISTRY)/nic-monitor:$(RELEASE_TAG)

.PHONY: clean
clean:
	$(RM) images/*

