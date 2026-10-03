BINARY  := nyxr
PKG     := ./cmd/nyxr
PACKETD := nyxr-packetd
PACKETD_PKG := ./cmd/nyxr-packetd
DIST    := dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

GO      ?= go
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
LINUX_ARCHES := amd64 arm64
NFPM    ?= $(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0
# deb/rpm need a semantic version; untagged builds fall back to 0.0.0-dev.
PKG_VERSION := $(shell v='$(VERSION)'; v=$${v\#v}; case "$$v" in ([0-9]*.[0-9]*.[0-9]*) echo "$$v" ;; (*) echo 0.0.0-dev ;; esac)

export CGO_ENABLED := 0

.PHONY: all build install uninstall test vet check fuzz benchmark cross linux-packages package checksums clean help

all: check build

## build: build nyxr and nyxr-packetd for the host platform
build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(PACKETD) $(PACKETD_PKG)

## install: copy built binaries into $(DESTDIR)$(BINDIR) (run `make build` first)
install:
	@for f in $(BINARY) $(PACKETD); do \
		[ -f $$f ] || { echo "$$f not built; run 'make build' first" >&2; exit 1; }; \
	done
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BINARY) $(PACKETD) $(DESTDIR)$(BINDIR)/

## uninstall: remove installed binaries from $(DESTDIR)$(BINDIR)
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY) $(DESTDIR)$(BINDIR)/$(PACKETD)

## test: run unit tests
test:
	$(GO) test ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## check: run tests and vet
check: test vet

## fuzz: run short hostile-input campaigns for decoder, pcap, probe, service and nmap-db parsing
fuzz:
	$(GO) test -run '^$$' -fuzz '^FuzzDecoder$$' -fuzztime=5s -parallel=2 ./internal/packet
	$(GO) test -run '^$$' -fuzz '^FuzzPCAPReader$$' -fuzztime=5s -parallel=2 ./internal/packet
	$(GO) test -run '^$$' -fuzz '^FuzzDefinitionAndMatcher$$' -fuzztime=5s -parallel=2 ./internal/probe
	$(GO) test -run '^$$' -fuzz '^FuzzResponseParsers$$' -fuzztime=5s -parallel=2 ./internal/service
	$(GO) test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime=5s -parallel=2 ./internal/nmapdb

## benchmark: save fixed-workload measurements and CPU profile
benchmark:
	bash tests/performance/baseline.sh

## cross: build binaries for every supported platform into dist/
cross:
	@mkdir -p $(DIST)
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		[ "$$os" = windows ] && ext=.exe; \
		out=$(DIST)/$(BINARY)-$$os-$$arch$$ext; \
		echo "build $$out"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out $(PKG); \
		echo "build $(DIST)/$(PACKETD)-$$os-$$arch$$ext"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(PACKETD)-$$os-$$arch$$ext $(PACKETD_PKG); \
	done

## linux-packages: build .deb and .rpm packages for linux/amd64 and linux/arm64
linux-packages: cross
	@set -e; stage=$(DIST)/pkg; rm -rf $$stage; mkdir -p $$stage; \
	$(GO) run $(PKG) completion bash > $$stage/nyxr.bash; \
	$(GO) run $(PKG) completion zsh > $$stage/_nyxr; \
	$(GO) run $(PKG) completion fish > $$stage/nyxr.fish; \
	for arch in $(LINUX_ARCHES); do \
		cp $(DIST)/$(BINARY)-linux-$$arch $$stage/$(BINARY); \
		cp $(DIST)/$(PACKETD)-linux-$$arch $$stage/$(PACKETD); \
		for fmt in deb rpm; do \
			GOARCH=$$arch PKG_VERSION=$(PKG_VERSION) \
				$(NFPM) package --config packaging/nfpm.yaml --packager $$fmt --target $(DIST)/; \
		done; \
	done; \
	rm -rf $$stage

## package: build release archives (tar.gz, zip for windows), deb/rpm packages and checksums
package: linux-packages
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		[ "$$os" = windows ] && ext=.exe; \
		name=$(BINARY)-$(VERSION)-$$os-$$arch; \
		stage=$(DIST)/$$name; \
		rm -rf $$stage; mkdir -p $$stage; \
		cp $(DIST)/$(BINARY)-$$os-$$arch$$ext $$stage/$(BINARY)$$ext; \
		cp $(DIST)/$(PACKETD)-$$os-$$arch$$ext $$stage/$(PACKETD)$$ext; \
		cp README.md LICENSE $$stage/; \
		if [ "$$os" = windows ]; then \
			(cd $(DIST) && rm -f $$name.zip && zip -qr $$name.zip $$name); \
		else \
			tar -C $(DIST) -czf $(DIST)/$$name.tar.gz $$name; \
		fi; \
		rm -rf $$stage; \
		echo "package $$name"; \
	done
	@$(MAKE) --no-print-directory checksums

## checksums: write SHA-256 sums for release archives and packages
checksums: PACKAGES = $(BINARY)-*.tar.gz $(BINARY)-*.zip $(BINARY)_*.deb $(BINARY)-*.rpm
checksums:
	@cd $(DIST) && { command -v sha256sum >/dev/null && sha256sum $(PACKAGES) || shasum -a 256 $(PACKAGES); } > SHA256SUMS
	@echo "checksums $(DIST)/SHA256SUMS"

## clean: remove build output
clean:
	rm -rf $(DIST) $(BINARY) $(BINARY).exe $(PACKETD) $(PACKETD).exe

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
