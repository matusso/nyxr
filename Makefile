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

export CGO_ENABLED := 0

.PHONY: all build install uninstall test vet check fuzz benchmark cross package checksums clean help

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

## package: build release archives (tar.gz, zip for windows) and checksums
package: cross
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

## checksums: write SHA-256 sums for release archives
checksums:
	@cd $(DIST) && { command -v sha256sum >/dev/null && sha256sum $(BINARY)-*.tar.gz $(BINARY)-*.zip || shasum -a 256 $(BINARY)-*.tar.gz $(BINARY)-*.zip; } > SHA256SUMS
	@echo "checksums $(DIST)/SHA256SUMS"

## clean: remove build output
clean:
	rm -rf $(DIST) $(BINARY) $(BINARY).exe $(PACKETD) $(PACKETD).exe

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
