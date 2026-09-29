BINARY  := scanner
PKG     := ./cmd/scanner
DIST    := dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

GO      ?= go
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

export CGO_ENABLED := 0

.PHONY: all build test vet check cross package checksums clean help

all: check build

## build: build the scanner for the host platform
build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## test: run unit tests
test:
	$(GO) test ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## check: run tests and vet
check: test vet

## cross: build binaries for every supported platform into dist/
cross:
	@mkdir -p $(DIST)
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		[ "$$os" = windows ] && ext=.exe; \
		out=$(DIST)/$(BINARY)-$$os-$$arch$$ext; \
		echo "build $$out"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out $(PKG); \
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
	rm -rf $(DIST) $(BINARY) $(BINARY).exe

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
