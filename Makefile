BINARY_NAME=shipguard
INSTALL_DIR=$(HOME)/.local/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS=-s -w -X main.version=$(VERSION)

.PHONY: all build install test vet fmt-check clean image-test

all: build

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/shipguard

install: build
	mkdir -p $(INSTALL_DIR)
	cp bin/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Installed $(BINARY_NAME) to $(INSTALL_DIR)/$(BINARY_NAME)"

test:
	go test -v ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt: files above need formatting"; exit 1; }

clean:
	rm -rf bin/

image-test:
	docker build --build-arg VERSION=dev -t shipguard:dev .
	docker run --rm shipguard:dev version
	docker run --rm --entrypoint sh shipguard:dev -c 'gitleaks version && opengrep --version && osv-scanner --version && trivy --version'
