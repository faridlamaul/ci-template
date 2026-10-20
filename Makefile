BINARY_NAME=shipguard
INSTALL_DIR=$(HOME)/.local/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS=-s -w -X main.version=$(VERSION)

.PHONY: all build install test vet fmt-check clean image-test e2e docs-check gitlab-lint

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

e2e: image-test
	SHIPGUARD_IMAGE=shipguard:dev go test -tags e2e -count=1 ./e2e/

# Validates every `.shipguard.yaml` snippet in README.md and docs/*.md with the real CLI.
docs-check:
	./scripts/docs-check.sh

# Renders the GitLab template and lints it (and a consumer-style pipeline that
# includes it) on gitlab.com against the private test project.
GITLAB_LINT_PROJECT_ID ?= 87873115
gitlab-lint:
	rm -rf dist/gitlab
	./scripts/render-gitlab.sh 0.0.0 dist/gitlab
	./scripts/gitlab-lint.sh $(GITLAB_LINT_PROJECT_ID) dist/gitlab
