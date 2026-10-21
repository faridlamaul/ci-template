BINARY_NAME=shipguard
INSTALL_DIR=$(HOME)/.local/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS=-s -w -X main.version=$(VERSION)

.PHONY: all build install test vet fmt-check clean image-test e2e ci-e2e docs-check gitlab-lint publish-test bump-test

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

# Runs `shipguard ci` on the fixtures in testdata/ci inside the official language
# images (needs Docker and network). Pass LANG on the command line to filter
# languages, for example `make ci-e2e LANG=go,rust` (the LANG environment
# variable is the locale and is ignored).
ci-e2e:
	SHIPGUARD_CI_E2E=1 SHIPGUARD_CI_E2E_LANG='$(if $(filter command line,$(origin LANG)),$(LANG))' go test -tags e2e -count=1 -timeout 60m -v -run TestCIFixtures ./e2e/

# Validates every `.shipguard.yaml` snippet in README.md and docs/*.md with the real CLI.
docs-check:
	./scripts/docs-check.sh

# Tests scripts/publish-gitlab.sh against local bare repositories (no network).
publish-test:
	./scripts/publish-gitlab-test.sh

# Tests scripts/bump-scanners.sh with a fake gh (no network).
bump-test:
	./scripts/bump-scanners-test.sh

# Renders the GitLab template and lints it (and a consumer-style pipeline that
# includes it) on gitlab.com against the private test project.
GITLAB_LINT_PROJECT_ID ?= 87873115
gitlab-lint:
	rm -rf dist/gitlab
	./scripts/render-gitlab.sh 0.0.0 dist/gitlab
	./scripts/gitlab-lint.sh $(GITLAB_LINT_PROJECT_ID) dist/gitlab
