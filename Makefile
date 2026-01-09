# =========================
# Header / config
# =========================
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:

.DEFAULT_GOAL := help

APP        := ngxora

# Versioning / tagging
TAG      ?= dev
REGISTRY ?= registry.example.com
IMAGE    ?= $(REGISTRY)/$(APP):$(TAG)
PLATFORMS ?= linux/amd64,linux/arm64

# Tools
CARGO      ?= cargo
DOCKER  ?= docker

.PHONY: help all ci \
        test test-unit test-integration lint \
        build build-bin build-image \
        publish publish-image publish-release \
        clean

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "%-18s %s\n", $$1, $$2}'

all: test build ## Run tests + build artifacts
ci: lint test build ## CI pipeline (lint + tests + build)

# =========================
# Tests section
# =========================

lint: ## Lint source code
	@echo "lint: (example)"; \
	$(CARGO) vet ./...

test: test-unit ## Run default test suite
test-unit: ## Run unit tests
	$(CARGO) test ./...

test-integration: ## Run integration tests
	# require env or docker compose etc.
	$(CARGO) test -tags=integration ./...

# =========================
# Build section
# =========================

build: build-bin build-image ## Build all artifacts

build-image: ## Build docker image locally
	$(DOCKER) build -t $(IMAGE):$(TAG) .

# =========================
# Publish section
# =========================

publish: test build publish-image ## Default publish (safe)

publish-image: ## Push docker image to registry
	$(DOCKER) push $(IMAGE):$(TAG)

publish-release: ## Publish release artifacts (example placeholder)
	@echo "publish-release: implement (GitHub/GitLab release upload)"

# =========================
# Cleanup section
# =========================

clean: ## Remove build artifacts
	find . -iname 'target' -type d -exec rm -rf {} \;
