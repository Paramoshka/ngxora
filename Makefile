# =========================
# Header / config
# =========================
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:

.DEFAULT_GOAL := help

APP        := ngxora
PLUGINS_CFG ?= plugins.cfg

# Versioning / tagging
TAG      ?= dev
REGISTRY ?=
IMAGE_REPO ?= $(APP)
IMAGE    ?= $(if $(strip $(REGISTRY)),$(REGISTRY)/$(IMAGE_REPO),$(IMAGE_REPO)):$(TAG)
BUILDER_IMAGE := ngxora-src
PLATFORMS ?= linux/amd64,linux/arm64
PLUGIN_FEATURES := $(shell if [ -f $(PLUGINS_CFG) ]; then awk 'NF && $$1 !~ /^#/ {print "plugin-" $$1}' $(PLUGINS_CFG) | paste -sd, -; fi)
CARGO_PLUGIN_FLAGS := --no-default-features $(if $(PLUGIN_FEATURES),--features $(PLUGIN_FEATURES))
RUNTIME_FEATURE_FLAGS := $(if $(PLUGIN_FEATURES),--features $(PLUGIN_FEATURES))

# Tools
CARGO      ?= cargo
GO         ?= go
DOCKER     ?= docker
GRYPE      ?= grype
GRYPE_FAIL_ON ?= high
CARGO_TARGET_DIR ?= target
CARGO_LOCK_FLAGS ?= --locked
GO_BUILD_CACHE ?= /tmp/ngxora-go-build

.PHONY: help all ci \
        test test-unit lint \
        build build-bin build-image gen-go-sdk \
        publish publish-image publish-release registry-login scan-image \
        clean

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "%-18s %s\n", $$1, $$2}'

all: test build ## Run tests + build artifacts
ci: lint test build ## CI pipeline (lint + tests + build)


# =========================
# Src section
# =========================
image-builder:
	CARGO_BUILD_FLAGS="$(CARGO_PLUGIN_FLAGS)" $(DOCKER) build . \
		--build-arg CARGO_BUILD_FLAGS \
		-t $(BUILDER_IMAGE) \
		--file ./Dockerfile \
		--target builder

# =========================
# Tests section
# =========================

lint: ## Lint source code
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(CARGO) fmt --check

test: test-unit ## Run default test suite
test-unit: ## Run unit tests
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(CARGO) test $(CARGO_LOCK_FLAGS) --manifest-path crates/ngxora-config/Cargo.toml
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(CARGO) test $(CARGO_LOCK_FLAGS) --manifest-path crates/ngxora-compile/Cargo.toml
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(CARGO) test $(CARGO_LOCK_FLAGS) --manifest-path crates/extensions/headers/Cargo.toml
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(CARGO) test $(CARGO_LOCK_FLAGS) --manifest-path crates/ngxora-runtime/Cargo.toml $(RUNTIME_FEATURE_FLAGS)
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(CARGO) run $(CARGO_LOCK_FLAGS) -- --check examples/ngxora.conf
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(CARGO) run $(CARGO_LOCK_FLAGS) -- --check examples/ngxora-tls.conf

# =========================
# Build section
# =========================

build: build-bin build-image ## Build all artifacts

build-bin: ## Build local release binary with plugins from plugins.cfg
	CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(CARGO) build $(CARGO_LOCK_FLAGS) --release --bin $(APP) $(CARGO_PLUGIN_FLAGS)

build-image: ## Build docker image locally
	CARGO_BUILD_FLAGS="$(CARGO_PLUGIN_FLAGS)" $(DOCKER) build \
		--build-arg CARGO_BUILD_FLAGS \
		-t $(IMAGE) .

gen-go-sdk: ## Generate Go SDK from control.proto
	./sdk/go/gen.sh

# =========================
# Publish section
# =========================

publish: test build publish-image ## Default publish (safe)

registry-login: ## Log in to the container registry using env vars
	test -n "$(REGISTRY)" || (echo "REGISTRY is required"; exit 1)
	test -n "$(REGISTRY_USERNAME)" || (echo "REGISTRY_USERNAME is required"; exit 1)
	test -n "$(REGISTRY_TOKEN)" || (echo "REGISTRY_TOKEN is required"; exit 1)
	printf '%s' "$(REGISTRY_TOKEN)" | $(DOCKER) login "$(REGISTRY)" -u "$(REGISTRY_USERNAME)" --password-stdin

scan-image: ## Scan the built image with grype and fail on configured severity
	command -v $(GRYPE) >/dev/null 2>&1 || (echo "grype is required"; exit 1)
	$(GRYPE) $(IMAGE) --fail-on $(GRYPE_FAIL_ON)

publish-image: registry-login ## Push docker image to registry
	$(DOCKER) push $(IMAGE)

publish-release: ## Publish release artifacts (example placeholder)
	@echo "publish-release: implement (GitHub/GitLab release upload)"

# =========================
# Cleanup section
# =========================

clean: ## Remove build artifacts
	find . -iname 'target' -type d -exec rm -rf {} \;
