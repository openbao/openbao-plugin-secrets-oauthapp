#
# Commands
#

export BUILDAH ?= buildah
export GIT ?= git
export GO ?= go
export JQ ?= jq
export MKDIR_P ?= mkdir -p
export RM ?= rm -f
export SHA256SUM ?= shasum -a 256
export SHELLCHECK ?= shellcheck
export TAR ?= tar
export ZIP_M ?= zip -m

#
# Variables
#

export GOFLAGS ?=

PLUGIN_DIST_TARGETS ?= $(addprefix dist-bin-,darwin-amd64 darwin-arm64 windows-amd64 windows-386 linux-amd64 linux-386 linux-arm64 linux-arm freebsd-amd64 freebsd-386 freebsd-arm netbsd-amd64 netbsd-386 openbsd-amd64 openbsd-386 solaris-amd64)

# Platforms of the OCI image. The arm64 variant must be explicit: OpenBao asks
# the registry for linux/arm64/v8 on arm64 hosts.
IMAGE_PLATFORMS ?= linux/amd64 linux/arm64/v8
IMAGE_NAME ?= ghcr.io/openbao/openbao-plugin-secrets-oauthapp
# The dist-bin-<os>-<arch> targets that build the binaries for IMAGE_PLATFORMS.
IMAGE_DIST_TARGETS = $(foreach p,$(IMAGE_PLATFORMS),dist-bin-$(word 1,$(subst /, ,$(p)))-$(word 2,$(subst /, ,$(p))))

#
#
#

PLUGIN_DIST_NAME := openbao-plugin-secrets-oauthapp
PLUGIN_DIST_VERSION ?= $(shell $(GIT) describe --tags --always --dirty)

ARTIFACTS_DIR := artifacts
BIN_DIR := bin

#
# Targets
#

.PHONY: all
all: build

$(ARTIFACTS_DIR) $(BIN_DIR):
	$(MKDIR_P) $@

.PHONY: generate
generate:
	$(GO) generate ./...

.PHONY: build
build: generate $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/$(PLUGIN_DIST_NAME) ./cmd/openbao-plugin-secrets-oauthapp

.PHONY: check
check: generate
	scripts/check

.PHONY: test
test: generate
	scripts/test

.PHONY: dist
dist: $(PLUGIN_DIST_TARGETS)

.PHONY: image-dist
image-dist: $(IMAGE_DIST_TARGETS)

# Builds the image from the release archives in ARTIFACTS_DIR, so run `make
# image-dist` (or `make dist`) first.
.PHONY: image
image:
	scripts/image $(PLUGIN_DIST_NAME) $(PLUGIN_DIST_VERSION) $(IMAGE_NAME):$(PLUGIN_DIST_VERSION) $(IMAGE_PLATFORMS)
	scripts/check-image $(PLUGIN_DIST_NAME) $(PLUGIN_DIST_VERSION) $(IMAGE_NAME):$(PLUGIN_DIST_VERSION) $(IMAGE_PLATFORMS)

.PHONY: image-push
image-push:
	$(BUILDAH) manifest push --all $(IMAGE_NAME):$(PLUGIN_DIST_VERSION) docker://$(IMAGE_NAME):$(PLUGIN_DIST_VERSION)

.PHONY: clean
clean:
	$(RM) -r $(ARTIFACTS_DIR)/
	$(RM) -r $(BIN_DIR)/

.PHONY: $(PLUGIN_DIST_TARGETS)
$(PLUGIN_DIST_TARGETS): export CGO_ENABLED := 0
$(PLUGIN_DIST_TARGETS): export GOFLAGS += -a
$(PLUGIN_DIST_TARGETS): export GOOS = $(word 1,$(subst -, ,$*))
$(PLUGIN_DIST_TARGETS): export GOARCH = $(word 2,$(subst -, ,$*))
$(PLUGIN_DIST_TARGETS): export LDFLAGS += -extldflags "-static"
$(PLUGIN_DIST_TARGETS): dist-bin-%: $(ARTIFACTS_DIR)
	scripts/dist $(PLUGIN_DIST_NAME) $(PLUGIN_DIST_VERSION)
