VERSION ?= 0.1.4
REGISTRY ?= docker.io
OWNER ?= hippocampus

# Build network. Empty = docker's default (fine on most hosts). Set NETWORK=host when
# the build container cannot resolve anything — the classic symptom is
# `apk add --no-cache ...: temporary error (try again later)` in ./guard, which on this
# host is caused by the resolver living inside a VPN namespace that a default-bridge
# build container cannot reach. See README > Troubleshooting.
NETWORK ?=
NETWORK_FLAG := $(if $(strip $(NETWORK)),--network $(NETWORK),)

.PHONY: help test build guard ui push smoke clean

help:
	@echo "make test    run the test suite (needs python3 + pytest)"
	@echo "make build   build both images ($(OWNER)/netguard:$(VERSION), ...-guard)"
	@echo "             add NETWORK=host if the build cannot resolve packages"
	@echo "make push    tag and push both images to $(REGISTRY)/$(OWNER)"
	@echo "make push-multiarch  same, but amd64+arm64 (needs buildx + qemu binfmt)"
	@echo "make smoke   run the UI image against the fixture API"

test:
	python3 -m pytest -q

build: guard ui

guard:
	docker build $(NETWORK_FLAG) -t $(OWNER)/netguard-guard:$(VERSION) ./guard

ui:
	docker build $(NETWORK_FLAG) -t $(OWNER)/netguard:$(VERSION) ./ui

push: build
	docker tag $(OWNER)/netguard:$(VERSION) $(REGISTRY)/$(OWNER)/netguard:$(VERSION)
	docker tag $(OWNER)/netguard:$(VERSION) $(REGISTRY)/$(OWNER)/netguard:latest
	docker tag $(OWNER)/netguard-guard:$(VERSION) $(REGISTRY)/$(OWNER)/netguard-guard:$(VERSION)
	docker tag $(OWNER)/netguard-guard:$(VERSION) $(REGISTRY)/$(OWNER)/netguard-guard:latest
	docker push $(REGISTRY)/$(OWNER)/netguard:$(VERSION)
	docker push $(REGISTRY)/$(OWNER)/netguard:latest
	docker push $(REGISTRY)/$(OWNER)/netguard-guard:$(VERSION)
	docker push $(REGISTRY)/$(OWNER)/netguard-guard:latest

# Multi-arch. Needs buildx and arm64 emulation on the building host:
#   docker run --privileged --rm tonistiigi/binfmt --install arm64
# The registry ends up with an OCI index, so `docker pull` resolves per platform.
push-multiarch:
	docker buildx build --platform linux/amd64,linux/arm64 \
	  -t $(REGISTRY)/$(OWNER)/netguard:$(VERSION) -t $(REGISTRY)/$(OWNER)/netguard:latest --push ./ui
	docker buildx build --platform linux/amd64,linux/arm64 \
	  -t $(REGISTRY)/$(OWNER)/netguard-guard:$(VERSION) -t $(REGISTRY)/$(OWNER)/netguard-guard:latest --push ./guard

smoke:
	docker run -d --rm --name netguard-smoke -p 8080:8080 \
	  -e DOCKER_HOST=tcp://host.docker.internal:2375 \
	  -v $$PWD/config:/guard:ro -v $$PWD/state:/state:ro \
	  $(OWNER)/netguard:$(VERSION)

clean:
	rm -rf ui/__pycache__ tests/__pycache__ .pytest_cache
