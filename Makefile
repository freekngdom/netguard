VERSION ?= 0.1.0
REGISTRY ?= docker.io
OWNER ?= hippocampus

.PHONY: help test build guard ui push smoke clean

help:
	@echo "make test    run the test suite (needs python3 + pytest)"
	@echo "make build   build both images ($(OWNER)/netguard:$(VERSION), ...-guard)"
	@echo "make push    tag and push both images to $(REGISTRY)/$(OWNER)"
	@echo "make smoke   run the UI image against the fixture API"

test:
	python3 -m pytest -q

build: guard ui

guard:
	docker build -t $(OWNER)/netguard-guard:$(VERSION) ./guard

ui:
	docker build -t $(OWNER)/netguard:$(VERSION) ./ui

push: build
	docker tag $(OWNER)/netguard:$(VERSION) $(REGISTRY)/$(OWNER)/netguard:$(VERSION)
	docker tag $(OWNER)/netguard:$(VERSION) $(REGISTRY)/$(OWNER)/netguard:latest
	docker tag $(OWNER)/netguard-guard:$(VERSION) $(REGISTRY)/$(OWNER)/netguard-guard:$(VERSION)
	docker tag $(OWNER)/netguard-guard:$(VERSION) $(REGISTRY)/$(OWNER)/netguard-guard:latest
	docker push $(REGISTRY)/$(OWNER)/netguard:$(VERSION)
	docker push $(REGISTRY)/$(OWNER)/netguard:latest
	docker push $(REGISTRY)/$(OWNER)/netguard-guard:$(VERSION)
	docker push $(REGISTRY)/$(OWNER)/netguard-guard:latest

smoke:
	docker run -d --rm --name netguard-smoke -p 8080:8080 \
	  -e DOCKER_HOST=tcp://host.docker.internal:2375 \
	  -v $$PWD/config:/guard:ro -v $$PWD/state:/state:ro \
	  $(OWNER)/netguard:$(VERSION)

clean:
	rm -rf ui/__pycache__ tests/__pycache__ .pytest_cache
