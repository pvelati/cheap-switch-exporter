.PHONY: all clean docker-tag-latest docker-image

IMAGE_BASE := madworx/cheap-switch-exporter
IMAGE_TAG := $(shell git describe --always --dirty --abbrev=7)
IMAGE := $(IMAGE_BASE):$(IMAGE_TAG)
DEPS := $(wildcard *.go) go.mod go.sum config.yaml.example Makefile

all: help

cheap-switch-exporter: $(DEPS) ## Build the cheap-switch-exporter binary locally
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -ldflags="-w -s -X 'main.Version=$(IMAGE_TAG)'" \
    -o cheap-switch-exporter

docker-image: .docker-built ## Build the docker image

docker-image-tag-latest: .docker-built ## Tag the docker image as latest
	docker tag $(IMAGE) $(IMAGE_BASE):latest

clean: ## Clean up the build artifacts
	rm -f cheap-switch-exporter .docker-built *~


.docker-built: $(DEPS) Dockerfile
	docker build -t $(IMAGE) .
	touch $@

help:  ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target>\n\nTargets:\n"} \
	     /^[a-zA-Z0-9_-]+:.*##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
