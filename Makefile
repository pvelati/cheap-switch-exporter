# Run `make check` after every change. Everything else is opt-in.

GO         ?= go
FAKE_PORT  ?= 127.0.0.1:8081
EXP_PORT   ?= 127.0.0.1:9101
PROFILE    ?= standard
COVER_FILE ?= coverage.out
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.DEFAULT_GOAL := help
.PHONY: help check fmt fmt-fix vet build test race cover cover-html \
        acceptance lint vuln fake demo tidy clean ci

help: ## Show this help
	@echo "cheap-switch-exporter"
	@echo
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Profiles for 'make fake': $$($(GO) run ./cmd/fakeswitch -list-profiles 2>/dev/null | tr '\n' ' ')"

## The one target to run after every change: formatting, static analysis,
## build, and the whole test suite under the race detector.
check: fmt vet build race ## Validate everything (run this after every change)
	@echo
	@echo "OK: formatting, vet, build and all tests under -race passed."

fmt: ## Fail if any file is not gofmt-ed
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-ed:"; echo "$$unformatted"; \
		echo "run: make fmt-fix"; exit 1; \
	fi
	@echo "gofmt: clean"

fmt-fix: ## Rewrite files with gofmt
	gofmt -w .

vet: ## Run go vet
	$(GO) vet ./...
	@echo "vet: clean"

build: ## Build the exporter and the fake switch
	$(GO) build -trimpath -ldflags="-X main.Version=$(VERSION)" -o /dev/null .
	$(GO) build -o /dev/null ./cmd/fakeswitch
	@echo "build: ok"

test: ## Run the tests
	$(GO) test -count=1 ./...

race: ## Run the tests under the race detector
	$(GO) test -race -count=1 -timeout 300s ./...

acceptance: ## Run only the black-box acceptance suite against every fake firmware
	$(GO) test -count=1 -timeout 300s -run TestAcceptance -v .

cover: ## Report test coverage per function
	$(GO) test -count=1 -coverprofile=$(COVER_FILE) ./... > /dev/null
	@$(GO) tool cover -func=$(COVER_FILE) | tail -1
	@echo "detail: make cover-html"

cover-html: cover ## Open the coverage report in a browser
	$(GO) tool cover -html=$(COVER_FILE)

## Compares go.mod and go.sum before and after, rather than against git, so it
## also works with other uncommitted changes in the tree.
tidy: ## Verify go.mod and go.sum are tidy
	@tmp=$$(mktemp -d); \
	cp go.mod go.sum "$$tmp/"; \
	$(GO) mod tidy; \
	if ! cmp -s go.mod "$$tmp/go.mod" || ! cmp -s go.sum "$$tmp/go.sum"; then \
		echo "go mod tidy changed go.mod or go.sum, commit the result:"; \
		diff -u "$$tmp/go.mod" go.mod || true; \
		rm -rf "$$tmp"; exit 1; \
	fi; \
	rm -rf "$$tmp"; \
	echo "modules: tidy"

lint: ## Run golangci-lint if it is installed
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout 5m; \
	else \
		echo "golangci-lint not installed, skipping."; \
		echo "install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2"; \
	fi

vuln: ## Scan dependencies for known vulnerabilities
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

fake: ## Run a fake switch (PROFILE=standard|quirks|keeplink|session|binardat|poe|garbage|...)
	$(GO) run ./cmd/fakeswitch -profile $(PROFILE) -listen $(FAKE_PORT)

## Runs a fake switch in the background and the real exporter in the foreground,
## so you can browse the metrics by hand. Ctrl-C stops both.
##
## The config is generated in /tmp on purpose: reading ./config.yaml here would
## point the demo at a real switch if the developer has one configured.
demo: DEMO_POE = $(if $(filter poe,$(PROFILE)),true,false)
demo: ## Run a fake switch plus the exporter for manual inspection
	@$(GO) build -o /tmp/cse-fakeswitch ./cmd/fakeswitch
	@$(GO) build -o /tmp/cse-exporter .
	@printf 'address: "%s"\nusername: admin\npassword: admin\npoll_rate_seconds: 0\ntimeout_seconds: 5\npoe: %s\n' \
		'$(FAKE_PORT)' '$(DEMO_POE)' > /tmp/cse-demo.yaml
	@chmod 600 /tmp/cse-demo.yaml
	@/tmp/cse-fakeswitch -profile $(PROFILE) -listen $(FAKE_PORT) & \
	fake_pid=$$!; \
	trap 'kill $$fake_pid 2>/dev/null; rm -f /tmp/cse-fakeswitch /tmp/cse-exporter /tmp/cse-demo.yaml' EXIT INT TERM; \
	sleep 1; \
	echo; echo "metrics: http://$(EXP_PORT)/metrics   (poe=$(DEMO_POE))"; echo; \
	/tmp/cse-exporter -c /tmp/cse-demo.yaml --web.listen-address $(EXP_PORT) --log.level debug

ci: fmt vet tidy build race cover ## Everything CI runs

clean: ## Remove build and test artefacts
	rm -f $(COVER_FILE) cheap-switch-exporter fakeswitch
	$(GO) clean -testcache
