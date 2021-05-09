GO      ?= go
DEBUG   ?= 0
VERBOSE ?= 0
CODECOV ?= 0

ifneq ($(DEBUG),0)
GO_TEST_FLAGS        += -count=1
endif
ifneq ($(CODECOV),0)
GO_TEST_FLAGS        += -coverprofile=coverage.txt -covermode=atomic
endif
ifneq ($(VERBOSE),0)
GO_TEST_FLAGS        += -v
GO_TEST_BENCH_FLAGS  += -v
endif

GO_TOOLS_GOLANGCI_LINT ?= $(shell $(GO) env GOPATH)/bin/golangci-lint

# -- test ----------------------------------------------------------------------

.PHONY: test bench
.ONESHELL: test bench lint

test:
	$(GO) test $(GO_TEST_FLAGS) ./...

bench:
	$(GO) test $(GO_TEST_FLAGS) -bench=.* ./...

lint: $(GO_TOOLS_GOLANGCI_LINT)
	$(GO_TOOLS_GOLANGCI_LINT) run

# -- tools ---------------------------------------------------------------------

.PHONY: tools

tools: $(GO_TOOLS_GOLANGCI_LINT)

$(GO_TOOLS_GOLANGCI_LINT):
	GO111MODULE=on $(GO) get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.27.0

# -- go mod --------------------------------------------------------------------

.PHONY: go-mod-verify go-mod-tidy

go-mod-verify: go-mod-tidy
	git diff --quiet go.* || git diff --exit-code go.* || exit 1

go-mod-tidy:
	$(GO) mod tidy
	$(GO) mod download
