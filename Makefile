.PHONY: build release lint golangci-lint-version vet vuln test e2e clean

build:
	CGO_ENABLED=0 go build -buildmode=pie -o ssh_transport_exporter .

release: NEXT_VERSION = $(shell svu next --v0 --always)
release:
	@echo "Current version: $(shell svu current)"
	@echo "Next version:    $(NEXT_VERSION)"
	@read -p "Press enter to confirm release or Ctrl+C to cancel"
	git tag -a $(NEXT_VERSION) -m "Release $(NEXT_VERSION)"
	git push origin $(NEXT_VERSION)

GOLANGCI_LINT_VERSION := v2.15.0

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

# CI reads the version here to run the prebuilt golangci-lint.
golangci-lint-version:
	@echo $(GOLANGCI_LINT_VERSION)

vet:
	go vet -tags e2e ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

test:
	go test -race -cover -v ./...

COMPOSE ?= docker compose
E2E_COMPOSE = $(COMPOSE) -f tests/e2e/compose.yaml

e2e:
	trap '$(E2E_COMPOSE) down' EXIT; \
	$(E2E_COMPOSE) up -d --build && \
	go test -tags e2e -count=1 -v ./tests/e2e/...

clean:
	@echo "Removing build artifacts..."
	rm -rfv dist/ ssh_transport_exporter
