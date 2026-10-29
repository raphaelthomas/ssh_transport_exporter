.PHONY: build release lint vet vuln test clean

build:
	go build -buildmode=pie -o ssh_transport_exporter .

release: NEXT_VERSION = $(shell svu next --v0 --always)
release:
	@echo "Current version: $(shell svu current)"
	@echo "Next version:    $(NEXT_VERSION)"
	@read -p "Press enter to confirm release or Ctrl+C to cancel"
	git tag -a $(NEXT_VERSION) -m "Release $(NEXT_VERSION)"
	git push origin $(NEXT_VERSION)

lint:
	golangci-lint run ./...

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

test:
	go test -race -cover -v ./...

clean:
	@echo "Removing build artifacts..."
	rm -rfv dist/ ssh_transport_exporter
