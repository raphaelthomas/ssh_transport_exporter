NEXT_VERSION := $(shell svu next --v0)

.PHONY: build release lint vet test clean

build:
	go build -o ssh_transport_exporter .

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

test:
	go test -v ./...

clean:
	@echo "Removing build artifacts..."
	rm -rfv dist/ ssh_transport_exporter
