.PHONY: build test short lint fuzz soak cover release-check

build:
	go build -o seatbelt ./cmd/seatbelt

test:
	go test ./...

short:
	go test -short ./...
lint:
	golangci-lint run ./...
cover:
	go test -coverprofile=coverage.txt ./internal/...
	go tool cover -func=coverage.txt | tail -1
