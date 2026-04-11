.PHONY: build test short lint fuzz soak cover release-check

build:
	go build -o seatbelt ./cmd/seatbelt

test:
	go test ./...

short:
	go test -short ./...
lint:
	golangci-lint run ./...
# Runs each fuzz target for FUZZTIME.
FUZZTIME ?= 60s
fuzz:
	go test ./internal/shell -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME)
	go test ./internal/policy -run '^$$' -fuzz '^FuzzEvaluate$$' -fuzztime $(FUZZTIME)
	go test ./internal/policy -run '^$$' -fuzz '^FuzzDisguises$$' -fuzztime $(FUZZTIME)
	go test ./internal/policy -run '^$$' -fuzz '^FuzzGlobalFlags$$' -fuzztime $(FUZZTIME)
cover:
	go test -coverprofile=coverage.txt ./internal/...
	go tool cover -func=coverage.txt | tail -1
release-check:
	goreleaser check
