.PHONY: build test vet

build:
	go build -buildvcs=false -trimpath -o bin/sentinelmilter ./cmd/sentinelmilter

test:
	go test ./...

vet:
	go vet -buildvcs=false ./...
