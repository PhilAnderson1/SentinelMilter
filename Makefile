.PHONY: build test vet

build:
	go build -buildvcs=false -trimpath -o bin/milterguard ./cmd/milterguard

test:
	go test ./...

vet:
	go vet -buildvcs=false ./...
