BINARY=bin/sec

.PHONY: build test vet clean install

build:
	go build -o $(BINARY) .

test:
	go test ./... -timeout 120s

vet:
	go vet ./...

install:
	go build -o "$$(go env GOPATH)/bin/sec" .

clean:
	rm -rf bin dist
