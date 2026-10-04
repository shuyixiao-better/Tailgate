GO ?= go
VERSION ?= dev
STATICCHECK ?= staticcheck
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: build build-local test race vet staticcheck check integration clean

build:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/tailgate.exe ./cmd/tailgate

build-local:
	@mkdir -p dist
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/tailgate ./cmd/tailgate

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

staticcheck:
	$(STATICCHECK) ./...

check: test vet staticcheck

# Start the supplied SSH containers first: docker compose up -d.
integration:
	$(GO) test -tags integration -count=1 ./...

clean:
	rm -rf dist
