# k8scout Makefile
# Static binary build + Docker operations

BINARY      := k8scout
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
REGISTRY    := ghcr.io/hac01
IMAGE       := $(REGISTRY)/$(BINARY):$(VERSION)
IMAGE_LATEST:= $(REGISTRY)/$(BINARY):latest

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-extldflags '-static'

.PHONY: build build-linux build-linux-arm64 build-darwin build-darwin-arm64 build-all test lint docker-build docker-push deploy clean

## build: compile for the current OS (dev use)
build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) ./main.go

## build-linux: cross-compile a static linux/amd64 binary
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY)-linux-amd64 ./main.go
	@echo "Static binary: ./$(BINARY)-linux-amd64"
	@file ./$(BINARY)-linux-amd64

## build-linux-arm64: cross-compile a static linux/arm64 binary
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY)-linux-arm64 ./main.go
	@echo "Static binary: ./$(BINARY)-linux-arm64"
	@file ./$(BINARY)-linux-arm64

## build-darwin: compile a macOS/amd64 binary
build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY)-darwin-amd64 ./main.go
	@echo "Binary: ./$(BINARY)-darwin-amd64"

## build-darwin-arm64: compile a macOS/arm64 (Apple Silicon) binary
build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY)-darwin-arm64 ./main.go
	@echo "Binary: ./$(BINARY)-darwin-arm64"

## build-all: compile all four release targets
build-all: build-linux build-linux-arm64 build-darwin build-darwin-arm64
	@echo ""
	@echo "All release binaries:"
	@ls -lh $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 $(BINARY)-darwin-amd64 $(BINARY)-darwin-arm64

## test: run unit tests
test:
	go test -race -count=1 ./...

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## docker-build: build the container image
docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--platform linux/amd64 \
		-t $(IMAGE) \
		-t $(IMAGE_LATEST) \
		.

## docker-push: push to registry
docker-push: docker-build
	docker push $(IMAGE)
	docker push $(IMAGE_LATEST)

## deploy: apply RBAC and Job to current cluster context
deploy:
	kubectl apply -f deploy/rbac.yaml
	kubectl apply -f deploy/job.yaml

## logs: tail logs from the running job pod
logs:
	kubectl logs -l app=k8scout -f --tail=200

## results: copy the JSON report from the completed pod
results:
	@POD=$$(kubectl get pod -l app=k8scout -o jsonpath='{.items[0].metadata.name}'); \
	kubectl cp $$POD:/out/k8scout-result.json ./k8scout-result.json && \
	echo "Saved to ./k8scout-result.json"

## clean: remove local binaries
clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 $(BINARY)-darwin-amd64 $(BINARY)-darwin-arm64

help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
