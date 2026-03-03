# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# Install build dependencies for CGO-free static binary.
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache dependencies first.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a fully static binary.
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
    -trimpath \
    -ldflags="-s -w -extldflags '-static'" \
    -o /k8scout \
    ./main.go

# ── Stage 2: Minimal runtime image ───────────────────────────────────────────
# Use scratch for zero attack surface. Copy only the binary + CA certs.
FROM scratch

# CA certificates required for TLS to Kubernetes API server + OpenAI.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# The binary.
COPY --from=builder /k8scout /k8scout

# Run as non-root UID (arbitrary non-zero).
USER 65534:65534

ENTRYPOINT ["/k8scout"]
CMD ["--format", "text", "--all-namespaces", "--out", "/out/k8scout-result.json"]
