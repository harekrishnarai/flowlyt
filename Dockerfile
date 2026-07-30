# Base images are pinned by digest so the build is reproducible and cannot be
# repointed by whoever controls the tag. Flowlyt ships an UNPINNED_CONTAINER_IMAGE
# rule for exactly this, so its own image should comply.
FROM golang:1.25-bookworm@sha256:ea341baa9bd5ba6784f6d7161ace70544349a6242d54d34a0fbfd2c4d51c9d58 AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /flowlyt ./cmd/flowlyt

# Create a minimal container
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1

# Install git (needed for repository cloning) and CA certificates
RUN apk --no-cache add git ca-certificates

# Add non-root user for better security
RUN addgroup -S flowlyt && adduser -S -G flowlyt flowlyt

# Copy the binary from the builder stage
COPY --from=builder /flowlyt /usr/local/bin/flowlyt
RUN chmod +x /usr/local/bin/flowlyt

# Copy default policies from the builder stage. The previous `if [ -d
# "test/policies" ]` check ran in this final stage where no source is present,
# so it was always a no-op; copy from the builder where the source lives.
COPY --from=builder --chown=flowlyt:flowlyt /app/test/policies/ /etc/flowlyt/policies/

# Create a directory for scanning repositories
RUN mkdir -p /workspace && chown -R flowlyt:flowlyt /workspace
WORKDIR /workspace

# Switch to non-root user
USER flowlyt

# Set the entrypoint
ENTRYPOINT ["flowlyt"]

# Add labels for better container metadata
LABEL org.opencontainers.image.source="https://github.com/harekrishnarai/flowlyt"
LABEL org.opencontainers.image.description="GitHub Actions workflow security analyzer"
LABEL org.opencontainers.image.licenses="Apache-2.0"