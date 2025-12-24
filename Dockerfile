FROM golang:1.24-bookworm AS builder

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
FROM alpine:3.19

# Install git (needed for repository cloning) and CA certificates
RUN apk --no-cache add git ca-certificates

# Add non-root user for better security
RUN addgroup -S flowlyt && adduser -S -G flowlyt flowlyt

# Copy the binary from the builder stage
COPY --from=builder /flowlyt /usr/local/bin/flowlyt
RUN chmod +x /usr/local/bin/flowlyt

# Create directory for default policies and set ownership
RUN mkdir -p /etc/flowlyt/policies
# Conditionally copy policies if directory exists
RUN if [ -d "test/policies" ]; then cp -r test/policies/* /etc/flowlyt/policies/ || true; fi
RUN chown -R flowlyt:flowlyt /etc/flowlyt

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
LABEL org.opencontainers.image.licenses="MIT"