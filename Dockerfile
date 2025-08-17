FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache make git

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum to cache the dependency layer
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application using the Makefile to embed version info
RUN make wiresocks


FROM alpine:latest

# Add metadata labels
LABEL org.opencontainers.image.title="wiresocks"
LABEL org.opencontainers.image.description="A user-space WireGuard client that exposes a SOCKS and HTTP proxy."
LABEL org.opencontainers.image.source="https://github.com/shahradelahi/wiresocks"
LABEL org.opencontainers.image.licenses="MIT"

# Add ca-certificates and create a non-root user named 'wiresocks'
RUN apk add --no-cache ca-certificates net-tools && \
    addgroup -S wiresocks && \
    adduser -S wiresocks -G wiresocks

# Copy the compiled binary from the builder stage
COPY --from=builder /app/build/wiresocks /usr/local/bin/wiresocks

# Switch to the non-root user
USER wiresocks

# Set the entrypoint to the wiresocks binary
ENTRYPOINT [ "/usr/local/bin/wiresocks" ]

CMD [ "-c", "/etc/wiresocks/config.conf" ]
