# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o geminicli2api .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata

# Copy binary from builder
COPY --from=builder /app/geminicli2api .

# Create credentials directory
RUN mkdir -p /app/credentials

# Expose port
EXPOSE 8888

# Run the binary
CMD ["./geminicli2api"]
