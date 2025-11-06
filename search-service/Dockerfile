# Step 1: Build the Go binary
FROM golang:1.25.1-alpine AS builder
WORKDIR /app
# Copy go.mod/sum first to leverage Docker cache
COPY go.mod ./
COPY go.sum ./
RUN go mod download
# Copy all your Go code
COPY . .
# Build the binary, statically linked
RUN CGO_ENABLED=0 GOOS=linux go build -o /go-search-service .

# Step 2: Create a tiny final image
FROM alpine:latest
WORKDIR /
# Copy the compiled binary from the 'builder' stage
COPY --from=builder /go-search-service /go-search-service

# This is the command that starts your server
ENTRYPOINT ["/go-search-service"]