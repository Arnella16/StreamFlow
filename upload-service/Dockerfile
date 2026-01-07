# Stage 1: Build the Go binary
FROM golang:1.25.1-alpine AS builder

# Install build-time dependencies
RUN apk add --no-cache git

WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/upload-service .

# ---
# Stage 2: Create the final, small image
FROM alpine:latest

# --- CRITICAL: Install Runtime Dependencies ---
# ffmpeg: For video chunking (HLS)
# psmisc: For the 'fuser' command
RUN apk add --no-cache ffmpeg psmisc
# ---

WORKDIR /app

# Copy the compiled binary from the 'builder' stage
COPY --from=builder /app/upload-service /app/upload-service

# Create the directory where videos will be saved
RUN mkdir uploads

# Expose the port your Fiber app listens on
EXPOSE 3001

# This is the command that starts your server
ENTRYPOINT ["/app/upload-service"]