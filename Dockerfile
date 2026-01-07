# --------------------------
# Stage 1: Build frontend
# --------------------------
FROM node:20-alpine AS frontend-builder

WORKDIR /app/client

# Copy frontend package files and install deps
COPY client/package*.json ./
RUN npm install

# Copy frontend source code
COPY client/ ./

# Build Vite frontend
RUN npm run build

# --------------------------
# Stage 2: Build gateway
# --------------------------
# Stage 2: Gateway backend
FROM golang:1.25.1-alpine AS gateway-builder
WORKDIR /app/gateway

# Install git for go modules
RUN apk add --no-cache git

# Copy Go module files first
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download

# Copy source code
COPY gateway/ ./
RUN go build -o gateway


# --------------------------
# Stage 3: Final image
# --------------------------
FROM alpine:latest

WORKDIR /app

# Install CA certs for HTTPS if needed
RUN apk add --no-cache ca-certificates

# Copy built gateway binary
COPY --from=gateway-builder /app/gateway/gateway ./

# Copy built frontend
COPY --from=frontend-builder /app/client/dist ./client/dist

# Expose gateway port
EXPOSE 8081

# Start gateway
CMD ["./gateway"]



