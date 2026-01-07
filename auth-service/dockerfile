# Stage 1: Build
FROM golang:1.25.1-alpine AS builder
WORKDIR /app

# Install git (needed for 'bloom' dependency)
RUN apk add --no-cache git

COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/auth-service .

# Stage 2: Final Image
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/auth-service /app/auth-service

# This is for your app.Static("/", "./public")
# If you have a 'public' folder, you need to copy it
# COPY --from=builder /app/public ./public

EXPOSE 3000
ENTRYPOINT ["/app/auth-service"]