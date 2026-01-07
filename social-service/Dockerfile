# Stage 1: Build
FROM golang:1.25.1-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/social-service .

# Stage 2: Final Image
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/social-service /app/social-service
EXPOSE 3002
ENTRYPOINT ["/app/social-service"]