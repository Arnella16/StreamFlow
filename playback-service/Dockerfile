# Stage 1: Build
FROM golang:1.25.1-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/playback-service .

# Stage 2: Final Image
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/playback-service /app/playback-service
RUN mkdir uploads
EXPOSE 8083
ENTRYPOINT ["/app/playback-service"]