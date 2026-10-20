# Build Stage
FROM golang:1.27.3-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -o t-cloud-cert-sync .

# Run Stage
FROM alpine:3.23
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/t-cloud-cert-sync .

ENTRYPOINT ["./t-cloud-cert-sync"]
