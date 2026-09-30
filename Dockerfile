FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /app/s4a21-gateway ./cmd/gateway/

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/s4a21-gateway /app/s4a21-gateway
COPY --from=builder /app/wwwroot /app/wwwroot
COPY appsettings.json /app/appsettings.json

RUN mkdir -p /app/Data /app/logs /app/certs

EXPOSE 8000 8080 8001 20001-20201

ENTRYPOINT ["/app/s4a21-gateway"]
