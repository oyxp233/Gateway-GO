#!/bin/bash
# S4A21 Gateway Linux x64 构建脚本

set -e

echo "构建 S4A21 Gateway..."

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w -X main.version=$(date +%Y%m%d.%H%M%S)" \
  -o dist/s4a21-gateway \
  ./cmd/gateway/

echo "构建完成: dist/s4a21-gateway"
ls -lh dist/s4a21-gateway
