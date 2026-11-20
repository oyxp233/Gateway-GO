# syntax=docker/dockerfile:1
# S5A3 网关镜像（s5a3-gateway + s5a3-admin + wwwroot 同镜像）
#
# ★ 三条来自线上事故的硬约束，改之前先读：
#   1. Go 必须 1.26.5。1.27 的 runtime 有死锁 BUG，网关常驻 goroutine 会停摆。
#   2. 必须同时产出 s5a3-gateway 和 s5a3-admin 两个进程，缺一不可。
#   3. wwwroot/ 由 s5a3-admin 用 http.FileServer(http.Dir("wwwroot")) 从磁盘读，
#      不走 go:embed。只更新二进制不更新 wwwroot ⇒ 后台页面还是旧版。
#      所以本镜像把 wwwroot 一起打进 /app/wwwroot。
#
# 构建（在 Gateway-GO 仓库根目录）：
#   docker build -t s5a3-gateway:local .
# 运行（两个进程分别起容器，或用 compose 的 command 覆盖）：
#   docker run ... s5a3-gateway:local /app/s5a3-gateway --config /app/appsettings.json
#   docker run ... s5a3-gateway:local /app/s5a3-admin    --config /app/appsettings.json
# 工作目录固定 /app，与 appsettings.json 里的相对路径（./Data、./wwwroot、
# ./certs、./logs）一致。

FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -buildvcs=false -mod=readonly -trimpath -o /out/s5a3-gateway ./cmd/gateway && \
    CGO_ENABLED=0 go build -buildvcs=false -mod=readonly -trimpath -o /out/s5a3-admin    ./cmd/admin

FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -g 10001 dnf && adduser -D -u 10001 -G dnf dnf
WORKDIR /app
COPY --from=build /out/s5a3-gateway /app/s5a3-gateway
COPY --from=build /out/s5a3-admin    /app/s5a3-admin
# ★ wwwroot 必须随镜像交付（后台页面从磁盘读）
COPY wwwroot/ /app/wwwroot/
RUN mkdir -p /app/Data/Pvf /app/logs /app/certs /app/launcher_update /app/pvf_history /app/backups && \
    chown -R 10001:10001 /app

# 8000 网关 TCP / 8080 HTTPS / 8443 admin / 18080 内部 / 20000-20508 游戏代理口
EXPOSE 8000 8080 8443 18080 20000-20508/tcp 20000-20299/udp
USER 10001:10001
# 默认跑网关；admin 容器用 compose 的 command 覆盖为 /app/s5a3-admin
ENTRYPOINT ["/app/s5a3-gateway"]
CMD ["--config", "/app/appsettings.json"]
