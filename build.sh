#!/bin/bash
# ============================================================================
# Gateway-GO 构建脚本（2026-10-24 重写）
#
# 产出 dist/<goos>-<goarch>/ 下的一套**可直接部署**的产物：
#     s5a3-gateway   网关进程（玩家链路：TCP/HTTP/游戏端口代理）
#     s5a3-admin     管理后台进程（8443，/api/admin/* 与静态页）
#     wwwroot/       后台单页（index.html）
#
# ★ 为什么要把 wwwroot 一起打进来：
#   后台首页走的是 http.FileServer(http.Dir("wwwroot")) —— **从磁盘读**，
#   不走 go:embed（只有 static/register.html 是嵌入的）。
#   所以重新编译二进制**不会**更新后台页面，必须单独把 wwwroot 传上去。
#   2026-10-24 就是这样踩的坑：二进制更新了、页面还是旧的，
#   用户刷新后台看不到新功能，排查了半天。
#   现在把 wwwroot 放进产物目录，部署时整目录一起传就不会漏。
#
# 用法：
#     sh build.sh                 # 默认 linux/amd64
#     sh build.sh linux arm64
#     sh build.sh windows amd64
# ============================================================================

set -eu

GOOS=${1:-linux}
GOARCH=${2:-amd64}

case "$GOOS" in
  linux|windows|darwin) ;;
  *) echo "不支持的 GOOS: $GOOS" >&2; exit 2 ;;
esac
case "$GOARCH" in
  amd64|arm64) ;;
  *) echo "不支持的 GOARCH: $GOARCH" >&2; exit 2 ;;
esac

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

EXT=""
[ "$GOOS" = "windows" ] && EXT=".exe"
OUT="dist/${GOOS}-${GOARCH}"

echo "构建 Gateway-GO  ->  ${GOOS}/${GOARCH}"

mkdir -p "$OUT"

export CGO_ENABLED=0 GOOS GOARCH

# ---- Go 编译器固定 1.26.5 ----
# 1.27 的 runtime 有死锁 BUG（事件循环永久停摆），网关也有常驻 goroutine，
# 一律用 1.26.5 编。可用 GO_BIN 覆盖；找不到就回退 PATH 里的 go 并警告。
GO="${GO_BIN:-}"
if [ -z "$GO" ]; then
  for _cand in "/c/Go1.26.5/go/bin/go.exe" "C:/Go1.26.5/go/bin/go.exe"; do
    if [ -x "$_cand" ]; then GO="$_cand"; break; fi
  done
fi
if [ -z "$GO" ]; then
  GO="go"
  echo "!! 警告：未找到 Go 1.26.5，回退到 PATH：$(go version)"
fi

# -trimpath：去掉本机绝对路径，产物可复现
# -buildvcs=false：本仓不是标准 git 工作树也能构建
"$GO" build -buildvcs=false -mod=readonly -trimpath -o "$OUT/s5a3-gateway$EXT" ./cmd/gateway
echo "  [1/3] s5a3-gateway$EXT"

"$GO" build -buildvcs=false -mod=readonly -trimpath -o "$OUT/s5a3-admin$EXT" ./cmd/admin
echo "  [2/3] s5a3-admin$EXT"

# ★ 后台页面：从磁盘读，必须随产物一起交付
if [ -d wwwroot ]; then
  rm -rf "$OUT/wwwroot"
  cp -a wwwroot "$OUT/wwwroot"
  echo "  [3/3] wwwroot/（$(ls wwwroot | wc -l) 个文件）"
else
  echo "  [3/3] 警告：找不到 wwwroot/，后台页面将无法访问" >&2
fi

echo
echo "构建完成: $OUT"
ls -lh "$OUT"
echo
echo "部署提示：把 $OUT 下的 gateway / admin / wwwroot 一起传到服务器同目录。"
echo "         只传二进制不传 wwwroot ⇒ 后台页面仍是旧版（wwwroot 不走 go:embed）。"
