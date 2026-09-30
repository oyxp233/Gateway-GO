package httprouter

import (
	"io"
	"net/http"
)

// maxDrainBodyBytes 限制"读掉请求体"的上限。
//
// 与 Go 标准库的口径一致（net/http server.go 的 maxPostHandlerReadBytes = 256<<10）：
// 这个长度以内的请求体一次性读完就能复用连接；更大的本就该走"读完或主动放弃"，
// 不做无上限读取，免得被超大 body 拖住连接。
const maxDrainBodyBytes = 256 << 10

// drainingResponseWriter 在**写拒绝响应之前**把未消费的请求体读掉并丢弃。
//
// 背景（2026-09-23 真机实测复现的既有缺陷）：
// 鉴权失败、限流、404/405 这些分支不读请求体就直接写响应。服务端随后关闭连接时，
// socket 接收缓冲里可能还躺着客户端发来的数据 —— 内核会直接回 RST 而不是正常 FIN。
// Windows 客户端于是拿到 WinError 10054「远程主机强迫关闭了一个现有的连接」，
// 而不是预期的 401/404。实测对 8443 无密钥 POST 40 次，17 次是 RST（42%）。
//
// 修法：先读掉 body 再写响应头，连接保持干净可复用，拒绝响应稳定可读。
type drainingResponseWriter struct {
	http.ResponseWriter
	req     *http.Request
	drained bool
}

// drain 读掉未消费的请求体（幂等；只在拒绝响应时触发）。
//
// 正常路径下 handler 已把 body 读完，io.Copy 会立即返回 EOF，不产生额外开销。
func (d *drainingResponseWriter) drain() {
	if d.drained {
		return
	}
	d.drained = true
	if d.req == nil || d.req.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(d.req.Body, maxDrainBodyBytes))
}

func (d *drainingResponseWriter) WriteHeader(status int) {
	// 只在拒绝类响应上动手：成功响应说明 handler 已按自己的节奏消费了输入，
	// 不做多余读取，保持热路径零开销。
	if status >= http.StatusBadRequest {
		d.drain()
	}
	d.ResponseWriter.WriteHeader(status)
}

func (d *drainingResponseWriter) Write(b []byte) (int, error) {
	// 不在这里 drain：WriteHeader 若已被调用过，drain 已经做完了；
	// 若没调用过（隐式 200），说明是成功路径，本就不需要。
	return d.ResponseWriter.Write(b)
}

// withBodyDrain 给整个路由挂上"拒绝响应前先读掉请求体"的行为。
//
// 之所以包装 ResponseWriter 而不是逐个 handler 补 drain：
// 不读请求体就返回的路径不只鉴权失败，还有限流、404、405、方法不匹配等，
// 逐个补容易漏、以后新增接口又会再漏。包一次覆盖全部。
//
// 前提已核实：本项目没有任何 handler 依赖 http.Flusher / http.Hijacker /
// http.ResponseController 等可选接口，包装 ResponseWriter 不破坏语义。
func withBodyDrain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			// GET/HEAD 或空体请求：无需包装，直接走原路径。
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&drainingResponseWriter{ResponseWriter: w, req: r}, r)
	})
}
