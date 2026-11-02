package httprouter

import "net/http"

// maxRequestBodyBytes 单次请求体上限（8 MiB）。
//
// 为什么需要一个全局上限：json.Decoder 会把请求体全量缓冲进内存，
// 一个没有上限的端点等于给了任何能打到它的客户端一个"一次 POST 换多少内存"的旋钮。
// 全项目 30 处 `json.NewDecoder(r.Body)` 里原先只有 5 处（announce）自己包了 LimitReader，
// 逐个补容易漏、以后新增接口又会再漏 —— 与 withBodyDrain 同样的理由，包一次覆盖全部。
//
// 取值依据：合法请求里最大的是反作弊批量上报，announceMaxReportBytes = 5 MB
// （它自己另有一层 5 MB 的 LimitReader）。全局取 8 MiB 必须**大于**那个值，
// 否则会先把 announce 的上报截断 —— 那就把安全修复做成了功能回归。
// 两个公开端点（/api/heartbeat、/api/anticheat/report）另有 1 MiB 的收紧上限。
const maxRequestBodyBytes = 8 << 20

// maxUploadBodyBytes 文件上传端点的请求体上限（512 MiB）。
//
// 取值依据：合法上传里最大的是 PVF（线上 Script.pvf 实测 60,849,078B ≈ 58 MiB）。
// 512 MiB 留了约 8 倍余量（将来换更大的 PVF 也不会立刻撞墙），
// 又远小于这几个 handler 自己写的 ParseMultipartForm(2<<30) 内存阈值，
// 仍然挡得住"一次 POST 换走半个 G 内存"这类请求。
const maxUploadBodyBytes = 512 << 20

// uploadPaths 需要放宽请求体上限的端点（**精确路径匹配，不是前缀**）。
//
// 为什么必须列名单、而不是按 `/api/admin/` 前缀放开：这几个端点的共同点只有"收文件"，
// 按前缀放开等于把整个后台的 JSON 端点也一起放开，
// maxRequestBodyBytes 想防的东西（一次 POST 换多少内存）就原样放回来了。
//
// 为什么需要它们：这三个 handler 里都写着 ParseMultipartForm(2<<30)，
// 本意就是收大文件；全局 8 MiB 会把整条路打死，症状是前端弹
// `http: request body too large`（PVF 58 MiB，必然超限；2026-09-27 实事故）。
//
// ★ 路径写错 = **静默失效**：白名单永远不命中，功能还是坏的，而针对本表的测试全绿
// （它们只是拿字符串去查表）。TestUploadPathsAreRegisteredRoutes 用源码级断言
// 把这张表和 server.go 里真实注册的路由锁在一起，写错一个字符就会变红。
var uploadPaths = map[string]bool{
	"/api/admin/upload-pvf":       true, // 客户端校验：上传网关侧 PVF
	"/api/admin/server/pvf":       true, // 服务端管理：替换游戏服务端 PVF
	"/api/admin/integrity/upload": true, // 客户端校验：白/黑名单文件批量上传
	"/api/admin/launcher/upload":  true, // 登录器版本：上传新 exe（约 128 MiB，2026-10-01）
	"/api/admin/dnfexe/upload":    true, // DNF.EXE 版本：上传新 exe（约 20 MiB，2026-10-25）
	"/api/admin/drivers/upload":   true, // 驱动白名单：上传 .sys（实测最大的 NEPKernel.sys 3.9 MB，2026-10-16）
}

// uploadBodyLimitFor 返回该路径适用的请求体上限：白名单用 maxUploadBodyBytes，其余用 fallback。
func uploadBodyLimitFor(path string, fallback int64) int64 {
	if uploadPaths[path] {
		return maxUploadBodyBytes
	}
	return fallback
}

// withBodyLimit 给整个路由挂上请求体上限。
//
// 超限时 http.MaxBytesReader 让后续 Read 返回错误 → handler 的 Decode 失败 → 400，
// 并标记该连接在响应后关闭（免得残留的巨量 body 继续占着连接）。
//
// 注意包装顺序（见 serveHTTPOn）：必须**包在 withBodyDrain 外面**，
// 这样 MaxBytesReader 拿到的是原始的 http.ResponseWriter（它实现了 requestTooLarge，
// 能真正把连接标记为关闭）；反过来则拿到 drainingResponseWriter，标记会丢掉。
func withBodyLimit(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, uploadBodyLimitFor(r.URL.Path, limit))
		next.ServeHTTP(w, r)
	})
}
