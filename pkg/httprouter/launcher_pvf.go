package httprouter

import (
	"net/http"
	"strconv"

	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/utils"
)

// ============================================================================
// 登录器 PVF 增量下发（2026-09-30）
//
// 背景：Script.pvf 是服务端与客户端**共用**的权威脚本文件（当前 71.4 MiB ≈ 74.9 MB），
// 改一个数值 / 掉落 / 商店就要玩家重下整份 —— 而实测「改内容」的差分只有 0.29%。
//
// 链路：
//
//	后台 /api/admin/upload-pvf 传新 PVF
//	  → PvfService.ReplacePvf 留一份 .bak
//	  → rebuildDelta 生成「.bak → 当前」的增量包，落到 <DeltaDir>/current.delta
//	  → /api/launcher/policy 下发 pvf.delta{from_hash,to_hash,to_size,size,url}
//	  → 登录器：本地 hash == from_hash ⇒ 下本端点 ⇒ 本地合成 ⇒ 校验 to_hash
//	    ⇒ AtomicFile 原子替换 ⇒ 再走原有的 PvfFileGuard.Lock
//
// ★ 为什么走 /api 路由而不是静态目录：
//   与插件下载同因 —— 双进程形态下玩家端口(8080)的非 /api 路径一律 404
//   （usePublicOnlyMiddleware，见 launcher_plugins.go 抬头），wwwroot 只在管理端口可见。
//
// ★ 没有可用增量时返回 **404 而不是 200 空体**：
//   登录器把 404 当作「本次没有增量」，继续走原有的「校验失败 → 提示手动更新客户端」；
//   若回 200 空体，客户端会拿到一份长度 0 的"合法包"，白跑一次合成。
//
// ★ 客户端安全边界不变：
//   增量包只包含「从旧文件拷贝哪些区间」+「字面量」，本身不携带可执行内容；
//   最终产物必须通过整文件 SHA-256 校验才会被替换，且任何一步失败都保留旧文件。
//   这条路径**不会**让玩家拿到一份未经验证的 Script.pvf。
// ============================================================================

func (s *Server) handleLauncherPvfDelta(w http.ResponseWriter, r *http.Request) {
	if s.pvfSvc == nil {
		http.NotFound(w, r)
		return
	}

	// ?from=<hash>（2026-09-30 方案①）：客户端本地版本不是固定增量的基线时，
	// 登录器会带上自己的本地 hash 再请求一次 —— 网关从 pvf_history 找到该版本
	// 就现场生成「该版 → 当前版」的按需增量（有缓存），否则 404。
	// 不带参数 = 老行为（固定增量 current.delta），2.3.7 及更早客户端完全兼容。
	var d *models.PvfDeltaInfo
	if from := r.URL.Query().Get("from"); from != "" {
		d = s.pvfSvc.GetOnDemandDelta(from)
	} else {
		d = s.pvfSvc.GetDelta()
	}
	if d == nil {
		// 没有增量：没上传过新 PVF / 生成失败 / 增量包已过期 / 按需未命中（历史无此版）
		http.NotFound(w, r)
		return
	}
	if !utils.FileExists(d.Path) {
		// 内存里有、盘上没了（例如被手工删掉）—— 按"没有"处理，绝不返回半截文件
		http.NotFound(w, r)
		return
	}

	// 与插件下载同口径：刻意 no-store。客户端自己有「合成后校验、不过就报错」的
	// 明确路径，服务端再加 HTTP 缓存只会引入"中间层留着旧字节、客户端反复重试"的风险。
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	// 便于线上对拍"玩家下的到底是哪一份增量"
	w.Header().Set("ETag", `"`+d.ToHash+`"`)
	w.Header().Set("X-Delta-From", d.FromHash)
	w.Header().Set("X-Delta-To", d.ToHash)
	w.Header().Set("X-Delta-To-Size", strconv.FormatInt(d.ToSize, 10))
	tw, release, ok := s.dl.Begin(w, r)
	if !ok {
		return
	}
	defer release()
	http.ServeFile(tw, r, d.Path)
}
