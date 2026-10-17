package httprouter

import "s4a21-gateway/pkg/config"

// GateSwitches 是下发给登录器的门禁开关（`/api/launcher/policy` 的 `gates` 段）。
//
// 为什么开关放在**服务端**：登录器的 launcher-config.json 落在游戏目录，玩家可写。
// 一旦让本地配置能关掉 PVF 校验/完整性扫描，整套门禁就交到玩家手里了。
// 这里按服协议下发，客户端只执行。
//
// 字段缺省语义（客户端侧）：键缺失 = true（fail-closed）。所以老网关不返回本段时，
// 登录器退化成"全门禁"，与改造前完全一致。
type GateSwitches struct {
	// Policy 拉安全策略（黑白名单 + 驱动白名单）。
	Policy bool `json:"policy"`
	// Pvf 整文件 PVF 校验 + 增量更新 + 运行期锁。
	Pvf bool `json:"pvf"`
	// Plugins 受管插件同步（DLL 强管控）。
	Plugins bool `json:"plugins"`
	// Integrity 客户端完整性扫描（白名单存在性 + 黑名单/未登记模块）。
	Integrity bool `json:"integrity"`
	// Kernel 内核 / 易语言环境扫描。
	Kernel bool `json:"kernel"`
}

// allGatesOn 是"全门禁"，也是未知/异常情形下的回落值（宁可多拦，不可漏拦）。
var allGatesOn = GateSwitches{Policy: true, Pvf: true, Plugins: true, Integrity: true, Kernel: true}

// gateSwitchesFor 按服协议给出该服的门禁开关。
//
//	S4A21  ：全开（既有整套门禁，语义不变）。
//	S5A95  ：只留策略拉取，PVF/插件/完整性/内核四项关闭 —— DNF95 客户端没有登记 PVF、
//	         没有受管插件、且内核扫描对该客户端的误伤面未评估（设计文档 §5.3 的 v1 口径）。
//
// found=false（未知服 Id）时返回全开：未知服本来就该被登录面拒掉（1038），
// 若真走到这里也不该给出更宽松的门禁。
func gateSwitchesFor(profile config.GameServerEntry, found bool) GateSwitches {
	if !found {
		return allGatesOn
	}

	switch profile.Protocol {
	case config.ProtocolS5A95:
		return GateSwitches{
			Policy:    true,
			Pvf:       false,
			Plugins:   false,
			Integrity: false,
			Kernel:    false,
		}
	default:
		return allGatesOn
	}
}
