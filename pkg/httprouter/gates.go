package httprouter

import (
	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/models"
)

// GateSwitches 是下发给登录器的门禁开关（`/api/launcher/policy` 的 `gates` 段）。
//
// 为什么开关放在**服务端**：登录器的 launcher-config.json 落在游戏目录，玩家可写。
// 一旦让本地配置能关掉 PVF 校验/完整性扫描，整套门禁就交到玩家手里了。
// 这里按服协议下发，客户端只执行。
//
// 字段缺省语义（客户端侧）：键缺失 = true（fail-closed）。所以老网关不返回本段时，
// 登录器退化成"全门禁"，与改造前完全一致。
//
// 结构定义搬到 models.GateBlock（2026-10-21）：登录响应也要带同一份开关，
// 而 models 不能反向依赖 httprouter。这里用类型别名保持本包内旧代码零改动。
type GateSwitches = models.GateBlock

// allGatesOn 是"全门禁"，也是未知/异常情形下的回落值（宁可多拦，不可漏拦）。
var allGatesOn = config.AllGatesOn

// gateSwitchesFor 按服协议给出该服的门禁开关（判定本体在 config.GateSwitchesFor，
// 与登录响应共用一份，避免两个出口口径漂移）。
func gateSwitchesFor(profile config.GameServerEntry, found bool) GateSwitches {
	return config.GateSwitchesFor(profile, found)
}
