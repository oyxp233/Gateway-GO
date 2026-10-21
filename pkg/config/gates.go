package config

import "s4a21-gateway/pkg/models"

// GateSwitchesFor 按服协议给出该服该跑哪几道客户端门禁。
//
// 为什么放在 config 包：它纯粹是"服配置 → 策略"的映射，没有状态。
// 放在这里之后，登录面（auth）和策略面（httprouter）用的是**同一份判定**，
// 不会出现"登录响应说跳过 PVF、策略接口说校验 PVF"这种自相矛盾。
//
//	S4A21  ：全开（既有整套门禁，语义不变）。
//	S5A95  ：只留策略拉取，PVF/插件/完整性/内核四项关闭 —— DNF95 客户端没有
//	         登记 PVF、没有受管插件、且内核扫描对该客户端的误伤面未评估。
//	S5A3   ：五项全关。S5A3 是自建服务端 + 原版客户端，网关侧没有它的 PVF
//	         登记、插件清单和完整性白名单；任何一项门禁都只会把玩家拦在门外，
//	         拦不到任何真东西（PVF/客户端由服务端自己校验）。
//
// found=false（未知服 Id）时返回全开：未知服本来就该被登录面拒掉（1038），
// 若真走到这里也不该给出更宽松的门禁。
func GateSwitchesFor(profile GameServerEntry, found bool) models.GateBlock {
	if !found {
		return AllGatesOn
	}

	switch profile.Protocol {
	case ProtocolS5A95:
		return models.GateBlock{
			Policy:    true,
			Pvf:       false,
			Plugins:   false,
			Integrity: false,
			Kernel:    false,
		}
	case ProtocolS5A3:
		return models.GateBlock{}
	default:
		return AllGatesOn
	}
}

// AllGatesOn 是"全门禁"，也是未知/异常情形下的回落值（宁可多拦，不可漏拦）。
var AllGatesOn = models.GateBlock{Policy: true, Pvf: true, Plugins: true, Integrity: true, Kernel: true}
