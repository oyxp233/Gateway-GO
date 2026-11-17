package config

import "s4a21-gateway/pkg/models"

// GateSwitchesFor 按服配置给出该服该跑哪几道客户端门禁。
//
// 为什么放在 config 包：它纯粹是"服配置 → 策略"的映射，没有状态。
// 放在这里之后，登录面（auth）和策略面（httprouter）用的是**同一份判定**，
// 不会出现"登录响应说跳过 PVF、策略接口说校验 PVF"这种自相矛盾。
//
// 判定顺序（三服合一改造，2026-10-24）：
//
//	① ListCaps 非 nil → 完全按 caps[] 决定（运营在后台显式配置的，最高优先）
//	② ListCaps 为 nil → 按 Protocol 默认值（下面的 switch）
//
// caps[] 是清单下发的能力位，与 GateBlock 的字段一一对应：
//
//	"policy" / "pvf" / "plugins" / "integrity" / "kernel" / "dnfexe"
//
// ★ 为什么 caps 优先于协议：评估文档（第三章 3.2）指出原实现的"缺口 B" ——
//
//	S5A3 的门禁全关是写死在协议判定里的，运营即使给 S5A3 开了白名单也打不开。
//	改成清单下发后，运营在后台逐项开关即可，不用改代码。
//
// 协议默认值（caps 未配置时）：
//
//	S4A21  ：全开（既有整套门禁，语义不变）。
//	S5A95  ：只留策略拉取，PVF/插件/完整性/内核四项关闭 —— DNF95 客户端没有
//	         登记 PVF、没有受管插件、且内核扫描对该客户端的误伤面未评估。
//	S5A3   ：六项全关（连 Policy 都不拉）。S5A3 是自建服务端 + 原版客户端，
//	         网关侧没有它的 PVF 登记、插件清单和完整性白名单；任何一项门禁
//	         都只会把玩家拦在门外，拦不到任何真东西（PVF/客户端由服务端自己校验）。
//	         ★ 这是"协议默认值"；线上 90CN 用 ListCaps 显式覆盖了它（六项全开），
//	         故 S5A3 的反外挂链实际是启用的 —— 详见本节末尾说明。
//
// found=false（未知服 Id）时返回全开：未知服本来就该被登录面拒掉（1038），
// 若真走到这里也不该给出更宽松的门禁。
func GateSwitchesFor(profile GameServerEntry, found bool) models.GateBlock {
	if !found {
		return AllGatesOn
	}

	// ① 运营显式配置的 caps[] 优先
	if profile.ListCaps != nil {
		return gateBlockFromCaps(profile.ListCaps)
	}

	// ② 协议默认值
	switch profile.Protocol {
	case ProtocolS5A95:
		return models.GateBlock{
			Policy:    true,
			Pvf:       false,
			Plugins:   false,
			Integrity: false,
			Kernel:    false,
			// DNF95 的客户端主程序是 ARAD.exe，不走 dnfexe 通道（那条通道只认 DNF.exe）。
			DnfExe: false,
		}
	case ProtocolS5A3:
		return models.GateBlock{}
	default:
		return AllGatesOn
	}
}

// gateBlockFromCaps 把能力位列表转成 GateBlock。
//
// 语义：**列出的能力才开，未列出的关闭**。
//
// ★ Policy 特殊处理：策略拉取（黑白名单 + 驱动白名单）是几乎所有门禁的前置 ——
//
//	没有策略就没有白名单可查。所以除非 caps 显式且列表非空，Policy 一律开。
//	这与改造前的行为一致：S5A95 的协议默认值里 Policy=true；
//	S5A3 的协议默认值是空 GateBlock（六项全 false，连 Policy 都不拉），
//	那是刻意的 —— 因为 S5A3 客户端默认不走登录器门禁链。
//	★ 注意：线上 90CN 的 S5A3 用 ListCaps 把六项都显式打开了（含 policy），
//	因此实际运行形态不是这里的协议默认值。运维红线：不要把它改小，否则
//	S5A3Ext.ini 管理 / AC 握手 / 必需模块监视会整体静默失效。
func gateBlockFromCaps(caps []string) models.GateBlock {
	var g models.GateBlock
	for _, c := range caps {
		switch c {
		case "policy":
			g.Policy = true
		case "pvf":
			g.Pvf = true
		case "plugins":
			g.Plugins = true
		case "integrity":
			g.Integrity = true
		case "kernel":
			g.Kernel = true
		case "dnfexe":
			g.DnfExe = true
		}
	}
	return g
}

// AllGatesOn 是"全门禁"，也是未知/异常情形下的回落值（宁可多拦，不可漏拦）。
var AllGatesOn = models.GateBlock{
	Policy:    true,
	Pvf:       true,
	Plugins:   true,
	Integrity: true,
	Kernel:    true,
	DnfExe:    true,
}

// DefaultCapsFor 按协议返回默认能力位列表（供服清单下发用）。
//
// ★ 为什么从 GateSwitchesFor 反推而不是另写一份 switch：
//
//	caps[] 与 GateBlock 表达的是同一件事（该服开哪几道门禁）。
//	两处各写一份必然漂移 —— 那正是评估文档点名要避免的"两个出口口径不一致"。
//	这里从协议默认门禁反推出 caps，保证登录响应（GateSwitchesFor）与
//	服清单（DefaultCapsFor）永远是同一份判定。
//
// 注意返回的切片顺序固定（policy → pvf → plugins → integrity → kernel），
// 便于日志阅读与测试断言。
func DefaultCapsFor(protocol string) []string {
	// 用空 ListCaps 走协议默认分支（nil 会进 caps 分支，语义不同）
	g := GateSwitchesFor(GameServerEntry{Protocol: protocol, ListCaps: nil}, true)

	caps := make([]string, 0, 6)
	if g.Policy {
		caps = append(caps, "policy")
	}
	if g.Pvf {
		caps = append(caps, "pvf")
	}
	if g.Plugins {
		caps = append(caps, "plugins")
	}
	if g.Integrity {
		caps = append(caps, "integrity")
	}
	if g.Kernel {
		caps = append(caps, "kernel")
	}
	if g.DnfExe {
		caps = append(caps, "dnfexe")
	}
	return caps
}
