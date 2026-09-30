package proxy

import (
	"testing"

	"s4a21-gateway/pkg/session"
)

// ─────────────────────────────────────────────────────────────────────────────
// 关端口要清 connCounts（审查报告 网关 P1-4）
//
// ReloadPorts 关闭端口时 `online := p.connCounts[c.port]` 只读不删，
// 后续同一 publicPort 被重新启用时，新连接 `p.connCounts[publicPort]++` 会从陈旧旧值起算
// → 后台「在线连接数」虚高，管理员据错误数字判断。
//
// 本用例直接把计数预置成 3（只验账目，不依赖真实连接的握手时序），
// 断言：① 关闭回报里仍是 3；② 计数条目被清掉；③ 重新启用后从 0 起算。
// ─────────────────────────────────────────────────────────────────────────────

func TestReloadPortsClearsConnCounts(t *testing.T) {
	pub1, pub2 := freePort(t), freePort(t)
	channelPort := freePort(t)

	store := NewPortConfigStoreBootstrap(t.TempDir(), nil, nil)
	pHolder := wireStore(store)

	if _, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub1, Backend: 10001, Enabled: true},
		{Public: pub2, Backend: 10002, Enabled: true},
	}}); err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}

	p := newTestProxy(t, store, session.NewSessionManager(func() {}, func() {}), channelPort)
	*pHolder = p
	p.Start()
	defer p.Stop()

	p.mu.Lock()
	p.connCounts[pub1] = 3
	p.mu.Unlock()

	res, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub1, Backend: 10001, Enabled: false},
		{Public: pub2, Backend: 10002, Enabled: true},
	}})
	if err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}
	if len(res.Closed) != 1 || res.Closed[0].Port != pub1 {
		t.Fatalf("期望关闭 pub1，实际 %+v", res.Closed)
	}
	if res.Closed[0].OnlineConnections != 3 {
		t.Fatalf("关闭时应如实回报最后在线连接数 3，实际 %d", res.Closed[0].OnlineConnections)
	}

	p.mu.RLock()
	left, has := p.connCounts[pub1]
	p.mu.RUnlock()
	if has {
		t.Fatalf("端口关闭后计数应被清掉，实际残留 %d（重新启用后在线数会虚高）", left)
	}

	// 重新启用同一公网端口：计数必须从 0 起算
	if _, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub1, Backend: 10001, Enabled: true},
		{Public: pub2, Backend: 10002, Enabled: true},
	}}); err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}
	if !dialOK(pub1) {
		t.Fatalf("重新启用后 pub1 应处于监听状态")
	}

	p.mu.RLock()
	after := p.connCounts[pub1]
	p.mu.RUnlock()
	if after != 0 {
		t.Fatalf("重新启用后在线连接数应从 0 起算，实际 %d（旧值没清）", after)
	}
}
