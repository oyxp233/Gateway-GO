package session

import (
	"testing"
	"time"

	"s4a21-gateway/pkg/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// 掉线重连自动放行的判据（2026-10-10 生产 18:30 卡顿掉线复盘）
//
// 背景：客户端掉线后玩家重开登录器，旧会话还没到心跳超时就被判"已在线"，
// 登录器弹窗等人点确认 —— 人不在电脑前就一直进不去。于是加了一条**更短**的
// 判据：旧会话心跳已停滞 + 新登录来自同一端 ⇒ 判定为掉线重连，直接放行。
//
// 这里锁的是"不会误放行"那条底线：**心跳停滞但来自别处 = 异地顶号，必须拦住。**
// 顶号保护是账号安全的一部分，为了消除掉线体感把它打穿是得不偿失的。
// ─────────────────────────────────────────────────────────────────────────────

// newSessionWith 建一个可指定 IP / device_secret 的会话。
func newSessionWith(t *testing.T, sm *SessionManager, account, ip, secret string) *models.Session {
	t.Helper()
	token, err := sm.CreateSession(account, "10001", ip, secret, "")
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	sess, ok := sm.ValidateToken(token)
	if !ok {
		t.Fatalf("会话创建后取不到")
	}
	return sess
}

// ageSession 把会话的心跳时间推回 seconds 秒前（模拟客户端进程已死）。
func ageSession(sess *models.Session, seconds int64) {
	sess.LastHeartbeat = time.Now().Unix() - seconds
}

func TestStaleReconnectHitsSameIP(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "msp", "1.2.3.4", "secret-a")
	ageSession(sess, 40)

	got, ok := sm.FindStaleSessionForReconnect("msp", "1.2.3.4", "secret-a", 35)
	if !ok {
		t.Fatal("同 IP + 心跳停滞 40s 应判定为掉线重连")
	}
	if got.Token != sess.Token {
		t.Fatalf("命中的不是那个僵尸会话: got=%s want=%s", got.Token, sess.Token)
	}
}

func TestStaleReconnectHitsSameDeviceDifferentIP(t *testing.T) {
	// NAT / 手机热点切换出口 IP 是常态，设备指纹不变仍应放行。
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "msp", "1.2.3.4", "secret-a")
	ageSession(sess, 40)

	if _, ok := sm.FindStaleSessionForReconnect("msp", "9.9.9.9", "secret-a", 35); !ok {
		t.Fatal("同设备换 IP（NAT 重拨）应判定为掉线重连")
	}
}

func TestStaleReconnectRejectsDifferentEndpoint(t *testing.T) {
	// 异地顶号：心跳停滞但 IP 与设备都对不上 ⇒ 必须拦住，交给 1023 弹窗。
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "msp", "1.2.3.4", "secret-a")
	ageSession(sess, 40)

	if _, ok := sm.FindStaleSessionForReconnect("msp", "9.9.9.9", "secret-b", 35); ok {
		t.Fatal("异地（IP 与设备都不同）被误判成掉线重连 —— 顶号保护被打穿")
	}
}

func TestStaleReconnectRejectsEmptySecretsDifferentIP(t *testing.T) {
	// 两边 device_secret 都是空串时不能算"同设备"：老客户端 / 换机器第一次登录
	// 都是空串，拿空串判等会让任意机器都算同一端，顶号保护形同虚设。
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "msp", "1.2.3.4", "")
	ageSession(sess, 40)

	if _, ok := sm.FindStaleSessionForReconnect("msp", "9.9.9.9", "", 35); ok {
		t.Fatal("两端 device_secret 都为空时不应判定为同一端")
	}
}

func TestStaleReconnectRejectsFreshHeartbeat(t *testing.T) {
	// 活人：心跳只停了 10 秒（登录器 30 秒一次心跳，丢一次很正常）⇒ 不能踢。
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "msp", "1.2.3.4", "secret-a")
	ageSession(sess, 10)

	if _, ok := sm.FindStaleSessionForReconnect("msp", "1.2.3.4", "secret-a", 35); ok {
		t.Fatal("心跳仅停滞 10s（未超阈值）不应判定为僵尸会话")
	}
}

func TestStaleReconnectDisabledWhenThresholdNotPositive(t *testing.T) {
	// 阈值 0 / 负数 = 功能关闭，退回"一律弹窗"的老行为。
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "msp", "1.2.3.4", "secret-a")
	ageSession(sess, 3600)

	for _, threshold := range []int{0, -1} {
		if _, ok := sm.FindStaleSessionForReconnect("msp", "1.2.3.4", "secret-a", threshold); ok {
			t.Fatalf("阈值 %d 表示关闭，不应命中", threshold)
		}
	}
}

func TestStaleReconnectIgnoresOtherAccounts(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	other := newSessionWith(t, sm, "msp2", "1.2.3.4", "secret-a")
	ageSession(other, 3600)

	if _, ok := sm.FindStaleSessionForReconnect("msp", "1.2.3.4", "secret-a", 35); ok {
		t.Fatal("同 IP 下别人的僵尸会话不该被用来放行的判定")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 过期清理的明细（运维判据）
// ─────────────────────────────────────────────────────────────────────────────

func TestCleanExpiredSessionsWithDetailsReportsStaleness(t *testing.T) {
	sm := NewSessionManager(nil, nil)

	gone := newSessionWith(t, sm, "crashed_guy", "1.2.3.4", "s1")
	ageSession(gone, 300)
	alive := newSessionWith(t, sm, "still_here", "5.6.7.8", "s2")

	// ★ 2026-11-17：有活跃游戏连接的会话不再被清（那是玩家还在游戏里）。
	//   明细测试改用频道连接，仍验证"超时会话带连接时被清、明细记录在线状态"。
	channelSide, _ := pipePair(t)
	sm.AddProxyConnection(gone, channelSide)

	n, details := sm.CleanExpiredSessionsWithDetails(60)
	if n != 1 || len(details) != 1 {
		t.Fatalf("应清理 1 个并返回 1 条明细，实际 n=%d details=%d", n, len(details))
	}
	d := details[0]
	if d.Account != "crashed_guy" {
		t.Fatalf("明细账号不对: %s", d.Account)
	}
	if d.StaleSecs < 300 {
		t.Fatalf("心跳停滞秒数偏小: %d", d.StaleSecs)
	}
	if d.ProxyConns != 1 {
		t.Fatalf("应记到 1 条频道连接（说明玩家当时还挂在频道里），实际 %d", d.ProxyConns)
	}
	if d.ClientIP != "1.2.3.4" {
		t.Fatalf("明细 IP 不对: %s", d.ClientIP)
	}
	if _, ok := sm.ValidateToken(alive.Token); !ok {
		t.Fatal("未过期的会话不应被清理")
	}
}

func TestCleanExpiredSessionsKeepsIntContract(t *testing.T) {
	// CleanExpiredSessions 仍只返回数量：既有调用方（单测 / 主循环）不受影响。
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "old", "1.2.3.4", "s")
	ageSession(sess, 600)

	if got := sm.CleanExpiredSessions(60); got != 1 {
		t.Fatalf("CleanExpiredSessions 应返回 1，实际 %d", got)
	}
	if got := sm.CleanExpiredSessions(60); got != 0 {
		t.Fatalf("第二轮应无可清理，实际 %d", got)
	}
}
