package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/session"
)

// ─────────────────────────────────────────────────────────────
// 方案 D（游戏口首包 m_id + 凭证认证）测试
//
// 每一条断言都问过自己：「把实现换回旧行为（只有 IP 白名单），它会不会红？」
// 不会红的不写进来。
// ─────────────────────────────────────────────────────────────

// buildGameLoginFrame 构造一条**帧长合规**的游戏登录首包：
// GamePacketHeader(14B) + i32(mIdLen) + mId + i32(pwdLen) + pwd。
//
// ★ length 字段是**含 14 字节头**的整帧长度 —— 服务端 FlexiblePacketProcessor
// 判 packetLength < headerSize 即非法。仓库里早期的 buildGameLoginFirstPacket
// 把它写成"只含 body"，那种包到服务端只会落 "Login body unparseable" 分支；
// 161 server.log 里能成功解析的登录全部来自真实客户端，即为此故。
func buildGameLoginFrame(mId, pwd string) []byte {
	body := make([]byte, 0, 4+len(mId)+4+len(pwd))
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(mId)))
	body = append(body, l[:]...)
	body = append(body, mId...)
	binary.LittleEndian.PutUint32(l[:], uint32(len(pwd)))
	body = append(body, l[:]...)
	body = append(body, pwd...)

	buf := make([]byte, gamePacketHeaderSize, gamePacketHeaderSize+len(body))
	buf[0] = 0x01 // cmd
	binary.LittleEndian.PutUint16(buf[1:], 0x1234)
	binary.LittleEndian.PutUint16(buf[11:], 1)
	// length 含 14 字节头（服务端口径）
	binary.LittleEndian.PutUint32(buf[3:], uint32(gamePacketHeaderSize+len(body)))
	return append(buf, body...)
}

// nonLoginFirstPacket 构造一个"完整但非登录"的首帧：14 字节头、length=14（无正文）。
//
// 用途：方案 D 把「连后端」前移到首包准入之后，集成测试必须先让客户端把
// 首包写进来，代理才会去连后端。这个首帧立即读齐（不会耗在首包超时等待），
// parseGameLoginPacket 判非登录包 ⇒ 走 IP 白名单回退 = 旧行为，
// 让不关心准入细节的测试（Stop 唤醒、端口热加载）沿用旧断言。
func nonLoginFirstPacket() []byte {
	b := make([]byte, gamePacketHeaderSize)
	b[0] = 0xAA // 与旧测试一致的首字节
	binary.LittleEndian.PutUint32(b[3:], gamePacketHeaderSize)
	return b
}

// fakeGameVerifier 假的凭证校验器：按 m_id 查表决定匹配/报错。
type fakeGameVerifier struct {
	matched map[string]bool
	errs    map[string]error
}

func (f *fakeGameVerifier) VerifyAccountCredential(mId, pwdField string) (bool, error) {
	if f == nil {
		return false, nil
	}
	if err, ok := f.errs[mId]; ok {
		return false, err
	}
	return f.matched[mId], nil
}

// newGameAuthFixture 搭一套方案 D 准入测试环境。
func newGameAuthFixture(t *testing.T, verifier GameCredentialVerifier, mutate func(*config.GatewayConfig)) (*ProxyServer, *session.SessionManager) {
	t.Helper()

	// 日志目录不用 t.TempDir：ConsoleLogger 持有 error.log 句柄，
	// 句柄不释放会让 TempDir 清理失败，症状是断言全过、测试却报 FAIL。
	logDir, err := os.MkdirTemp("", "s4a21-gw-auth-")
	if err != nil {
		t.Fatalf("建测试日志目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(logDir) })

	log, err := logger.NewConsoleLogger(logDir, logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(log.Close)

	cfg := config.DefaultConfig()
	cfg.Gateway.ListenAddress = "127.0.0.1"
	cfg.GameServer.MaxConnectionsPerIP = 4
	if mutate != nil {
		mutate(cfg)
	}

	sm := session.NewSessionManager(func() {}, func() {})
	return NewProxyServer(cfg, sm, log, nil, verifier), sm
}

// TestParseGameLoginPacket 严格登录包解析（准入依据，比归属用的
// parseGameLoginMId 更严：帧长自洽 + 正文恰好两个 DStr + 纯数字 m_id）。
func TestParseGameLoginPacket(t *testing.T) {
	token := strings.Repeat("ab", 32) // 64 hex，token 的实证形态

	// 合规登录包
	if mId, pwd, ok := parseGameLoginPacket(buildGameLoginFrame("10038", token)); !ok || mId != "10038" || pwd != token {
		t.Fatalf("合规登录包: got=(%q,%q,%v)，期望 (10038, token, true)", mId, pwd, ok)
	}

	// 空口令字段合法（服务端只要求 mId 非空）
	if mId, pwd, ok := parseGameLoginPacket(buildGameLoginFrame("10038", "")); !ok || mId != "10038" || pwd != "" {
		t.Fatalf("空口令字段应解析成功: got=(%q,%q,%v)", mId, pwd, ok)
	}

	// 非数字 m_id（老网关"m_id 填账号名"口径）→ 判失败，落回退分支 = 旧行为
	if _, _, ok := parseGameLoginPacket(buildGameLoginFrame("msp", token)); ok {
		t.Fatal("非数字 m_id 应判失败（走回退分支，不是凭证路径）")
	}

	// 缓冲区比声明的帧长更长（管道化/单次读收到多帧）⇒ 只认第一帧，
	// 拖尾部分属于后续帧，不应影响首帧解析（与旧 parseGameLoginMId 行为一致）
	trailing := append(buildGameLoginFrame("10038", token), 0x00)
	if mId, pwd, ok := parseGameLoginPacket(trailing); !ok || mId != "10038" || pwd != token {
		t.Fatalf("拖尾字节不应影响首帧解析: got=(%q,%q,%v)", mId, pwd, ok)
	}

	// 只有 header
	if _, _, ok := parseGameLoginPacket(make([]byte, gamePacketHeaderSize)); ok {
		t.Fatal("只有 header 应判失败")
	}

	// length 只写 body 长（仓库早期脚本的 bug 形态）⇒ 帧不完整、判失败
	bodyOnly := buildGameLoginFrame("10038", token)
	binary.LittleEndian.PutUint32(bodyOnly[3:], uint32(len(bodyOnly)-gamePacketHeaderSize))
	if _, _, ok := parseGameLoginPacket(bodyOnly); ok {
		t.Fatal("length 不含头时应判失败")
	}

	// length < headerSize
	bad := buildGameLoginFrame("10038", token)
	binary.LittleEndian.PutUint32(bad[3:], gamePacketHeaderSize-1)
	if _, _, ok := parseGameLoginPacket(bad); ok {
		t.Fatal("length < 14 应判失败")
	}

	// length 超上限
	bad2 := buildGameLoginFrame("10038", token)
	binary.LittleEndian.PutUint32(bad2[3:], uint32(maxFirstGamePacket+1))
	if _, _, ok := parseGameLoginPacket(bad2); ok {
		t.Fatal("length 超上限应判失败")
	}

	// nil 不 panic
	if _, _, ok := parseGameLoginPacket(nil); ok {
		t.Fatal("nil 应判失败")
	}
}

// TestFirstFrameComplete 首帧读齐判断。
func TestFirstFrameComplete(t *testing.T) {
	frame := buildGameLoginFrame("10038", "hash")

	if done, sane := firstFrameComplete(frame); !done || !sane {
		t.Fatalf("完整帧: got=(%v,%v)，期望 (true,true)", done, sane)
	}
	if done, sane := firstFrameComplete(frame[:len(frame)-1]); done || !sane {
		t.Fatalf("少一字节: got=(%v,%v)，期望 (false,true)", done, sane)
	}
	if done, sane := firstFrameComplete(frame[:gamePacketHeaderSize]); done || !sane {
		t.Fatalf("只有 header: got=(%v,%v)，期望 (false,true)", done, sane)
	}
	bad := buildGameLoginFrame("10038", "hash")
	binary.LittleEndian.PutUint32(bad[3:], gamePacketHeaderSize-1)
	if done, sane := firstFrameComplete(bad); done || sane {
		t.Fatalf("length<14: got=(%v,%v)，期望 (false,false)", done, sane)
	}
	bad2 := buildGameLoginFrame("10038", "hash")
	binary.LittleEndian.PutUint32(bad2[3:], uint32(maxFirstGamePacket+1))
	if done, sane := firstFrameComplete(bad2); done || sane {
		t.Fatalf("length 超限: got=(%v,%v)，期望 (false,false)", done, sane)
	}
	if done, sane := firstFrameComplete(nil); done || !sane {
		t.Fatalf("nil: got=(%v,%v)，期望 (false,true)", done, sane)
	}
}

// TestReadFirstGamePacket 首包读齐循环：分包必须读齐、非法帧长不能傻等、
// 超时必须交还已读字节（回退旧行为，不杀连接）。
func TestReadFirstGamePacket(t *testing.T) {
	frame := buildGameLoginFrame("10038", strings.Repeat("ab", 32))

	t.Run("一次到齐", func(t *testing.T) {
		srv, _ := newGameAuthFixture(t, nil, nil)
		client, peer := net.Pipe()
		defer client.Close()
		defer peer.Close()

		go func() { _, _ = peer.Write(frame) }()
		buf, complete := srv.readFirstGamePacket(client, 20011)
		if !complete || !bytes.Equal(buf, frame) {
			t.Fatalf("complete=%v len=%d，期望读到完整帧 %d 字节", complete, len(buf), len(frame))
		}
	})

	t.Run("分包两次到齐", func(t *testing.T) {
		srv, _ := newGameAuthFixture(t, nil, nil)
		client, peer := net.Pipe()
		defer client.Close()
		defer peer.Close()

		go func() {
			_, _ = peer.Write(frame[:20])
			_, _ = peer.Write(frame[20:])
		}()
		buf, complete := srv.readFirstGamePacket(client, 20011)
		if !complete || !bytes.Equal(buf, frame) {
			t.Fatalf("分包后 complete=%v len=%d，期望读齐 %d 字节", complete, len(buf), len(frame))
		}
	})

	t.Run("帧长非法立即返回", func(t *testing.T) {
		srv, _ := newGameAuthFixture(t, nil, nil)
		client, peer := net.Pipe()
		defer client.Close()
		defer peer.Close()

		bad := buildGameLoginFrame("10038", "hash")
		binary.LittleEndian.PutUint32(bad[3:], uint32(maxFirstGamePacket+1))
		// 只写 header，绝不补后续 —— 实现若傻等会卡到超时
		go func() { _, _ = peer.Write(bad[:gamePacketHeaderSize]) }()

		start := time.Now()
		buf, complete := srv.readFirstGamePacket(client, 20011)
		if complete {
			t.Fatal("非法帧长不应判读齐")
		}
		if len(buf) != gamePacketHeaderSize {
			t.Fatalf("应原样交还已读的 %d 字节，实际 %d", gamePacketHeaderSize, len(buf))
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("非法帧长还在傻等 —— 应在意识到帧长非法时立即返回")
		}
	})

	t.Run("超时未齐交还已读字节", func(t *testing.T) {
		srv, _ := newGameAuthFixture(t, nil, func(c *config.GatewayConfig) {
			c.GameServer.FirstReadTimeoutSeconds = 1
		})
		client, peer := net.Pipe()
		defer client.Close()
		defer peer.Close()

		go func() {
			_, _ = peer.Write(frame[:10]) // 只给 10 字节，永远等不齐
			time.Sleep(3 * time.Second)
		}()
		buf, complete := srv.readFirstGamePacket(client, 20011)
		if complete {
			t.Fatal("超时未齐不应判读齐")
		}
		if len(buf) != 10 {
			t.Fatalf("应交还已读的 10 字节，实际 %d", len(buf))
		}
	})

	t.Run("未配超时只读一次", func(t *testing.T) {
		srv, _ := newGameAuthFixture(t, nil, func(c *config.GatewayConfig) {
			c.GameServer.FirstReadTimeoutSeconds = 0
		})
		client, peer := net.Pipe()
		defer client.Close()
		defer peer.Close()

		go func() { _, _ = peer.Write(frame[:10]) }()
		buf, complete := srv.readFirstGamePacket(client, 20011)
		if complete || len(buf) != 10 {
			t.Fatalf("旧语义应只读一次: complete=%v len=%d", complete, len(buf))
		}
	})
}

// TestAdmitGameClientMatrix 方案 D 准入矩阵。
func TestAdmitGameClientMatrix(t *testing.T) {
	const (
		mId      = "10038"
		loginIP  = "198.51.100.7"  // 玩家 8000 登录所用 IP
		otherIP  = "203.0.113.9"   // 从未登录过的 IP（加速器/跨网段出口的模拟）
		pwdMd5   = "5f4dcc3b5aa765d61d8327deb882cf99" // "password" 的 MD5
		wrongPwd = "0f4dcc3b5aa765d61d8327deb882cf99" // 首字符改错 ⇒ 长度相同、内容不同
	)

	// withSession 建一个 mId 的会话并返回其 token。
	withSession := func(t *testing.T, sm *session.SessionManager, ip string) string {
		t.Helper()
		tok, err := sm.CreateSession("acct", mId, ip, "")
		if err != nil {
			t.Fatalf("建会话失败: %v", err)
		}
		return tok
	}

	t.Run("token命中_同IP放行", func(t *testing.T) {
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: false}}, nil)
		tok := withSession(t, sm, loginIP)

		adm := srv.admitGameClient(loginIP, buildGameLoginFrame(mId, tok), true)
		if !adm.allowed || !adm.authed || adm.cred != "token" || !adm.sessionDecided || adm.session == nil {
			t.Fatalf("token 命中必须凭证放行: %+v", adm)
		}
	})

	t.Run("token命中_异IP放行_事件二修复", func(t *testing.T) {
		// 正式服2 事件二的形态：会话绑在登录 IP，游戏连接从另一个 IP 来。
		// 旧行为在这里必然被拒（IP 不在白名单）——这条就是修复本身。
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: false}}, nil)
		tok := withSession(t, sm, loginIP)

		adm := srv.admitGameClient(otherIP, buildGameLoginFrame(mId, tok), true)
		if !adm.allowed || !adm.authed || adm.cred != "token" || adm.session == nil {
			t.Fatalf("异 IP + 正确 token 必须放行: %+v", adm)
		}
	})

	t.Run("口令命中_异IP放行", func(t *testing.T) {
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: true}}, nil)
		withSession(t, sm, loginIP)

		adm := srv.admitGameClient(otherIP, buildGameLoginFrame(mId, pwdMd5), true)
		if !adm.allowed || !adm.authed || adm.cred != "pwd" || adm.session == nil {
			t.Fatalf("异 IP + 正确口令必须放行: %+v", adm)
		}
	})

	t.Run("凭证不符_观察模式回退白名单", func(t *testing.T) {
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: false}}, nil)
		withSession(t, sm, loginIP)

		adm := srv.admitGameClient(loginIP, buildGameLoginFrame(mId, wrongPwd), true)
		if !adm.allowed || adm.authed || adm.sessionDecided {
			t.Fatalf("观察模式必须回退白名单（不拒绝、不算凭证准入）: %+v", adm)
		}
	})

	t.Run("凭证不符_收紧模式拒绝_堵冒充", func(t *testing.T) {
		// 存量漏洞的形态：已登录用户伪造首包 m_id 冒充他人。
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: false}},
			func(c *config.GatewayConfig) { c.GameServer.GamePortAuth.RequireCredential = true })
		withSession(t, sm, loginIP)

		adm := srv.admitGameClient(loginIP, buildGameLoginFrame(mId, wrongPwd), true)
		if adm.allowed || adm.reason != reasonCredMismatch {
			t.Fatalf("收紧模式必须拒绝: %+v", adm)
		}
	})

	t.Run("无会话_口令命中_放行且不归属", func(t *testing.T) {
		// 会话已过期（心跳超时/被踢）但口令正确：放行，不归属任何会话。
		srv, _ := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: true}}, nil)

		adm := srv.admitGameClient(otherIP, buildGameLoginFrame(mId, pwdMd5), true)
		if !adm.allowed || !adm.authed || adm.cred != "pwd" || !adm.sessionDecided || adm.session != nil {
			t.Fatalf("无会话 + 口令正确应放行且无归属: %+v", adm)
		}
	})

	t.Run("无会话_口令不符_观察模式按白名单", func(t *testing.T) {
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: false}}, nil)
		// 同 IP 另有一个账号的会话 ⇒ 该 IP 在白名单里
		if _, err := sm.CreateSession("other", "10039", otherIP, ""); err != nil {
			t.Fatalf("建会话失败: %v", err)
		}

		adm := srv.admitGameClient(otherIP, buildGameLoginFrame(mId, wrongPwd), true)
		if !adm.allowed || adm.authed {
			t.Fatalf("观察模式 + 白名单内应放行: %+v", adm)
		}
	})

	t.Run("无会话_口令不符_收紧模式拒绝", func(t *testing.T) {
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: false}},
			func(c *config.GatewayConfig) { c.GameServer.GamePortAuth.RequireCredential = true })
		if _, err := sm.CreateSession("other", "10039", otherIP, ""); err != nil {
			t.Fatalf("建会话失败: %v", err)
		}

		adm := srv.admitGameClient(otherIP, buildGameLoginFrame(mId, wrongPwd), true)
		if adm.allowed || adm.reason != reasonCredMismatch {
			t.Fatalf("收紧模式必须拒绝（哪怕 IP 在白名单里）: %+v", adm)
		}
	})

	t.Run("库故障不拒人_观察与收紧都不拒", func(t *testing.T) {
		verifier := &fakeGameVerifier{
			errs: map[string]error{mId: errors.New("database is locked")},
		}
		for _, strict := range []bool{false, true} {
			srv, sm := newGameAuthFixture(t, verifier, func(c *config.GatewayConfig) {
				c.GameServer.GamePortAuth.RequireCredential = strict
			})
			withSession(t, sm, loginIP)

			adm := srv.admitGameClient(loginIP, buildGameLoginFrame(mId, pwdMd5), true)
			if !adm.allowed || adm.authed {
				t.Fatalf("库故障（strict=%v）必须回退白名单放行: %+v", strict, adm)
			}
		}
	})

	t.Run("解析失败回退旧行为", func(t *testing.T) {
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: true}}, nil)
		withSession(t, sm, loginIP)

		// 帧没读齐（分包超时）——哪怕口令是对的也不走凭证路径
		adm := srv.admitGameClient(loginIP, buildGameLoginFrame(mId, pwdMd5)[:10], false)
		if !adm.allowed || adm.authed {
			t.Fatalf("帧未齐必须回退: %+v", adm)
		}
		// 白名单外 ⇒ 与旧行为一样拒
		adm2 := srv.admitGameClient(otherIP, buildGameLoginFrame(mId, pwdMd5)[:10], false)
		if adm2.allowed || adm2.reason != reasonIPNotAllowed {
			t.Fatalf("帧未齐 + 白名单外必须拒: %+v", adm2)
		}
	})

	t.Run("非登录首帧回退旧行为", func(t *testing.T) {
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: true}}, nil)
		withSession(t, sm, loginIP)

		// 帧读齐了但正文不是登录包（非数字 m_id）
		adm := srv.admitGameClient(loginIP, buildGameLoginFrame("msp", pwdMd5), true)
		if !adm.allowed || adm.authed {
			t.Fatalf("非登录首帧必须回退: %+v", adm)
		}
	})

	t.Run("开关关闭_完全旧行为", func(t *testing.T) {
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: true}},
			func(c *config.GatewayConfig) { c.GameServer.GamePortAuth.Enabled = false })
		tok := withSession(t, sm, loginIP)

		// 白名单内：放行但不算凭证准入（槽位仍按 IP 计）
		adm := srv.admitGameClient(loginIP, buildGameLoginFrame(mId, tok), true)
		if !adm.allowed || adm.authed {
			t.Fatalf("开关关闭 + 白名单内应放行且非凭证准入: %+v", adm)
		}
		// 白名单外：拒（哪怕 token 是对的）
		adm2 := srv.admitGameClient(otherIP, buildGameLoginFrame(mId, tok), true)
		if adm2.allowed || adm2.reason != reasonIPNotAllowed {
			t.Fatalf("开关关闭 + 白名单外必须拒: %+v", adm2)
		}
	})

	t.Run("空口令字段不走token路径", func(t *testing.T) {
		srv, sm := newGameAuthFixture(t, &fakeGameVerifier{matched: map[string]bool{mId: false}}, nil)
		withSession(t, sm, loginIP)

		adm := srv.admitGameClient(loginIP, buildGameLoginFrame(mId, ""), true)
		if !adm.allowed || adm.authed {
			t.Fatalf("空口令字段必须回退: %+v", adm)
		}
	})

	t.Run("校验器缺失_无法验证时不拒人", func(t *testing.T) {
		// 收紧模式 + 校验器没接上：绝不允许把"无法验证"当成"验证不通过"
		srv, _ := newGameAuthFixture(t, nil, func(c *config.GatewayConfig) {
			c.GameServer.GamePortAuth.RequireCredential = true
		})

		adm := srv.admitGameClient(otherIP, buildGameLoginFrame(mId, pwdMd5), true)
		if adm.allowed || adm.reason != reasonIPNotAllowed {
			t.Fatalf("校验器缺失只能按白名单拒，不能按凭证拒: %+v", adm)
		}
	})
}

// TestGameSlotByMId 账号维度并发槽位（方案 D）。
func TestGameSlotByMId(t *testing.T) {
	sm := session.NewSessionManager(func() {}, func() {})

	for i := 0; i < 2; i++ {
		if !sm.TryAcquireGameSlotByMId("10038", 2) {
			t.Fatalf("第 %d 次获取应成功", i+1)
		}
	}
	if sm.TryAcquireGameSlotByMId("10038", 2) {
		t.Fatal("第 3 次应被拒（账号维度上限 2）")
	}
	if got := sm.GameSlotCountByMId("10038"); got != 2 {
		t.Fatalf("GameSlotCountByMId = %d，期望 2", got)
	}

	// 另一个账号互不影响
	if !sm.TryAcquireGameSlotByMId("10039", 2) {
		t.Fatal("另一账号不应被占额")
	}
	// IP 维度独立计数
	if !sm.TryAcquireGameSlot("203.0.113.9", 2) {
		t.Fatal("IP 维度应独立")
	}

	sm.ReleaseGameSlotByMId("10038")
	if !sm.TryAcquireGameSlotByMId("10038", 2) {
		t.Fatal("释放后应能再获取")
	}

	// 空 m_id 直接拒：不能把全部账号塞进同一个桶
	if sm.TryAcquireGameSlotByMId("", 2) {
		t.Fatal("空 m_id 应拒")
	}
	// max<=0 = 不限
	if !sm.TryAcquireGameSlotByMId("10040", 0) {
		t.Fatal("max<=0 应不限")
	}
}

// TestFindSessionByMIdAndToken (m_id, token) 双条件会话查找。
func TestFindSessionByMIdAndToken(t *testing.T) {
	sm := session.NewSessionManager(func() {}, func() {})

	tok, err := sm.CreateSession("acct", "10038", "198.51.100.7", "")
	if err != nil {
		t.Fatalf("建会话失败: %v", err)
	}
	if s, ok := sm.FindSessionByMIdAndToken("10038", tok); !ok || s.Account != "acct" {
		t.Fatal("正确的 (m_id, token) 应命中")
	}
	if _, ok := sm.FindSessionByMIdAndToken("10038", strings.Repeat("f", 64)); ok {
		t.Fatal("错误 token 不应命中")
	}
	if _, ok := sm.FindSessionByMIdAndToken("99999", tok); ok {
		t.Fatal("错误 m_id 不应命中")
	}
	if _, ok := sm.FindSessionByMIdAndToken("10038", ""); ok {
		t.Fatal("空 token 不应命中")
	}

	// 同 m_id 两个会话（stale reconnect 结转场景）：各自 token 都要能命中
	tok2, err := sm.CreateSession("acct", "10038", "203.0.113.9", "")
	if err != nil {
		t.Fatalf("建第二个会话失败: %v", err)
	}
	if _, ok := sm.FindSessionByMIdAndToken("10038", tok2); !ok {
		t.Fatal("第二个会话的 token 也应能命中")
	}
}
