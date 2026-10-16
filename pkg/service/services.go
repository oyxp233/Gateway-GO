package service

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/pvfdiff"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/session"
	"s4a21-gateway/pkg/utils"
)

// AccountService 账号服务。
type AccountService struct {
	db     *database.Database
	config *config.GatewayConfig
	logger *logger.ConsoleLogger

	// registerMu 串行化「限额判定 → 建号 → 落流水」这一段临界区（2026-10-13）。
	//
	// 为什么必须加锁：判据是"先 COUNT 再 INSERT"。两条 SQL 之间若插进另一个注册
	// 请求，两边都会数到"还没超"然后双双入库 —— 限额写的是 2，实际能注册 3、4 个。
	// 注册是低频动作（全服一天几十次），一把互斥锁的代价可以忽略。
	//
	// 注意：本结构体因此**不可按值拷贝**，全仓均以 *AccountService 传递。
	registerMu sync.Mutex
}

// NewAccountService 创建账号服务。
func NewAccountService(db *database.Database, cfg *config.GatewayConfig, logger *logger.ConsoleLogger) *AccountService {
	return &AccountService{db: db, config: cfg, logger: logger}
}

// Register 注册新账号。
func (s *AccountService) Register(name, passwordMd5 string) int {
	name = utils.TrimSpace(name)
	passwordMd5 = utils.TrimSpace(passwordMd5)

	if name == "" {
		return models.Err.AccountEmpty
	}
	if len(name) < 3 || len(name) > 20 {
		return models.Err.AccountLength
	}
	for _, ch := range name {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
			return models.Err.IllegalChars
		}
	}

	if passwordMd5 == "" {
		return models.Err.PasswordEmpty
	}
	if len(passwordMd5) != 32 {
		return models.Err.PasswordLength
	}
	for _, ch := range passwordMd5 {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return models.Err.PasswordLength
		}
	}

	// 检查是否已存在
	existing, _ := s.db.GetAccountByName(name)
	if existing != nil {
		return models.Err.AccountExists
	}

	// 这个纯数字名是否已经被人绑成 QQ 号？
	//
	// ★ 先到先得：数字 X 一旦被人绑成 QQ 号，X 就不能再被别人注册成账号名。
	//
	// 为什么这条保留、而绑定侧那个对称的检查放开了（见 service.SendBindCode）：
	// 注册的是**新玩家**，让他换个名字成本最低；反过来若放行，就是让"已经能用
	// X 登录"的 QQ 号主人降级成"必须记得带 qq: 前缀才能登"—— 让老能力倒退。
	// 宁可新玩家换个名，也不要已绑定的人踩坑。而绑定侧面对的是一个已经走到
	// 一半的存量玩家，拦下去他就是彻底用不了这个 QQ 号，代价不对称。
	//
	// 注：查库失败时**不拦**（照常注册）。绑定表只是可选增强，不该拖垮注册。
	// 用 AccountExists(1003) 而不是 QQNumberConflict(1034)：对玩家来说结果都是
	// "这个名字不能用"，1003 的现成文案正好；而 1034 的文案是绑定向的
	//（"该数字已被用作账号名"），从注册口抛出来方向刚好说反，只会把人绕晕。
	if isAllDigits(name) {
		owner, err := s.db.GetAccountByQQNumber(name)
		if err != nil {
			s.logger.Warn(fmt.Sprintf("查数字账号名是否已被绑定为 QQ 号失败（不拦注册）: name=%s err=%v", name, err))
		} else if owner != "" {
			return models.Err.AccountExists
		}
	}

	// 生成 salt 和 m_id
	salt, err := security.GenerateSalt()
	if err != nil {
		return models.Err.DatabaseError
	}
	// ★ m_id 必须纯数字：DNF 客户端把启动参数第 4 段（{m_id}）按数字解析，解析失败
	// 会回落成字面量 "invalid_id" 上报，服务端据此在游戏库建幽灵行，导致网关侧按
	// 真 m_id 关联的泡点 / 点券 / 查角色全部落空。账号名本身是数字时优先复用
	//（与原 .NET 网关「{m_id} 填账号名」口径一致）。详见 database.AllocateNumericMId。
	mId, err := s.db.AllocateNumericMId(name)
	if err != nil {
		s.logger.Error(fmt.Sprintf("分配 m_id 失败: name=%s err=%v", name, err))
		return models.Err.DatabaseError
	}

	pwdHash := security.DeriveHash(passwordMd5, salt)
	s.logger.Info(fmt.Sprintf("注册: name=%s m_id=%s", name, mId))

	account := &database.Account{
		MId:       mId,
		Name:      name,
		PwdHash:   pwdHash,
		Salt:      salt,
		CreatedAt: utils.NowUnix(),
	}

	if err := s.db.InsertAccount(account); err != nil {
		s.logger.Error(fmt.Sprintf("注册失败: %v", err))
		return models.Err.DatabaseError
	}

	return models.Err.Ok
}

// RegisterWithLimit 带注册限额的注册：限额判定与建号在同一临界区内完成。
//
// 返回 (models.Err.Ok, "") 表示注册成功；否则返回错误码与文案。
// message 为空时调用方用 errorMessages[code] 兜底。
//
// 调用方（auth.handler）必须在**客户端 IP 可用的地方**调用它 —— 原 Register
// 不带来源信息，算不出限额。clientIP 由 TCP 远端地址得到（不是客户端自填）。
func (s *AccountService) RegisterWithLimit(name, passwordMd5, ip, machineID string) (int, string) {
	name = utils.TrimSpace(name)
	ip = utils.TrimSpace(ip)
	machineID = utils.TrimSpace(machineID)

	s.registerMu.Lock()
	defer s.registerMu.Unlock()

	if code, msg := s.CheckRegisterLimit(ip, machineID); code != models.Err.Ok {
		// 单独再打一条**带账号名**的拒绝日志。
		//
		// CheckRegisterLimit 内部那条明细只有 IP/机器码 —— 玩家来问"我注册不了"
		// 时，运营手里只有账号名，没有账号名的日志等于查不到。这与登录路径的
		// 「拒绝重复登录: 账号=…」保持同一风格，排障时一眼能对上。
		s.logger.Warn(fmt.Sprintf("拒绝注册: 账号=%s IP=%s machine=%s 原因码=%d",
			name, ip, maskMachineID(machineID), code))
		return code, msg
	}

	code := s.Register(name, passwordMd5)
	if code != models.Err.Ok {
		return code, ""
	}

	// 落流水。★ 写失败**不改判注册结果**：账号已经建好了，把玩家挡回去只会让他
	// 重试、然后撞上 1003「账号已存在」，反而更像"注册功能坏了"。
	// 代价是这一条注册不占后续配额（限额被小幅放松），可接受。
	mID := ""
	if acc, err := s.db.GetAccountByName(name); err == nil && acc != nil {
		mID = acc.MId
	}
	if err := s.db.InsertRegistrationLog(name, mID, ip, machineID, utils.NowUnix()); err != nil {
		s.logger.Error(fmt.Sprintf("写注册流水失败（不影响注册成功）: account=%s ip=%s err=%v", name, ip, err))
	}

	return models.Err.Ok, ""
}

// CheckRegisterLimit 判定本次注册是否触顶（2026-10-13）。
//
// 返回 (models.Err.Ok, "") 表示放行；否则返回错误码与给玩家看的文案。
// 两条判据的取值都走**运行时快照**（config.RegisterLimitSnapshot）——
// 管理员在后台改完立即生效，不用重启网关。
//
// 语义（与 config.RegisterLimitSection 的注释保持一致）：
//   - 总开关关 ⇒ 一律放行（一键回滚）。
//   - ip 为空 / machineID 为空 ⇒ **跳过该维度**，不是当成同一个空值去计数。
//     机器码缺失是常态（老登录器不带该字段），若把空串当共同机器，全服瞬间注册不了。
//   - 阈值 <= 0 ⇒ 该维度不限制。
//   - 查库失败 ⇒ **放行**并记 WARN。限额是防刷的软约束，注册是玩家的硬需求；
//     库抖一下就把全服注册堵死，代价远大于"这一波没限住"。
func (s *AccountService) CheckRegisterLimit(ip, machineID string) (int, string) {
	if s == nil || s.config == nil || s.db == nil {
		return models.Err.Ok, ""
	}
	limit := s.config.RegisterLimitSnapshot()
	if !limit.Enabled {
		return models.Err.Ok, ""
	}

	// ① 同一来源 IP 的当日注册数。
	if limit.PerIPPerDay > 0 && ip != "" {
		n, err := s.db.CountRegistrationsByIPSince(ip, startOfToday())
		if err != nil {
			s.logger.Warn(fmt.Sprintf("统计同 IP 当日注册数失败（跳过 IP 限额）: ip=%s err=%v", ip, err))
		} else if n >= limit.PerIPPerDay {
			s.logger.Warn(fmt.Sprintf("注册被 IP 限额拦下: ip=%s 今日已注册=%d 上限=%d", ip, n, limit.PerIPPerDay))
			return models.Err.RegisterIpLimit,
				fmt.Sprintf("同一网络今日注册账号已达上限（%d 个），请明天再试或联系管理员", limit.PerIPPerDay)
		}
	}

	// ② 同一机器码的累计注册数（不限时间窗）。
	if limit.PerMachine > 0 && machineID != "" {
		n, err := s.db.CountRegistrationsByMachine(machineID)
		if err != nil {
			s.logger.Warn(fmt.Sprintf("统计同机器码注册数失败（跳过机器限额）: machine=%s err=%v", maskMachineID(machineID), err))
		} else if n >= limit.PerMachine {
			s.logger.Warn(fmt.Sprintf("注册被机器限额拦下: machine=%s 已注册=%d 上限=%d",
				maskMachineID(machineID), n, limit.PerMachine))
			return models.Err.RegisterMachineLimit,
				fmt.Sprintf("该设备注册账号数已达上限（%d 个），请联系管理员", limit.PerMachine)
		}
	}

	return models.Err.Ok, ""
}

// maskMachineID 给机器码脱敏后再进日志。
//
// 机器码由 MAC 推导，属于设备标识：日志会被打包、会被截图、会被贴进群里排障，
// 完整值落盘只是无谓的扩散。保留前 4 后 4 足够在排障时对齐"是不是同一台"。
func maskMachineID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:4] + "***" + id[len(id)-4:]
}

// Login 登录账号。
func (s *AccountService) Login(name, passwordMd5, deviceSecret, ip string) *models.LoginResult {
	name = utils.TrimSpace(name)
	passwordMd5 = utils.TrimSpace(passwordMd5)

	if name == "" {
		return &models.LoginResult{ErrorCode: models.Err.AccountEmpty}
	}
	if passwordMd5 == "" {
		return &models.LoginResult{ErrorCode: models.Err.PasswordEmpty}
	}

	account, err := s.db.GetAccountByName(name)
	if err != nil {
		return &models.LoginResult{ErrorCode: models.Err.DatabaseError}
	}
	if account == nil {
		// 账号不存在也要花掉与「密码错误」同量级的时间，否则响应时延本身就是
		// 一个用户名枚举接口（P2-1）。详见 equalizeLoginTiming 的注释。
		equalizeLoginTiming(passwordMd5)
		return &models.LoginResult{ErrorCode: models.Err.AccountNotFound}
	}

	// 检查锁定
	now := utils.NowUnix()
	if account.LockoutUntil > now {
		return &models.LoginResult{ErrorCode: models.Err.AccountLocked}
	}

	// 密码验证
	//
	// 两条路径，与 .NET 原网关 VerifyPassword 一致：
	//   - 网关自注册/改密的账号：salt 非空，走 SHA256(MD5(pwd) + salt) 加盐比对；
	//   - 从游戏库迁移进来的老账号：游戏库没有 salt 列，password_hash 存的就是
	//     客户端上报的 pwd_md5 明文，salt 为空，此时直接按 MD5 比对（大小写归一）。
	//     漏掉这条分支会导致所有迁移账号永远登录失败。
	if !verifyAccountPassword(passwordMd5, account) {
		// 登录失败
		account.FailedLoginCount++
		if account.FailedLoginCount >= 5 {
			account.LockoutUntil = now + 300 // 5 分钟锁定
		}
		s.db.UpdateAccountLogin(name, ip, account.FailedLoginCount, account.LockoutUntil)
		return &models.LoginResult{ErrorCode: models.Err.WrongPassword}
	}

	// 重置失败计数
	s.db.UpdateAccountLogin(name, ip, 0, 0)

	// 设备凭证处理
	deviceChanged := false
	if s.config.Device.EnforceBinding {
		if account.DeviceSecret != "" && account.DeviceSecret != deviceSecret {
			// 检查冷却期
			cooldownMs := int64(s.config.Device.RotationCooldownMinutes) * 60
			if account.DeviceSecretLastRotated+cooldownMs > now {
				return &models.LoginResult{ErrorCode: models.Err.DeviceRotationCooldown}
			}
			// 强制绑定：拒绝
			return &models.LoginResult{ErrorCode: models.Err.DeviceChanged}
		}
	} else {
		// 非强制绑定：轮换密钥
		if account.DeviceSecret != deviceSecret {
			newSecret, _ := security.GenerateToken()
			s.db.UpdateAccountDeviceSecret(name, newSecret, now)
			s.db.InsertDeviceHistory(account.MId, newSecret, ip)
			s.db.TrimDeviceHistory(account.MId, s.config.Device.MaxHistory)
			deviceChanged = true
		}
	}

	// 生成 token
	token, err := security.GenerateToken()
	if err != nil {
		return &models.LoginResult{ErrorCode: models.Err.DatabaseError}
	}

	// 拼装启动参数
	launchArgs := s.buildLaunchArgs(account.MId, token)

	return &models.LoginResult{
		ErrorCode:     models.Err.Ok,
		Token:         token,
		Cera:          account.Cera,
		MId:           account.MId,
		DeviceSecret:  account.DeviceSecret,
		DeviceChanged: deviceChanged,
		LaunchArgs:    launchArgs,
	}
}

// ChangePassword 修改密码。
func (s *AccountService) ChangePassword(name, oldPwdMd5, newPwdMd5 string) int {
	name = utils.TrimSpace(name)
	oldPwdMd5 = utils.TrimSpace(oldPwdMd5)
	newPwdMd5 = utils.TrimSpace(newPwdMd5)

	if name == "" {
		return models.Err.AccountEmpty
	}
	if oldPwdMd5 == "" {
		return models.Err.PasswordEmpty
	}
	if newPwdMd5 == "" {
		return models.Err.PasswordEmpty
	}
	if oldPwdMd5 == newPwdMd5 {
		return models.Err.SamePassword
	}

	account, err := s.db.GetAccountByName(name)
	if err != nil || account == nil {
		return models.Err.AccountNotFound
	}

	// 验证旧密码（兼容游戏库迁移进来的空 salt 老账号）
	if !verifyAccountPassword(oldPwdMd5, account) {
		return models.Err.WrongPassword
	}

	// 生成新 salt
	newSalt, err := security.GenerateSalt()
	if err != nil {
		return models.Err.DatabaseError
	}
	newHash := security.DeriveHash(newPwdMd5, newSalt)

	if err := s.db.UpdateAccountPwd(name, newHash, newSalt); err != nil {
		return models.Err.DatabaseError
	}

	// 把密码 MD5 同步写回游戏库 accounts.password_hash。
	// 游戏库无 salt 列，存的就是客户端上报的 pwd_md5；服务端补丁的密码校验
	// 直接比对这一列，不同步会导致改过密码的账号被服务端拦在门外。
	// 只写现有列、不改 schema；失败仅记日志，不影响网关侧改密结果。
	if err := s.db.SyncPasswordHashToGameDb(name, newPwdMd5); err != nil {
		s.logger.Warn(fmt.Sprintf("密码同步游戏库失败（不影响网关侧改密）: 账号=%s, 错误=%v", name, err))
	}

	s.logger.Info(fmt.Sprintf("修改密码: %s", name))
	return models.Err.Ok
}

// IsBanned 检查账号是否被封禁。
func (s *AccountService) IsBanned(name string) (bool, error) {
	return s.db.IsBanned(name)
}

// UpdateHeartbeat 更新心跳。
func (s *AccountService) UpdateHeartbeat(name string) error {
	return s.db.UpdateAccountHeartbeat(name)
}

// GetAccountInfo 获取账号信息。
//
// 点券三列优先取**游戏库**：游戏内的消费/充值都发生在游戏库，
// 网关库只是镜像（泡点双写、游戏库消费不回写），直接展示镜像会
// 出现"后台显示有点券、游戏内为 0/对不上"。游戏库未配置或查询
// 失败时回退网关库值。
func (s *AccountService) GetAccountInfo(name string) (*models.AccountInfo, error) {
	account, err := s.db.GetAccountByName(name)
	if err != nil || account == nil {
		return nil, nil
	}
	info := &models.AccountInfo{
		MId:            account.MId,
		Cera:           account.Cera,
		TokenCera:      account.TokenCera,
		HappyTokenCera: account.HappyTokenCera,
	}
	if cera, token, happy, ok := s.db.GetCurrencyTripleByMId(account.MId); ok {
		info.Cera, info.TokenCera, info.HappyTokenCera = cera, token, happy
	}
	return info, nil
}

// ListAccounts 分页查询账号。
//
// cera 同 GetAccountInfo：游戏库为准，游戏库无该账号行时回退网关库镜像。
func (s *AccountService) ListAccounts(keyword string, page, pageSize int) (int, []map[string]interface{}) {
	total, accounts, _ := s.db.ListAccounts(keyword, page, pageSize)
	result := make([]map[string]interface{}, 0, len(accounts))

	// QQ 号绑定一次批量取回（一页可能 500 个账号，逐行查就是 500 次 SQL）。
	names := make([]string, 0, len(accounts))
	mIds := make([]string, 0, len(accounts))
	for _, a := range accounts {
		names = append(names, a.Name)
		mIds = append(mIds, a.MId)
	}
	qqBindings, err := s.db.QQNumbersByAccounts(names)
	if err != nil {
		// 绑定表读不出来（例如老库没跑迁移）不该让整个账号列表失败 ——
		// QQ 号是附加展示，缺了不影响账号管理的主要功能。
		if s.logger != nil {
			s.logger.Warn(fmt.Sprintf("批量查 QQ 绑定失败（列表照常返回，QQ 号显示为空）: %v", err))
		}
		qqBindings = map[string]string{}
	}

	// G-11（2026-10-04 审查）：三币种也改成一次批量取回（原先逐行调
	// GetCurrencyTripleByMId = 一页最多 500 次跨库查询）。
	ceraByMId := s.db.GetCurrencyTriplesByMIds(mIds)

	for _, a := range accounts {
		cera := a.Cera
		if t, ok := ceraByMId[a.MId]; ok {
			cera = t.Cera
		}
		result = append(result, map[string]interface{}{
			"name": a.Name, "m_id": a.MId, "cera": cera,
			"last_login_at": a.LastLoginAt, "last_login_ip": a.LastLoginIP,
			"last_heartbeat": a.LastHeartbeat,
			// created_at 是**网关库**写入时刻（导入批次会挤在同一秒），只用于排序兜底。
			"created_at": a.CreatedAt,
			// game_created_at 才是玩家真实注册时间（游戏库 accounts.created_at，UTC 文本）。
			// 空串 = 游戏库还没有该账号（注册后没进过游戏），前端显示网关库时间并标注。
			"game_created_at": a.GameCreatedAt,
			// banned = 管理员封禁（要解封）；locked = 登录失败自动锁定（到期自解，可手动解锁）。
			// 两者是不同维度，界面上分开展示，不合成一个"异常"状态。
			"banned": a.Banned,
			"locked": a.Locked,
			// qq_number = 绑定的 QQ 号（空串 = 未绑定）。
			// 界面上放在「帐号」列第二行展示，不额外占一列。
			"qq_number": qqBindings[a.Name],
		})
	}
	return total, result
}

// ResetAllPasswords 批量重置密码。
func (s *AccountService) ResetAllPasswords(passwordMd5 string, dryRun bool) map[string]interface{} {
	names, _ := s.db.ListAllAccountNames()
	total := len(names)
	updated := 0
	notInGameDb := 0

	if !dryRun {
		for _, name := range names {
			if err := s.resetSinglePassword(name, passwordMd5); err != nil {
				notInGameDb++
				continue
			}
			updated++
		}
	}

	return map[string]interface{}{
		"ok": true, "message": "批量重置完成", "dry_run": dryRun,
		"total": total, "updated": updated, "not_in_game_db": notInGameDb,
	}
}

// resetSinglePassword 为账号重置密码，返回错误表示该账号无法处理。
//
// 同时把新密码的 MD5 写回游戏库，保证服务端补丁的密码校验不会拦住该账号。
func (s *AccountService) resetSinglePassword(name, passwordMd5 string) error {
	account, err := s.db.GetAccountByName(name)
	if err != nil || account == nil {
		return fmt.Errorf("账号不存在")
	}

	salt, err := security.GenerateSalt()
	if err != nil {
		return err
	}
	hash := security.DeriveHash(passwordMd5, salt)
	if err := s.db.ResetAccountPwd(name, hash, salt); err != nil {
		return err
	}

	// 同步游戏库；失败不阻断（与 .NET 原网关一致：仅记日志）。
	if err := s.db.SyncPasswordHashToGameDb(name, passwordMd5); err != nil {
		s.logger.Warn(fmt.Sprintf("重置密码同步游戏库失败: 账号=%s, 错误=%v", name, err))
	}
	return nil
}

// MigrateAccountsFromGameDb 从游戏库迁移账号。
func (s *AccountService) MigrateAccountsFromGameDb() (*database.MigrationResult, error) {
	return s.db.MigrateAccountsFromGameDb()
}

// FindUnsupportedLaunchArgsPlaceholders 检查启动参数模板中的非法占位符。
func FindUnsupportedLaunchArgsPlaceholders(format string) []string {
	var unsupported []string
	for i := 0; i < len(format); i++ {
		if format[i] != '{' {
			continue
		}
		end := i + 1
		for end < len(format) && format[end] != '}' {
			end++
		}
		if end >= len(format) {
			// 未闭合的 { 当作占位符处理（异常格式）
			placeholder := format[i:]
			if !containsStr(SupportedLaunchArgsPlaceholders, placeholder) {
				unsupported = append(unsupported, placeholder)
			}
			break
		}
		placeholder := format[i : end+1]
		if !containsStr(SupportedLaunchArgsPlaceholders, placeholder) {
			unsupported = append(unsupported, placeholder)
		}
		i = end
	}
	return unsupported
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// SupportedLaunchArgsPlaceholders 支持的启动参数占位符。
var SupportedLaunchArgsPlaceholders = []string{"{ip}", "{port}", "{m_id}", "{token}"}

// DefaultLaunchArgsFormat 启动参数模板的代码默认值，转发自 config 包，
// 保证“配置默认值”与“启动校验基准”只有一份真相。
//
// 注意 `{token}` 必须在第 5 段（紧随 `{m_id}`，其后依次是 `1?0?6?0?2?1`）——
// 这是生产口径，依据见 config 包同名常量的注释。写反会导致游戏端把写死的常量当 token，
// 表现为玩家登录成功但连不上游戏。
const DefaultLaunchArgsFormat = config.DefaultLaunchArgsFormat

func (s *AccountService) buildLaunchArgs(mId, token string) string {
	format := s.config.GameServer.LaunchArgsFormat
	// 替换占位符
	ip := s.config.GameServer.PublicIP
	port := fmt.Sprintf("%d", s.config.Gateway.ProxyPort)

	result := format
	result = replaceAll(result, "{ip}", ip)
	result = replaceAll(result, "{port}", port)
	result = replaceAll(result, "{m_id}", mId)
	result = replaceAll(result, "{token}", token)

	return result
}

func replaceAll(s, old, new string) string {
	result := ""
	for {
		idx := indexOf(s, old)
		if idx < 0 {
			return result + s
		}
		result += s[:idx]
		result += new
		s = s[idx+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// AdminService 管理后台服务。
type AdminService struct {
	db     *database.Database
	config *config.GatewayConfig
	logger *logger.ConsoleLogger
}

// NewAdminService 创建管理后台服务。
func NewAdminService(db *database.Database, cfg *config.GatewayConfig, logger *logger.ConsoleLogger) *AdminService {
	return &AdminService{db: db, config: cfg, logger: logger}
}

// ValidateAuthKey 验证管理密钥。
func (s *AdminService) ValidateAuthKey(key string) bool {
	return security.ConstantTimeEquals(key, s.config.Admin.AuthKey)
}

// ResetPassword 重置单账号密码。
//
// 同时把新密码 MD5 写回游戏库 accounts.password_hash，避免玩家用新密码过了
// 网关验证却被游戏服务端拦住（服务端校验的就是那一列）。
func (s *AdminService) ResetPassword(account, newPwdMd5 string) int {
	account = utils.TrimSpace(account)
	if account == "" {
		return models.Err.AccountEmpty
	}

	existing, _ := s.db.GetAccountByName(account)
	if existing == nil {
		return models.Err.AccountNotFound
	}

	salt, err := security.GenerateSalt()
	if err != nil {
		return models.Err.DatabaseError
	}
	hash := security.DeriveHash(newPwdMd5, salt)

	if err := s.db.ResetAccountPwd(account, hash, salt); err != nil {
		return models.Err.DatabaseError
	}

	// 同步游戏库；失败仅告警，不改动已成功的网关侧结果。
	if err := s.db.SyncPasswordHashToGameDb(account, newPwdMd5); err != nil {
		if s.logger != nil {
			s.logger.Warn(fmt.Sprintf("重置密码同步游戏库失败（不影响网关侧）: 账号=%s, 错误=%v", account, err))
		}
	}

	return models.Err.Ok
}

// ResetDeviceBinding 解除指定账号的设备绑定。
//
// 返回错误码（models.Err.*），语义与 ResetPassword 一致：
//   - Err.Ok：已成功解除，调用方可配合踢下线让新设备立即生效；
//   - Err.AccountEmpty：账号名为空；
//   - Err.AccountNotFound：账号不存在；
//   - Err.DatabaseError：落库失败。
//
// 说明：原实现 `return 0 // 简化` 是空操作，接口对外谎报成功，
// 现改为真实清除 accounts 的设备字段与 device_history 历史表。
func (s *AdminService) ResetDeviceBinding(account string) int {
	account = utils.TrimSpace(account)
	if account == "" {
		return models.Err.AccountEmpty
	}

	existing, err := s.db.GetAccountByName(account)
	if err != nil {
		return models.Err.DatabaseError
	}
	if existing == nil {
		return models.Err.AccountNotFound
	}

	if err := s.db.ClearDeviceSecret(account); err != nil {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("解除设备绑定失败: 账号=%s, 错误=%v", account, err))
		}
		return models.Err.DatabaseError
	}

	if s.logger != nil {
		s.logger.Info(fmt.Sprintf("已解除设备绑定: 账号=%s, m_id=%s", account, existing.MId))
	}
	return models.Err.Ok
}

// BroadcastItems 全服发放。
func (s *AdminService) BroadcastItems(req *models.BroadcastRequest) map[string]interface{} {
	if req == nil || len(req.Items) == 0 {
		return map[string]interface{}{"ok": false, "error": "物品列表不能为空"}
	}

	items := make([]database.MailItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = database.MailItem{
			ItemTemplateId: item.ItemTemplateId,
			Count:          item.Count,
			Kind:           derefInt(item.Kind, 3),
			ItemType:       derefInt(item.ItemType, 0),
		}
	}

	// 查询目标角色
	var characters []database.Character
	if req.TargetCharacterId != nil && *req.TargetCharacterId > 0 {
		// 指定角色
		char, err := s.db.GetCharacter(*req.TargetCharacterId)
		if err != nil || char == nil {
			return map[string]interface{}{"ok": false, "error": "角色不存在"}
		}
		characters = append(characters, *char)
	} else if req.TargetAccountId != nil && *req.TargetAccountId > 0 {
		// 指定账号
		var err error
		characters, err = s.db.GetCharactersByAccount(*req.TargetAccountId)
		if err != nil {
			return map[string]interface{}{"ok": false, "error": err.Error()}
		}
	} else {
		// 全服
		var err error
		characters, err = s.db.GetAllAliveCharacters()
		if err != nil {
			return map[string]interface{}{"ok": false, "error": err.Error()}
		}
	}

	if len(characters) == 0 {
		return map[string]interface{}{"ok": false, "error": "未找到符合条件的角色"}
	}

	// 检查角色数上限
	if s.config.Admin.BroadcastTotalCharacterLimit > 0 && len(characters) > s.config.Admin.BroadcastTotalCharacterLimit {
		return map[string]interface{}{"ok": false, "error": fmt.Sprintf("角色数 %d 超过上限 %d", len(characters), s.config.Admin.BroadcastTotalCharacterLimit)}
	}

	sent := 0
	failed := 0
	errors := []string{}

	for _, char := range characters {
		if err := s.db.SendMailToCharacter(char.CharacterId, char.Name, "系统邮件", "", items, 720); err != nil {
			failed++
			errors = append(errors, fmt.Sprintf("角色 %d: %v", char.CharacterId, err))
			if len(errors) >= 50 {
				break
			}
		} else {
			sent++
		}
	}

	result := map[string]interface{}{
		"ok": true, "total": len(characters), "sent": sent, "failed": failed,
	}
	if len(errors) > 0 {
		result["errors"] = errors
	}
	return result
}

// GetRoles 查询角色。
func (s *AdminService) GetRoles(account string) (*struct {
	ErrorCode int
	Roles     []models.RoleInfo
	Message   string
}, error) {
	dbRoles, err := s.db.GetRolesByAccount(account)
	if err != nil {
		return &struct {
			ErrorCode int
			Roles     []models.RoleInfo
			Message   string
		}{ErrorCode: models.Err.DatabaseError, Roles: nil, Message: "查询失败"}, nil
	}

	// 转换 database.RoleInfo -> models.RoleInfo
	roles := make([]models.RoleInfo, len(dbRoles))
	for i, r := range dbRoles {
		roles[i] = models.RoleInfo{
			CharacterId: r.CharacterId,
			Name:        r.Name,
			Level:       r.Level,
			Job:         r.Job,
			GrowType:    r.GrowType,
			JobName:     r.JobName,
			Exp:         r.Exp,
		}
	}

	return &struct {
		ErrorCode int
		Roles     []models.RoleInfo
		Message   string
	}{ErrorCode: models.Err.Ok, Roles: roles, Message: "查询成功"}, nil
}

// SendItems 定向发物品。
func (s *AdminService) SendItems(characterId int64, items []models.MailItemRequest) *struct {
	ErrorCode int
	Message   string
} {
	dbItems := make([]database.MailItem, len(items))
	for i, item := range items {
		dbItems[i] = database.MailItem{
			ItemTemplateId: item.ItemTemplateId,
			Count:          item.Count,
			Kind:           derefInt(item.Kind, 3),
			ItemType:       derefInt(item.ItemType, 0),
		}
	}

	if err := s.db.SendMail(characterId, dbItems); err != nil {
		return &struct {
			ErrorCode int
			Message   string
		}{ErrorCode: models.Err.DatabaseError, Message: err.Error()}
	}

	return &struct {
		ErrorCode int
		Message   string
	}{ErrorCode: models.Err.Ok, Message: "邮件已投递"}
}

// ClearMailbox 清空邮箱。
func (s *AdminService) ClearMailbox(characterId int64) (int, int) {
	count, err := s.db.ClearMailbox(characterId)
	if err != nil {
		return models.Err.DatabaseError, 0
	}
	return models.Err.Ok, int(count)
}

// verifyAccountPassword 校验登录密码，兼容两代账号存储格式。
//
// 两种情形：
//  1. salt 非空 —— 网关侧自注册或改密后的账号，比对 SHA256(MD5(pwd) + salt)；
//  2. salt 为空 —— 从游戏库迁移进来的老账号。服务端 v11 的 accounts 表没有 salt 列，
//     password_hash 直接存客户端上报的 pwd_md5，因此这里按 MD5 直比。
//     MD5 十六进制语义上不区分大小写，比对前统一转小写再走恒定时间比较。
//
// 该函数是 AccountService.Login 的密码判定唯一入口，新增登录路径请复用它，
// 不要各自实现，避免又出现「迁移账号无法登录」这类不一致。
// deriveHashFn 默认指向 security.DeriveHash。
//
// 之所以抽成包级变量：P2-1 的时序抹平没有可观察的返回值（算完就丢），
// 只能靠"这条路径到底算了几次哈希"来断言。测试用它挂计数钩子，
// 见 pkg/service/login_timing_test.go。
var deriveHashFn = security.DeriveHash

// timingEqualizerSalt 是「账号不存在」分支用来抹平时延的固定假 salt。
// 用常量而不是随机值：真实 salt 来自库，账号不存在时无 salt 可用；
// 常量保证每次输入长度一致、耗时可预期。
const timingEqualizerSalt = "s4a21-login-timing-equalizer"

// equalizeLoginTiming 让「账号不存在」这条路也付出一次加盐哈希的 CPU 代价。
//
// 为什么（P2-1）：`account == nil` 时直接返回 AccountNotFound，而「密码错误」
// 要先算一次 SHA256(MD5+salt)、再写一次失败计数才返回 —— 两条路径的响应时延差
// 足以被用来枚举有效用户名（账号不存在快、密码错慢）。
//
// 抹平到什么程度：哈希部分完全抹平，这是时延里最大的一块。
// 残余差异有两处，都已知且可接受：
//   - 「密码错误」还有一次 UpdateAccountLogin 写库 —— 不写库就无法等价复现，
//     而写库会污染数据；本机 SQLite 单次写耗时被哈希开销盖住。
//   - 迁移进来的老账号（salt 为空）走的是纯 MD5 比对、不经过哈希，
//     所以那条路径比这里更快 —— 但它是少数且是历史账号。
func equalizeLoginTiming(passwordMd5 string) {
	_ = deriveHashFn(passwordMd5, timingEqualizerSalt)
}

func verifyAccountPassword(inputMd5 string, account *database.Account) bool {
	if account == nil {
		return false
	}

	if account.Salt == "" {
		return security.ConstantTimeEquals(
			strings.ToLower(strings.TrimSpace(inputMd5)),
			strings.ToLower(strings.TrimSpace(account.PwdHash)),
		)
	}

	computed := deriveHashFn(inputMd5, account.Salt)
	return security.ConstantTimeEquals(computed, account.PwdHash)
}

// VerifyAccountCredential 校验游戏口首包凭证是否对应该账号口令。
//
// 实现 pkg/proxy.GameCredentialVerifier —— 游戏口准入（方案 D）的
// 「账号口令」凭证路径用。之所以放在 service 层：verifyAccountPassword
// 是全网关唯一的密码判定入口（含迁移账号的「空 salt 直比 MD5」分支），
// 游戏口必须复用它，不能在 proxy 包里再实现一遍。
//
// 返回值的三种含义：
//   - (true, nil)：口令匹配（含 salt 为空的迁移账号的 MD5 直比分支）；
//   - (false, nil)：**确定**不匹配，或网关库没有这个 m_id 的账号
//     （m_id 全部由网关分配，没有账号即说明这不是登录器链路产物）；
//   - (false, err)：网关库读取失败 —— 调用方必须按「无法验证」处理
//     （回退旧行为 + 告警），绝不能因网关自身故障拒掉正常玩家。
func (s *AccountService) VerifyAccountCredential(mId, pwdField string) (bool, error) {
	acct, err := s.db.GetAccountByMId(strings.TrimSpace(mId))
	if err != nil {
		return false, err
	}
	if acct == nil {
		return false, nil
	}
	return verifyAccountPassword(pwdField, acct), nil
}

func derefInt(p *int, def int) int {
	if p != nil {
		return *p
	}
	return def
}

// BanService 封禁服务。
type BanService struct {
	db         *database.Database
	sessionMgr interface{}
	logger     *logger.ConsoleLogger
}

// NewBanService 创建封禁服务。
func NewBanService(db *database.Database, sessionMgr interface{}) *BanService {
	return &BanService{db: db, sessionMgr: sessionMgr, logger: logger.Global()}
}

// BanAccount 封禁账号。
func (s *BanService) BanAccount(account, reason string) map[string]interface{} {
	if err := s.db.BanAccount(account, reason); err != nil {
		return map[string]interface{}{"ok": false, "error": err.Error()}
	}
	kicked := 0
	if s.sessionMgr != nil {
		if sm, ok := s.sessionMgr.(interface {
			KickAccount(string) (int, []string)
		}); ok {
			kicked, _ = sm.KickAccount(account)
		}
	}
	if s.logger != nil {
		s.logger.Warn(fmt.Sprintf("[BAN] 封禁账号 %s（原因：%s），已踢下线 %d 个会话", account, reason, kicked))
	}
	return map[string]interface{}{"ok": true, "kicked": kicked}
}

// UnbanAccount 解封账号。
func (s *BanService) UnbanAccount(account string) map[string]interface{} {
	removed, err := s.db.UnbanAccount(account)
	if err != nil {
		return map[string]interface{}{"ok": false, "error": err.Error()}
	}
	return map[string]interface{}{"ok": true, "removed": removed}
}

// QueryBans 查询封禁列表。
func (s *BanService) QueryBans(keyword string, page, pageSize int) (int, []map[string]interface{}) {
	total, entries, err := s.db.QueryBans(keyword, page, pageSize)
	if err != nil {
		return 0, nil
	}
	rows := make([]map[string]interface{}, len(entries))
	for i, e := range entries {
		rows[i] = map[string]interface{}{"name": e.Name, "reason": e.Reason, "banned_at": e.BannedAt}
	}
	return total, rows
}

// PvfService PVF 指纹服务。
// deltaFileName 是增量包在 DeltaDir 里的固定文件名。
//
// 只保留一份：客户端只可能从「上一版」升到「当前版」，更老的版本没有对应 delta。
const deltaFileName = "current.delta"

type PvfService struct {
	config *config.GatewayConfig
	logger *logger.ConsoleLogger
	mu     sync.RWMutex
	info   *models.PvfInfo
	mode   string
	// delta 是当前可下发的「上一版 → 当前版」增量包，可能为 nil。
	// 仅在 pvf_delta/current.delta 存在**且它的 to_hash == 当前 PVF hash** 时才有值
	// —— 见 loadDeltaLocked 的说明。
	delta *models.PvfDeltaInfo
	// histMu 只保护 pvf_history/index.json 的读-改-写（与 s.mu 互不嵌套，
	// 锁顺序恒为 histMu → s.mu，反向不存在）。
	histMu sync.Mutex
	// replaceMu 串行化 ReplacePvf 的整条链路（备份→写盘→刷新→重建 delta→入历史）。
	//
	// G-6（2026-10-04 审查）：原先全程无互斥，并发上传时第二次 BackupFile 会把
	// 第一次刚写好的新版备份成 .bak ⇒ rebuildDelta 产出 from == to 的**自差分**
	// ——这正是 09-30「全体旧版客户端进不去」的成因形态。
	// 跨进程那一层（upload-pvf 在 gateway 与 admin 都注册）另见 acquirePvfReplaceLock。
	replaceMu sync.Mutex
	// deltaGroup 合并「同一个 from 的并发按需增量生成」（G-4 / G-10）。
	deltaGroup keyedGroup
}

// NewPvfService 创建 PVF 服务。
func NewPvfService(cfg *config.GatewayConfig, logger *logger.ConsoleLogger) *PvfService {
	return &PvfService{
		config: cfg,
		logger: logger,
		mode:   "file",
	}
}

// GetPvfInfo 获取 PVF 信息。缓存未命中时懒加载（加锁，避免并发重复计算）。
func (s *PvfService) GetPvfInfo() *models.PvfInfo {
	s.mu.RLock()
	info := s.info
	s.mu.RUnlock()
	if info != nil {
		return info
	}

	s.RefreshCache()

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.info
}

// GetSourceMode 获取来源模式。
func (s *PvfService) GetSourceMode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

// PvfPath 返回网关管理的 PVF 文件路径（即 config.Pvf.FilePath）。
//
// 用它做「另一条上传入口是否指向同一个文件」的守卫：服务端 PVF 与网关管理的
// PVF 必须是同一个文件，否则走那条入口会绕过增量更新链路与指纹登记。
func (s *PvfService) PvfPath() string {
	return s.config.Pvf.FilePath
}

// DeltaDir 返回 PVF 增量包目录（相对路径按网关运行目录解析）。
func (s *PvfService) DeltaDir() string {
	dir := strings.TrimSpace(s.config.Pvf.DeltaDir)
	if dir == "" {
		dir = "./pvf_delta"
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// GetDelta 返回当前可下发的增量包；没有可用增量时返回 nil（调用方据此省略 policy 字段）。
//
// ★ 这里再校一次 ToHash == 当前 PVF hash。loadDeltaLocked 已经校过一次，
// 但「替换 PVF 失败/刷新缓存」与「读 delta」之间存在窗口，多一道不会有害，
// 而漏掉的代价是**把玩家本地 PVF 合成成一份错的内容**。
func (s *PvfService) GetDelta() *models.PvfDeltaInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.delta == nil || s.info == nil || s.info.Hash == "" {
		return nil
	}
	if !strings.EqualFold(s.delta.ToHash, s.info.Hash) {
		return nil
	}
	return s.delta
}

// loadDeltaLocked 从磁盘装载增量包 —— 网关重启后不必重新生成。
// 调用方必须已持有写锁。
func (s *PvfService) loadDeltaLocked() {
	s.delta = nil
	if s.info == nil || s.info.Hash == "" {
		return
	}

	path := filepath.Join(s.DeltaDir(), deltaFileName)
	if !utils.FileExists(path) {
		return
	}

	h, err := pvfdiff.Inspect(path)
	if err != nil {
		s.logger.Warn("PVF 增量包头部不可读，本次不下发增量: " + err.Error())
		return
	}
	// 磁盘上这份增量包对应的**不是**当前 PVF ⇒ 绝不能外发。
	// 典型场景：运维手动换了 Script.pvf（没走 upload-pvf），delta 就过时了。
	if !strings.EqualFold(h.ToHash, s.info.Hash) {
		s.logger.Warn(fmt.Sprintf(
			"PVF 增量包已过期（to=%s，当前=%s），本次不下发增量",
			shortHash(h.ToHash), shortHash(s.info.Hash)))
		return
	}

	stats, _ := utils.GetFileStats(path)
	created := ""
	if stats != nil {
		created = stats.ModifiedUtc
	}
	s.delta = &models.PvfDeltaInfo{
		FromHash:   h.FromHash,
		ToHash:     h.ToHash,
		ToSize:     h.ToSize,
		Size:       h.TotalSize,
		Path:       path,
		CreatedUtc: created,
	}
}

// rebuildDelta 用 path+".bak"（上一版）与 path（当前版）生成增量包。
//
// 刻意**不返回错误**：调用它的路径上 PVF 已经替换成功了，没有任何理由因为
// "出不了 delta" 就回退整个替换。但失败时必须把 delta 置空 ——
// 宁可这次不下发增量（玩家走手动更新），也不能下发一份对不上的包。
func (s *PvfService) rebuildDelta(path string) {
	dir := s.DeltaDir()
	final := filepath.Join(dir, deltaFileName)

	clearDelta := func() {
		s.mu.Lock()
		s.delta = nil
		s.mu.Unlock()
	}

	bak := path + ".bak"
	if !utils.FileExists(bak) {
		clearDelta()
		s.logger.Warn("PVF 已替换但缺少 .bak 备份，无法生成增量包")
		return
	}
	if err := utils.MkdirAll(dir); err != nil {
		clearDelta()
		s.logger.Warn("创建 PVF 增量目录失败（本次不提供增量更新）: " + err.Error())
		return
	}

	t0 := time.Now()
	tmp := final + ".tmp"
	st, err := pvfdiff.Build(bak, path, tmp, pvfdiff.DefaultBlockSize)
	if err != nil {
		os.Remove(tmp)
		clearDelta()
		s.logger.Warn("生成 PVF 增量包失败（本次不提供增量更新）: " + err.Error())
		return
	}

	// G-6（2026-10-04 审查）：拒绝「自差分」（from == to）。
	//
	// 出现它只有两种可能，都意味着 .bak 不是真正的"上一版"：
	//   ① 并发替换 —— 第二次 BackupFile 把第一次刚写好的新版覆盖成了 .bak
	//      （2026-09-30「全体旧版客户端进不去」就是这种形态）；
	//   ② 本次上传的内容与当前版**完全相同**（幂等重传）。
	// 这两种情况生成出来的 delta 是个"把玩家本地文件改回它自己"的空补丁，
	// 下发它等于给玩家一个**看似成功、实则内容错误**的更新路径。
	// 宁可本次不给增量（玩家走全量），也不能落地一份自差分。
	if strings.EqualFold(st.FromHash, st.ToHash) {
		os.Remove(tmp)
		clearDelta()
		s.logger.Warn(fmt.Sprintf(
			"PVF 自差分已拒绝：.bak 与当前文件内容相同（%s）—— 本次不下发增量。"+
				"若刚发生过并发上传，请确认 .bak 是否是期望的上一版",
			shortHash(st.ToHash)))
		return
	}

	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		clearDelta()
		s.logger.Warn("落地 PVF 增量包失败（本次不提供增量更新）: " + err.Error())
		return
	}

	s.mu.Lock()
	s.loadDeltaLocked()
	s.mu.Unlock()

	if s.GetDelta() == nil {
		// 落地了但装载不上（头部坏 / to_hash 对不上）—— 已经在 loadDeltaLocked 里记过日志
		return
	}
	s.logger.Info(fmt.Sprintf(
		"PVF 增量包已生成: %s → %s, %d 字节 (%.2f%%), 指令 %d 条, 耗时 %.2fs",
		shortHash(st.FromHash), shortHash(st.ToHash),
		st.DeltaSize, st.DeltaRatio()*100, st.InstrCount, time.Since(t0).Seconds()))
}

// ============================================================================
// PVF 历史版本（2026-09-30 方案①「按需增量 + 回退」）
//
// 存储：pvf_history/<大写SHA-256>.pvf（内容寻址，同版本只存一份）
//	 + pvf_history/index.json（显示名 / 原文件名 / 首次入史时间）
//
// 写入方：PvfService.ReplacePvf / RollbackPvf / GetHistory 的惰性 seed
//（都在管理动作路径上，单人低频；gateway 与 admin 两进程理论上都能触达
// 这些路由，但 index.json 的读-改-写都收在 histMu + 原子 rename 内，
// 实际并发窗口仅剩「两个后台页面同时点按钮」，接受）。
// 读取方：管理后台版本历史表、/api/launcher/pvf/delta?from=<hash> 按需生成。
// ============================================================================

// HistoryDir 返回 PVF 历史版本目录（相对路径按网关运行目录解析）。
func (s *PvfService) HistoryDir() string {
	dir := strings.TrimSpace(s.config.Pvf.HistoryDir)
	if dir == "" {
		dir = "./pvf_history"
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// historyKeep 返回历史保留版数上限。
func (s *PvfService) historyKeep() int {
	if s.config.Pvf.HistoryKeep > 0 {
		return s.config.Pvf.HistoryKeep
	}
	return 20
}

const pvfHistoryIndexName = "index.json"

// loadHistoryIndex 读历史索引（文件不存在 → nil）。调用方须持有 histMu。
func (s *PvfService) loadHistoryIndex() []models.PvfHistoryEntry {
	raw, err := os.ReadFile(filepath.Join(s.HistoryDir(), pvfHistoryIndexName))
	if err != nil {
		return nil
	}
	var entries []models.PvfHistoryEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		s.logger.Warn("PVF 历史索引不可读（按空处理）: " + err.Error())
		return nil
	}
	return entries
}

// saveHistoryIndex 原子写历史索引。调用方须持有 histMu。
func (s *PvfService) saveHistoryIndex(entries []models.PvfHistoryEntry) error {
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	dir := s.HistoryDir()
	if err := utils.MkdirAll(dir); err != nil {
		return err
	}
	final := filepath.Join(dir, pvfHistoryIndexName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// archiveHistory 把一份 PVF 文件存进历史。
// 内容寻址：目标文件 <HASH>.pvf 已存在则跳过拷贝；
// 索引已有同 hash 记录则直接返回（**不覆盖**用户之前起的显示名）。
// 返回是否新增了记录。
func (s *PvfService) archiveHistory(path, name, filename string) (bool, error) {
	hash, err := security.ComputeFileFingerprintPath(path)
	if err != nil {
		return false, err
	}
	stats, _ := utils.GetFileStats(path)

	dir := s.HistoryDir()
	if err := utils.MkdirAll(dir); err != nil {
		return false, err
	}
	dst := filepath.Join(dir, hash+".pvf")
	if !utils.FileExists(dst) {
		tmp := dst + ".tmp"
		if err := utils.CopyFile(path, tmp); err != nil {
			os.Remove(tmp)
			return false, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return false, err
		}
	}

	s.histMu.Lock()
	defer s.histMu.Unlock()
	entries := s.loadHistoryIndex()
	for _, e := range entries {
		if strings.EqualFold(e.Hash, hash) {
			return false, nil // 已在历史：文件与记录都不动
		}
	}
	entry := models.PvfHistoryEntry{
		Hash: hash,
		Name: strings.TrimSpace(name),
		Filename: strings.TrimSpace(filename),
		// 毫秒精度：秒级会在「同一次上传连续入档两版」时撞值，
		// GetHistory 的新→旧排序就把旧版排到最前（UI 顶部显示错版本）。
		StoredUtc: time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"),
	}
	if stats != nil {
		entry.Size = stats.Size
	}
	entries = append(entries, entry)
	entries = s.pruneHistoryLocked(entries)
	if err := s.saveHistoryIndex(entries); err != nil {
		return false, err
	}
	s.logger.Info(fmt.Sprintf("PVF 版本已入历史: %s（%s）%d 字节",
		utils.ShortHash(hash), entry.Name, entry.Size))
	return true, nil
}

// pruneHistoryLocked 超限删最老。绝不删两类版本：
//   - 当前版（GetPvfInfo().Hash —— 回退目标 / 按需增量终点）
//   - 固定 delta 基线（delta.FromHash —— 玩家手上最常见的那版）
//
// 调用方须持有 histMu。
func (s *PvfService) pruneHistoryLocked(entries []models.PvfHistoryEntry) []models.PvfHistoryEntry {
	keep := s.historyKeep()
	if len(entries) <= keep {
		return entries
	}
	protected := map[string]bool{}
	if info := s.GetPvfInfo(); info != nil && info.Hash != "" {
		protected[strings.ToUpper(info.Hash)] = true
	}
	s.mu.RLock()
	if s.delta != nil && s.delta.FromHash != "" {
		protected[strings.ToUpper(s.delta.FromHash)] = true
	}
	s.mu.RUnlock()

	// StoredUtc 升序 = 最老在前；稳定排序保证同时间的按入史先后删。
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].StoredUtc < entries[j].StoredUtc })
	var kept []models.PvfHistoryEntry
	for _, e := range entries {
		if len(kept) < keep || protected[strings.ToUpper(e.Hash)] {
			kept = append(kept, e)
			continue
		}
		// 删文件 + 跳过记录。文件删失败也照常跳过（残留文件无索引引用，无害）。
		os.Remove(filepath.Join(s.HistoryDir(), e.Hash+".pvf"))
		s.logger.Info(fmt.Sprintf("PVF 历史超限清理: %s（%s）", utils.ShortHash(e.Hash), e.Name))
	}
	// 恢复新→旧的展示顺序由 GetHistory 排序，这里不额外处理。
	return kept
}

// GetHistory 返回历史列表（新→旧）。带惰性 seed：当前版与 .bak 版
// 不在历史时先入史 —— 覆盖「目录被清空 / 从未走过上传流程」的部署，
// 保证「回退到上一版」在任何状态下都可用。
func (s *PvfService) GetHistory() []models.PvfHistoryEntry {
	s.seedHistory(s.config.Pvf.FilePath)
	s.seedHistory(s.config.Pvf.FilePath + ".bak")

	s.histMu.Lock()
	entries := s.loadHistoryIndex()
	s.histMu.Unlock()

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].StoredUtc > entries[j].StoredUtc })
	return entries
}

// seedHistory 把一份 PVF 存进历史（已存在则无操作）。
func (s *PvfService) seedHistory(path string) {
	if !utils.FileExists(path) {
		return
	}
	hash, err := security.ComputeFileFingerprintPath(path)
	if err != nil {
		return
	}
	if utils.FileExists(filepath.Join(s.HistoryDir(), hash+".pvf")) {
		return
	}
	if _, err := s.archiveHistory(path, "", ""); err != nil {
		s.logger.Warn("PVF 历史自动存档失败（" + path + "）: " + err.Error())
	}
}

// RollbackPvf 回退到某个历史版本。走完整 ReplacePvf 链路：
// 备份当前版（成为新固定 delta 的 from）→ 替换 → RefreshCache → 重建增量 →
// 通知网关，因此回退后**在当前版的玩家**下次登录会增量降到回退版。
func (s *PvfService) RollbackPvf(hash string) (*models.PvfInfo, error) {
	normalized := NormalizeHashArg(hash)
	if normalized == "" {
		return nil, fmt.Errorf("hash 必须是 64 位十六进制 SHA-256")
	}
	src := filepath.Join(s.HistoryDir(), normalized+".pvf")
	if !utils.FileExists(src) {
		return nil, fmt.Errorf("历史版本不存在：%s", utils.ShortHash(normalized))
	}
	if info := s.GetPvfInfo(); info != nil && strings.EqualFold(info.Hash, normalized) {
		return nil, fmt.Errorf("该版本就是当前版本")
	}
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// name 留空：该 hash 已在历史（内容寻址），不会新建记录，也不覆盖显示名。
	return s.ReplacePvf(f, "", "")
}

// NormalizeHashArg 归一化外部传入的 hash 参数：大写 + 严格 64 位十六进制。
// 非法输入返回空串 —— 这也是路径拼接的安全闸（杜绝 ?from=../../ 之类穿越）。
func NormalizeHashArg(h string) string {
	h = strings.ToUpper(strings.TrimSpace(h))
	if len(h) != 64 {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return ""
		}
	}
	return h
}

// clearOnDemandDeltas 删除全部按需增量缓存（from_*.delta）。
// 上传/回退换了当前版后，旧缓存的 to_hash 全部过期 —— 不删会被
// GetOnDemandDelta 的「缓存有效性校验」逐个作废，不如一次性清掉。
func (s *PvfService) clearOnDemandDeltas() {
	dir := s.DeltaDir()
	items, err := os.ReadDir(dir)
	if err != nil {
		return // 目录不存在 = 没有缓存，正常
	}
	for _, it := range items {
		if !it.IsDir() && strings.HasPrefix(it.Name(), "from_") && strings.HasSuffix(it.Name(), ".delta") {
			os.Remove(filepath.Join(dir, it.Name()))
		}
	}
}

// GetOnDemandDelta 按 ?from=<hash> 返回「任意历史版 → 当前版」的增量包。
//
// 三层：缓存命中 → 历史现场生成（缓存复用）→ nil（404）。
// 任何一步的产物都要过 Inspect 双校验（from == 请求值 && to == 当前版 hash）
// 才会下发 —— 与固定增量同一条安全底线：绝不让玩家合成出对不上的文件。
// 返回 nil 的所有情形（含「from == 当前版」即已是最新）都由调用方回 404。
func (s *PvfService) GetOnDemandDelta(fromRaw string) *models.PvfDeltaInfo {
	from := NormalizeHashArg(fromRaw)
	if from == "" {
		return nil
	}
	info := s.GetPvfInfo()
	if info == nil || info.Hash == "" {
		return nil
	}
	if strings.EqualFold(from, info.Hash) {
		return nil // 已是最新
	}

	dir := s.DeltaDir()
	cache := filepath.Join(dir, "from_"+from+".delta")
	if d := s.inspectDeltaFile(cache, from, info.Hash); d != nil {
		return d // 缓存命中
	}

	// 生成路径：G-4 / G-10 —— 同一个 from 的并发请求只让一个真去算，其余等待并共享结果。
	// 限流是按 IP 分桶的，不同 IP 之间不共享，一批同版本玩家同时上线会一起打到这条路径。
	v, _ := s.deltaGroup.do(from, onDemandBuildWait, func() any {
		if d := s.inspectDeltaFile(cache, from, info.Hash); d != nil {
			return d // 等待期间已有别的调用生成好了
		}
		if utils.FileExists(cache) {
			os.Remove(cache) // 有文件但校验不过（to 过期/损坏）→ 作废重建
		}

		histPath := filepath.Join(s.HistoryDir(), from+".pvf")
		curPath := s.config.Pvf.FilePath
		if !utils.FileExists(histPath) || !utils.FileExists(curPath) {
			return nil // 历史里没有这版（或当前 PVF 缺失）
		}
		if err := utils.MkdirAll(dir); err != nil {
			return nil
		}

		t0 := time.Now()
		// G-4：tmp 名带 pid + 纳秒后缀。原先固定为 cache+".tmp"，并发的调用
		// （甚至 gateway / admin 两个进程）会共写同一文件：os.Create 截断 +
		// 写入交错 ⇒ 产出损坏包，而 Rename 之后谁也看不出来。
		tmp := fmt.Sprintf("%s.tmp-%d-%d", cache, os.Getpid(), time.Now().UnixNano())
		st, err := pvfdiff.Build(histPath, curPath, tmp, pvfdiff.DefaultBlockSize)
		if err != nil {
			os.Remove(tmp)
			s.logger.Warn("PVF 按需增量包生成失败: " + err.Error())
			return nil
		}
		if err := os.Rename(tmp, cache); err != nil {
			os.Remove(tmp)
			return nil
		}
		s.logger.Info(fmt.Sprintf(
			"PVF 按需增量包已生成: %s → %s, %d 字节 (%.2f%%), 指令 %d 条, 耗时 %.2fs",
			shortHash(st.FromHash), shortHash(st.ToHash),
			st.DeltaSize, st.DeltaRatio()*100, st.InstrCount, time.Since(t0).Seconds()))

		return s.inspectDeltaFile(cache, from, info.Hash)
	})
	if v == nil {
		return nil
	}
	d, _ := v.(*models.PvfDeltaInfo)
	return d
}

// inspectDeltaFile 读取一个 delta 文件并做 from/to 双校验；不通过返回 nil。
func (s *PvfService) inspectDeltaFile(path, wantFrom, wantTo string) *models.PvfDeltaInfo {
	if !utils.FileExists(path) {
		return nil
	}
	h, err := pvfdiff.Inspect(path)
	if err != nil {
		return nil
	}
	if !strings.EqualFold(h.FromHash, wantFrom) || !strings.EqualFold(h.ToHash, wantTo) {
		return nil
	}
	stats, _ := utils.GetFileStats(path)
	created := ""
	if stats != nil {
		created = stats.ModifiedUtc
	}
	return &models.PvfDeltaInfo{
		FromHash:   h.FromHash,
		ToHash:     h.ToHash,
		ToSize:     h.ToSize,
		Size:       h.TotalSize,
		Path:       path,
		CreatedUtc: created,
	}
}

// RefreshCache 刷新 PVF 指纹缓存。
//
// 采用流式计算全文件 SHA-256（PVF 可达数百 MB），避免整文件读入内存；
// 指纹按**大写**返回，与登录器侧比对口径一致。
func (s *PvfService) RefreshCache() error {
	path := s.config.Pvf.FilePath
	if !utils.FileExists(path) {
		s.mu.Lock()
		s.info = &models.PvfInfo{Path: path, Hash: "", Algo: security.FileFingerprintAlgo, Size: 0, ModifiedUtc: ""}
		s.loadDeltaLocked() // info.Hash 为空 ⇒ 顺带把 delta 清掉
		s.mu.Unlock()
		return nil
	}

	hash, err := security.ComputeFileFingerprintPath(path)
	if err != nil {
		// 审查报告 G-2：这里直接 return err 会留下 s.info == nil，
		// 而 GetPvfInfo() 会把这个 error 吞掉、返回 nil ⇒ /api/launcher/policy
		// （免鉴权、每个登录器启动必打）解引用 nil，进程级 panic + 崩溃循环。
		// 另外 s.info 保持 nil 会让**每个** policy 请求都重算一次全文件 SHA-256。
		// 处置：有旧 info 就保留（对外表现不变），没有就落一个"指纹不可用"的零值
		// （Path 保留）；两条路都不留 nil。错误本身照旧返回给调用方。
		s.mu.Lock()
		if s.info == nil {
			s.info = &models.PvfInfo{Path: path, Hash: "", Algo: security.FileFingerprintAlgo, Size: 0, ModifiedUtc: ""}
			s.loadDeltaLocked()
		}
		s.mu.Unlock()
		return err
	}

	stats, _ := utils.GetFileStats(path)

	s.mu.Lock()
	s.info = &models.PvfInfo{
		Path:        path,
		Hash:        hash,
		Algo:        security.FileFingerprintAlgo,
		Size:        stats.Size,
		ModifiedUtc: stats.ModifiedUtc,
	}
	s.mode = "file"
	// 指纹变了 ⇒ 顺带重新判定磁盘上的增量包还配不配得上（配不上就置空）。
	// 这一步同时覆盖「运维直接替换了 Script.pvf，没走 upload-pvf」的情况。
	s.loadDeltaLocked()
	s.mu.Unlock()
	return nil
}

// ── G-6：跨进程的 PVF 替换锁 ───────────────────────────────────────────────
//
// replaceMu 只挡得住**本进程内**的并发；admin 与 gateway 是两个进程、各自注册了
// upload-pvf，而 .bak 是**共享的磁盘资源**：两边同时走
//「BackupFile → 写盘 → rebuildDelta」，就会互相把对方刚写好的新版覆盖成 .bak，
// 最终产出 from == to 的自差分。所以再补一层文件锁。
//
// 用 O_CREATE|O_EXCL 的锁文件（<pvf>.lock）而不是 flock：O_EXCL 是 POSIX 与
// Windows 都保证原子性的最小公倍数，而 flock 的语义两边并不一致。
const (
	// pvfReplaceLockPoll 抢锁轮询间隔。
	pvfReplaceLockPoll = 200 * time.Millisecond
	// pvfReplaceLockStale 残留锁判定阈值：持锁进程崩溃/整机断电会留下永不释放的
	// 锁文件，超过这个时长就强制接管，否则 PVF 从此再也换不了。
	pvfReplaceLockStale = 10 * time.Minute
)

// pvfReplaceLockWait 抢锁的最长等待。上传 PVF 是低频人工操作，
// 30 秒足够覆盖"两个后台上传按钮被同时点到"，超出就直接报错让人重试。
//
// ★ 用 var 而非 const：测试要把"有进程持锁"的用例压到毫秒级，
// 否则光等这个超时就得跑 30 秒。
var pvfReplaceLockWait = 30 * time.Second

// acquirePvfReplaceLock 抢跨进程的 PVF 替换锁，返回释放函数（幂等：重复调用只删一次）。
func (s *PvfService) acquirePvfReplaceLock() (func(), error) {
	lockPath := s.config.Pvf.FilePath + ".lock"
	deadline := time.Now().Add(pvfReplaceLockWait)
	forced := false

	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err == nil {
			// 内容只为排障：谁在什么时候持的锁（admin 与 gateway 可能不同机/不同 pid）。
			fmt.Fprintf(f, "pid=%d time=%s\n",
				os.Getpid(), time.Now().UTC().Format(time.RFC3339))
			f.Close()
			return func() { os.Remove(lockPath) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("创建 PVF 替换锁失败（%s）: %w", lockPath, err)
		}

		// 锁已存在：判残留。只强制接管一次 —— 否则 os.Remove 一直失败时会死循环。
		if !forced {
			if st, serr := os.Stat(lockPath); serr == nil && time.Since(st.ModTime()) > pvfReplaceLockStale {
				s.logger.Warn(fmt.Sprintf(
					"发现残留的 PVF 替换锁（%s，%s 未更新）——强制接管",
					lockPath, time.Since(st.ModTime()).Round(time.Second)))
				forced = true
				if rerr := os.Remove(lockPath); rerr == nil {
					continue
				}
			}
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("另一个进程正在替换 PVF（锁文件 %s），请稍后重试", lockPath)
		}
		time.Sleep(pvfReplaceLockPoll)
	}
}

// ReplacePvf 替换 PVF 文件。
//
// name/filename 来自管理后台（显示备注 + 原上传文件名），写进历史记录 ——
// 仅该版本**首次**入史时生效，重复上传同内容不会覆盖旧备注。
func (s *PvfService) ReplacePvf(src io.Reader, name, filename string) (*models.PvfInfo, error) {
	// G-6（2026-10-04 审查）：整条链路必须互斥（见 replaceMu / acquirePvfReplaceLock）。
	s.replaceMu.Lock()
	defer s.replaceMu.Unlock()

	path := s.config.Pvf.FilePath

	// 目录先建好，否则下面的跨进程锁文件（<pvf>.lock）落在不存在的目录里会失败。
	if err := utils.MkdirAll(filepath.Dir(path)); err != nil {
		return nil, err
	}

	unlock, err := s.acquirePvfReplaceLock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	// 备份旧文件。★ 这个 .bak 同时是**生成增量包的旧版本输入** ——
	// 别为了省 75 MB 磁盘把它去掉，否则登录器永远只能全量更新。
	utils.BackupFile(path)

	// 写入新文件
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if _, err := io.Copy(f, src); err != nil {
		return nil, err
	}
	f.Close()

	if err := os.Rename(tmpPath, path); err != nil {
		return nil, err
	}

	if err := s.RefreshCache(); err != nil {
		return nil, err
	}

	// ★ 生成「上一版 → 当前版」增量包（登录器据此做增量更新）。
	//   放在替换**成功之后**，且内部不返回错误：PVF 已经换好了，
	//   不该因为"出不了 delta"就把整个替换回退；失败只会让本次没有增量可用。
	s.rebuildDelta(path)

	// ★ 历史存档（2026-09-30 方案①）：旧版（.bak）与新版都入史（内容寻址去重），
	//   供「版本回退」与 ?from=<hash> 按需增量使用。失败只记日志 ——
	//   替换已经成功，历史缺失的代价只是少一个可回退/可按需的版本。
	s.clearOnDemandDeltas() // 当前版已换 ⇒ 旧 from_*.delta 的 to 全部过期
	if _, err := s.archiveHistory(path+".bak", "", ""); err != nil {
		s.logger.Warn("PVF 旧版入历史失败（不影响替换）: " + err.Error())
	}
	if _, err := s.archiveHistory(path, name, filename); err != nil {
		s.logger.Warn("PVF 新版入历史失败（不影响替换）: " + err.Error())
	}

	return s.GetPvfInfo(), nil
}

// RegisterStamp 登记 PVF 指纹。
func (s *PvfService) RegisterStamp(file *string, hash *string, algo *string, size *int64) (*models.PvfInfo, error) {
	if file == nil || hash == nil || size == nil {
		return nil, fmt.Errorf("file/hash/size required")
	}

	// 登记的指纹同样按大写归一，避免与本地计算出的指纹大小写不一致。
	normalized := strings.ToUpper(strings.TrimSpace(*hash))

	s.mu.Lock()
	s.info = &models.PvfInfo{
		Path:        *file,
		Hash:        normalized,
		Algo:        derefString(algo, security.FileFingerprintAlgo),
		Size:        *size,
		ModifiedUtc: time.Now().UTC().Format(time.RFC3339),
	}
	s.mode = "registered"
	info := s.info
	s.mu.Unlock()
	return info, nil
}

// Unregister 撤销 PVF 登记。
func (s *PvfService) Unregister() {
	s.mu.Lock()
	s.mode = "file"
	s.mu.Unlock()
	_ = s.RefreshCache()
}

func derefString(p *string, def string) string {
	if p != nil {
		return *p
	}
	return def
}

// fileStamp 是策略文件的"版本指纹"。
//
// 只看 (修改时间, 字节数)：够轻（一次 stat，不用读文件内容，也不用起 fsnotify）、
// 也够准 —— 管理员在后台改名单必然走到一次 saveLocked 重写整个文件，
// 大文件几乎必变、小文件改条目数必变；再叠加纳秒级 mtime，实际不可能漏判。
type fileStamp struct {
	modNano int64
	size    int64
}

// IntegrityStore 完整性策略存储。
//
// 策略会持久化到 <configDir>/integrity_policy.json，重启后自动加载，
// 避免进程重启导致全部白/黑名单与放行模块丢失。
//
// ★★ 运行时还必须能被**别的进程**改醒（2026-10-12 修）：
// 管理后台是独立的 s4a21-admin 进程，它在 `/api/admin/integrity/*` 上增删条目后
// 只更新**它自己**的内存并把 `integrity_policy.json` 重写落盘；
// 而给登录器下发名单的 `/api/launcher/policy` 跑在**网关进程**里，读的是网关自己那份内存快照。
// 修复前网关只在构造时 load 一次 ⇒ 后台改完，网关下发的一直是旧名单，
// 只有重启网关进程（= 全体在线玩家掉线）才生效。
// 现在 Snapshot() 每次先看一眼文件指纹，变了就热加载，做到「后台保存 → 玩家下次拉策略即为新名单」，零掉线。
type IntegrityStore struct {
	mu         sync.RWMutex
	snapshot   *models.IntegritySnapshot
	policyPath string
	logger     *logger.ConsoleLogger
	diskStamp  fileStamp
}

// IntegrityPolicyFileName 完整性策略持久化文件名。
const IntegrityPolicyFileName = "integrity_policy.json"

// NewIntegrityStore 创建完整性策略存储，并从 configDir 加载已有策略。
// configDir 为空时退化为纯内存模式（仅用于测试）；log 为 nil 时使用全局日志。
func NewIntegrityStore(configDir string, log *logger.ConsoleLogger) *IntegrityStore {
	if log == nil {
		log = logger.Global()
	}
	s := &IntegrityStore{
		logger: log,
		snapshot: &models.IntegritySnapshot{
			Revision:       1,
			UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
			WhiteList:      make([]models.FingerprintEntry, 0),
			BlackList:      make([]models.FingerprintEntry, 0),
			AllowedModules: make([]string, 0),
		},
	}
	if configDir != "" {
		s.policyPath = filepath.Join(configDir, IntegrityPolicyFileName)
		s.loadLocked()
		// 记下"当前盘上的样子"，之后 Snapshot 才能分辨"变了"还是"没动过"。
		s.diskStamp = s.statPolicy()
	}
	return s
}

// logInfo 安全写日志（logger 为 nil 时静默）。
func (s *IntegrityStore) logInfo(msg string) {
	if s.logger != nil {
		s.logger.Info(msg)
	}
}

// logError 安全写错误日志（logger 为 nil 时静默）。
func (s *IntegrityStore) logError(msg string) {
	if s.logger != nil {
		s.logger.Error(msg)
	}
}

// load 供构造期调用（此刻没有并发，无需加锁）。
func (s *IntegrityStore) load() {
	s.loadLocked()
}

// loadLocked 从磁盘加载策略。文件不存在或解析失败时保持现有内存策略（不阻断启动）。
// 调用方必须已持有写锁。
func (s *IntegrityStore) loadLocked() {
	if s.policyPath == "" {
		return
	}
	data, err := os.ReadFile(s.policyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logError(fmt.Sprintf("[完整性策略] 读取失败: %v", err))
		}
		return
	}
	var snap models.IntegritySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		s.logError(fmt.Sprintf("[完整性策略] 解析失败，使用空策略: %v", err))
		return
	}
	// 补齐 nil 切片，避免调用方拿到 nil 需要额外判空
	if snap.WhiteList == nil {
		snap.WhiteList = make([]models.FingerprintEntry, 0)
	}
	if snap.BlackList == nil {
		snap.BlackList = make([]models.FingerprintEntry, 0)
	}
	if snap.AllowedModules == nil {
		snap.AllowedModules = make([]string, 0)
	}
	if snap.Revision <= 0 {
		snap.Revision = 1
	}
	s.snapshot = &snap
	s.logInfo(fmt.Sprintf("[完整性策略] 已加载: rev=%d 白名单=%d 黑名单=%d 放行模块=%d",
		snap.Revision, len(snap.WhiteList), len(snap.BlackList), len(snap.AllowedModules)))
}

// statPolicy 读取策略文件当下的指纹；路径为空 / 文件不存在 / 不可读一律返回零值。
func (s *IntegrityStore) statPolicy() fileStamp {
	if s.policyPath == "" {
		return fileStamp{}
	}
	fi, err := os.Stat(s.policyPath)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{modNano: fi.ModTime().UnixNano(), size: fi.Size()}
}

// reloadIfChangedLocked 检测到策略文件被**外部**改写时重载内存快照。
//
// 典型场景就是这次要修的 bug：管理后台（s4a21-admin 进程）增删条目后重写了
// integrity_policy.json，而网关进程的内存快照还停在它自己启动那一刻。
//
// 设计取舍：
//   - 只 stat 不读内容：一次 stat 的代价相对一次 policy 请求可以忽略，
//     比起"每次请求都 ReadFile + Unmarshal"（几 KB JSON）便宜一个量级；
//   - 零值指纹（文件还没生成过 / 暂时读不到）**不更新** s.diskStamp ——
//     否则"文件从无到有"这一次会被当成"没变"而漏掉；
//   - 文件被删时保持内存现状，不把已有名单清成空 —— 宁可继续下发旧名单，
//     也不要因为一次误删把所有客户端的放行配置打空。
func (s *IntegrityStore) reloadIfChangedLocked() {
	if s.policyPath == "" {
		return
	}
	now := s.statPolicy()
	if now == (fileStamp{}) || now == s.diskStamp {
		return
	}
	oldRev := s.snapshot.Revision
	s.loadLocked()
	s.diskStamp = now
	s.logInfo(fmt.Sprintf("[完整性策略] 检测到策略文件被外部改写，已热加载: rev=%d→%d 白名单=%d 黑名单=%d 放行模块=%d",
		oldRev, s.snapshot.Revision, len(s.snapshot.WhiteList), len(s.snapshot.BlackList), len(s.snapshot.AllowedModules)))
}

// saveLocked 把当前快照落盘（调用方必须已持有写锁）。
// 采用"写临时文件 -> 原子替换"策略，失败只记日志不回滚内存变更。
func (s *IntegrityStore) saveLocked() {
	if s.policyPath == "" {
		return
	}
	data, err := json.MarshalIndent(s.snapshot, "", "  ")
	if err != nil {
		s.logError(fmt.Sprintf("[完整性策略] 序列化失败: %v", err))
		return
	}
	tmpPath := s.policyPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		s.logError(fmt.Sprintf("[完整性策略] 写入临时文件失败: %v", err))
		return
	}
	if err := os.Rename(tmpPath, s.policyPath); err != nil {
		s.logError(fmt.Sprintf("[完整性策略] 原子替换失败: %v", err))
		return
	}
	// 这次改动是**本进程**写的：立刻同步指纹，免得下一次 Snapshot 把它误判成
	// "外部改写"又重载一遍（结果虽然一样，但每次都白读一次文件、还多打一条日志）。
	s.diskStamp = s.statPolicy()
}

// Snapshot 获取快照的深拷贝，避免调用方在锁外读取时与写操作产生数据竞争。
//
// ★ 每次都先看一眼策略文件有没有被**别的进程**（管理后台 / 人工上传）改写 ——
//   改了就热加载再返回。`/api/launcher/policy` 走的就是这里，
//   所以后台保存后玩家下一次拉到的就是新名单，不需要重启网关。
//
// 快路径只读锁 + 一次 stat；只有指纹真的变了才升级成写锁去重载。
func (s *IntegrityStore) Snapshot() *models.IntegritySnapshot {
	s.mu.RLock()
	if s.policyPath != "" {
		if now := s.statPolicy(); now != (fileStamp{}) && now != s.diskStamp {
			s.mu.RUnlock()
			s.mu.Lock()
			s.reloadIfChangedLocked() // 内部二次核对，避免两个并发请求重复加载
			s.mu.Unlock()
			s.mu.RLock()
		}
	}
	snap := cloneSnapshot(s.snapshot)
	s.mu.RUnlock()
	return snap
}

// cloneSnapshot 深拷贝一份快照（含所有切片内容）。
func cloneSnapshot(src *models.IntegritySnapshot) *models.IntegritySnapshot {
	if src == nil {
		return nil
	}
	dst := &models.IntegritySnapshot{
		Revision:  src.Revision,
		UpdatedAt: src.UpdatedAt,
	}
	dst.WhiteList = make([]models.FingerprintEntry, len(src.WhiteList))
	copy(dst.WhiteList, src.WhiteList)
	dst.BlackList = make([]models.FingerprintEntry, len(src.BlackList))
	copy(dst.BlackList, src.BlackList)
	dst.AllowedModules = make([]string, len(src.AllowedModules))
	copy(dst.AllowedModules, src.AllowedModules)
	return dst
}

// shortHash 安全截取哈希前 16 位用于展示，不足 16 位时原样返回。
func shortHash(h string) string {
	return utils.ShortHash(h)
}

// AddEntries 添加入白/黑名单。
func (s *IntegrityStore) AddEntries(isWhite bool, entries []models.FingerprintEntry) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	added := 0
	for _, e := range entries {
		if e.FileName == "" || e.Hash == "" {
			continue
		}
		if isWhite {
			// 检查是否已存在
			exists := false
			for _, existing := range s.snapshot.WhiteList {
				if existing.FileName == e.FileName && existing.Hash == e.Hash {
					exists = true
					break
				}
			}
			if !exists {
				e.Display = fmt.Sprintf("%s [%s]", e.FileName, shortHash(e.Hash))
				s.snapshot.WhiteList = append(s.snapshot.WhiteList, e)
				added++
			}
		} else {
			exists := false
			for _, existing := range s.snapshot.BlackList {
				if existing.FileName == e.FileName && existing.Hash == e.Hash {
					exists = true
					break
				}
			}
			if !exists {
				e.Display = fmt.Sprintf("%s [%s]", e.FileName, shortHash(e.Hash))
				s.snapshot.BlackList = append(s.snapshot.BlackList, e)
				added++
			}
		}
	}

	if added > 0 {
		s.snapshot.Revision++
		s.snapshot.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		s.saveLocked()
	}

	return added
}

// RemoveEntry 从白/黑名单移除条目。
func (s *IntegrityStore) RemoveEntry(isWhite bool, file, hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if isWhite {
		newList := make([]models.FingerprintEntry, 0, len(s.snapshot.WhiteList))
		removed := false
		for _, e := range s.snapshot.WhiteList {
			if e.FileName == file && e.Hash == hash {
				removed = true
			} else {
				newList = append(newList, e)
			}
		}
		s.snapshot.WhiteList = newList
		if removed {
			s.snapshot.Revision++
			s.snapshot.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			s.saveLocked()
		}
		return removed
	} else {
		newList := make([]models.FingerprintEntry, 0, len(s.snapshot.BlackList))
		removed := false
		for _, e := range s.snapshot.BlackList {
			if e.FileName == file && e.Hash == hash {
				removed = true
			} else {
				newList = append(newList, e)
			}
		}
		s.snapshot.BlackList = newList
		if removed {
			s.snapshot.Revision++
			s.snapshot.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			s.saveLocked()
		}
		return removed
	}
}

// AddAllowedModules 添加放行名单。
func (s *IntegrityStore) AddAllowedModules(names []string) (int, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	added := 0
	var rejected []string
	existing := make(map[string]bool)
	for _, n := range s.snapshot.AllowedModules {
		existing[n] = true
	}

	for _, name := range names {
		name = utils.TrimSpace(name)
		if name == "" || len(name) > 100 {
			rejected = append(rejected, name)
			continue
		}
		if existing[name] {
			rejected = append(rejected, name)
			continue
		}
		// 简化校验
		if !isValidModuleName(name) {
			rejected = append(rejected, name)
			continue
		}
		s.snapshot.AllowedModules = append(s.snapshot.AllowedModules, name)
		existing[name] = true
		added++
	}

	if added > 0 {
		s.snapshot.Revision++
		s.snapshot.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		s.saveLocked()
	}

	return added, rejected
}

// RemoveAllowedModule 移除放行名单条目。
func (s *IntegrityStore) RemoveAllowedModule(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	newList := make([]string, 0, len(s.snapshot.AllowedModules))
	removed := false
	for _, n := range s.snapshot.AllowedModules {
		if n == name {
			removed = true
		} else {
			newList = append(newList, n)
		}
	}
	s.snapshot.AllowedModules = newList
	if removed {
		s.snapshot.Revision++
		s.snapshot.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		s.saveLocked()
	}
	return removed
}

// Bump 递增修订号并落盘。
func (s *IntegrityStore) Bump() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.Revision++
	s.snapshot.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	s.saveLocked()
}

// ConfigPath 获取策略持久化文件路径（未启用持久化时返回空串）。
func (s *IntegrityStore) ConfigPath() string {
	return s.policyPath
}

func isValidModuleName(name string) bool {
	if len(name) == 0 || len(name) > 100 {
		return false
	}
	// 检查扩展名
	dotIdx := indexOf(name, ".")
	if dotIdx <= 0 || dotIdx == len(name)-1 {
		return false
	}
	for _, ch := range name {
		if ch == '/' || ch == '\\' || ch == ':' || ch == '*' || ch == '?' ||
			ch == '<' || ch == '>' || ch == '|' {
			return false
		}
	}
	return true
}

// RegisterBonusKinds 日志类型常量。
const (
	rbRegistered     = "registered"
	rbCera           = "cera"
	rbTokenCera      = "token_cera"
	rbHappyTokenCera = "happy_token_cera"
	rbGold           = "gold"
	rbItem           = "item"

	rbStatusPending    = "pending"
	rbStatusProcessing = "processing"
	rbStatusDone       = "done"
	rbStatusDelivered  = "delivered"
	rbStatusExpired    = "expired"
	rbStatusFailed     = "failed"
)

// RegisterBonusService 注册奖励服务：
//  1. 注册成功时在网关库登记 pending 流水（不追溯历史注册）；
//  2. 每次登录成功时处理：点券登录即发（不过期）；金币/物品需账号有首个存活角色，
//     通过系统邮件投递；注册超时仍无角色则金币/物品过期不补发；
//  3. 全程写 register_bonus_log 流水，后台可查询。
type RegisterBonusService struct {
	db     *database.Database
	config *config.GatewayConfig
	logger *logger.ConsoleLogger
	path   string
}

// NewRegisterBonusService 创建注册奖励服务。
func NewRegisterBonusService(db *database.Database, cfg *config.GatewayConfig, logger *logger.ConsoleLogger) *RegisterBonusService {
	return &RegisterBonusService{
		db: db, config: cfg, logger: logger,
		path: "./register_bonus.json",
	}
}

// GetConfig 读取磁盘配置；文件缺失或解析失败返回 nil。
func (s *RegisterBonusService) GetConfig() *models.RegisterBonusConfig {
	return s.loadConfig()
}

// ConfigPath 获取配置文件路径。
func (s *RegisterBonusService) ConfigPath() string {
	return s.path
}

// SaveConfig 校验并保存配置。
func (s *RegisterBonusService) SaveConfig(cfg *models.RegisterBonusConfig) (bool, string) {
	if err := validateRegisterBonusConfig(cfg); err != nil {
		return false, err.Error()
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return false, err.Error()
	}
	if err := os.WriteFile(s.path, data, 0644); err != nil {
		return false, err.Error()
	}
	return true, "配置已保存"
}

// EnsureDefaultFile 确保默认配置文件存在（enabled=false，需后台开启）。
func (s *RegisterBonusService) EnsureDefaultFile() {
	if utils.FileExists(s.path) {
		return
	}
	defaultCfg := &models.RegisterBonusConfig{
		Enabled:                false,
		Title:                  "注册奖励",
		Body:                   "欢迎注册，附件为注册奖励，请查收。",
		ItemExpireHours:        24,
		ItemSplitCount:         2000,
		ItemStackLimit:         20000,
		ItemDeliverLimit:       100,
		ItemAttachmentsPerMail: 10,
		Items:                  []models.RegisterBonusItem{},
	}
	data, _ := json.MarshalIndent(defaultCfg, "", "  ")
	os.WriteFile(s.path, data, 0644)
}

// loadConfig 从磁盘加载注册奖励配置。
func (s *RegisterBonusService) loadConfig() *models.RegisterBonusConfig {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil
	}
	var cfg models.RegisterBonusConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		s.logger.Warn(fmt.Sprintf("注册奖励配置解析失败: %v", err))
		return nil
	}
	return &cfg
}

// Register 注册成功后触发奖励登记（幂等）。
func (s *RegisterBonusService) Register(account string) {
	if account == "" {
		return
	}
	cfg := s.loadConfig()
	if cfg == nil || !cfg.Enabled {
		return
	}

	// 幂等：已登记过不再追加
	n, err := s.db.CountRegisterLog(account, rbRegistered)
	if err != nil {
		s.logger.Warn(fmt.Sprintf("注册奖励登记失败: %v", err))
		return
	}
	if n > 0 {
		return
	}

	row := &models.RegisterBonusLogRow{
		Account:    account,
		RewardType: rbRegistered,
		Status:     rbStatusPending,
	}
	if err := s.db.InsertRegisterLog(row); err != nil {
		s.logger.Warn(fmt.Sprintf("注册奖励登记失败: %v", err))
		return
	}
	s.logger.Info(fmt.Sprintf("注册奖励已登记: %s", account))
}

// ProcessOnLogin 登录成功处理注册奖励。
func (s *RegisterBonusService) ProcessOnLogin(account string) {
	if account == "" {
		return
	}
	cfg := s.loadConfig()
	if cfg == nil || !cfg.Enabled {
		return // 关闭期间保留 pending，重新开启后继续处理
	}

	reg, err := s.db.FindPendingRegister(account)
	if err != nil || reg == nil {
		return
	}

	// 原子抢占（并发防重复）
	claimed, err := s.db.ClaimRegisterPending(reg.ID)
	if err != nil {
		s.logger.Warn(fmt.Sprintf("注册奖励抢占失败: %v", err))
		return
	}
	if !claimed {
		return
	}

	releaseClaim := func() {
		if err := s.db.ReleaseRegisterClaim(reg.ID); err != nil {
			s.logger.Warn(fmt.Sprintf("注册奖励状态回滚失败，需管理员处理: %s", account))
		}
	}

	err = s.processRegistered(account, reg, cfg)
	if err != nil {
		s.logger.Warn(fmt.Sprintf("注册奖励发放失败(保留待发): %s: %v", account, err))
		releaseClaim()
		return
	}
	// 未标记 done 且未报错的等待路径（暂无角色等下次）由 processRegistered 返回
	// 一个 sentinel 语义，这里统一处理。
	if !s.isDone(reg.ID) {
		releaseClaim()
	}
}

// isDone 检查登记行是否已被标记完成。
func (s *RegisterBonusService) isDone(id int64) bool {
	// processRegistered 内部正常完成会调 MarkRegisterDone；
	// 若为 waiting 路径则不标记。这里通过状态查询判断。
	row, err := s.db.FindRegisterByID(id)
	if err != nil || row == nil {
		return false
	}
	return row.Status == rbStatusDone
}

// processRegistered 实际发放逻辑。返回 error 时由调用方退回 pending。
func (s *RegisterBonusService) processRegistered(account string, reg *models.RegisterBonusLogRow, cfg *models.RegisterBonusConfig) error {
	// 0) 先把「登录名」翻译成游戏库的 m_id。
	//
	// ★ 这里必须用 m_id，不能用登录名：AllocateNumericMId 会给「非纯数字登录名」
	// 另分配一个数字 m_id（如 kokiku -> 932320940），而下面所有游戏库操作查的都是
	// WHERE m_id = ?。此前直接传 account，导致昵称型账号的注册奖励永远命中 0 行、
	// 静默不发也不报错（纯数字登录名因为 m_id == name 而碰巧正常，所以一直没被发现）。
	mId := ""
	if acct, err := s.db.GetAccountByName(account); err != nil {
		return err
	} else if acct != nil {
		mId = acct.MId
	}
	if mId == "" {
		s.logWarn("注册奖励找不到账号记录，保持待发: account=%s", account)
		return nil // 保持 pending，等账号记录就绪
	}

	// 游戏库里没有该 m_id 的账号行时保持待发，而不是静默当成"已发放"。
	if _, _, _, ok := s.db.GetCurrencyTripleByMId(mId); !ok {
		s.logWarn("注册奖励：游戏库无此 m_id 的账号行，保持待发: account=%s m_id=%s", account, mId)
		return nil
	}

	// 1) 点券：登录即发，永不因超时过期
	for _, item := range []struct {
		kind   string
		column string
		amount int64
	}{
		{rbCera, "cera", cfg.Cera},
		{rbTokenCera, "token_cera", cfg.TokenCera},
		{rbHappyTokenCera, "happy_token_cera", cfg.HappyTokenCera},
	} {
		if item.amount <= 0 {
			continue
		}
		affected, err := s.db.AddCurrencyToGameAccount(mId, item.column, item.amount)
		if err != nil {
			return err
		}
		if affected == 0 {
			// 走到这里说明账号行存在性检查没能兜住，属于真异常 —— 过去这里完全静默
			// （不打日志、不报错、当成发放成功），这类故障就再也查不出来了。
			s.logWarn("注册奖励点券未命中（异常）: account=%s m_id=%s column=%s amount=%d",
				account, mId, item.column, item.amount)
			return fmt.Errorf("注册奖励点券未命中: account=%s m_id=%s column=%s",
				account, mId, item.column)
		}
		if err := s.appendLog(account, reg.AccountID, 0, "", item.kind, 0, "", 0, item.amount, rbStatusDelivered, ""); err != nil {
			return err
		}
	}

	// 2) 金币与物品：需首个存活角色
	hasMailReward := cfg.Gold > 0 || len(cfg.Items) > 0
	if !hasMailReward {
		return s.db.MarkRegisterDone(reg.ID)
	}

	if !s.db.GameConfigured() {
		s.logger.Warn(fmt.Sprintf("注册奖励待发放但游戏库未配置，跳过: %s", account))
		return nil // 保留 pending,等游戏库配置后重试
	}

	character, err := s.db.FindFirstAliveCharacter(mId)
	if err != nil {
		return err
	}

	expired := registerBonusExpired(reg.CreatedAt, cfg.ItemExpireHours)

	if character == nil {
		if !expired {
			return nil // 未超时，等玩家建角色（保持 pending）
		}

		// 过期：金币/物品过期不补发
		if cfg.Gold > 0 {
			_ = s.appendLog(account, reg.AccountID, 0, "", rbGold, 0, "", 0, cfg.Gold, rbStatusExpired,
				fmt.Sprintf("注册后 %d 小时内无存活角色，金币奖励过期", cfg.ItemExpireHours))
		}
		for _, item := range cfg.Items {
			if item.Count <= 0 {
				continue
			}
			display := item.Name
			if display == "" {
				display = fmt.Sprintf("#%d", item.ItemId)
			}
			_ = s.appendLog(account, reg.AccountID, 0, "", rbItem, int64(item.ItemId), display, item.Kind, item.Count, rbStatusExpired,
				fmt.Sprintf("注册后 %d 小时内无存活角色，物品奖励过期", cfg.ItemExpireHours))
		}
		return s.db.MarkRegisterDone(reg.ID)
	}

	// 3) 拆分配置为邮件批次
	batches, warning := s.mergeAndSplitRegisterItems(cfg)
	if warning != "" {
		s.logger.Warn(fmt.Sprintf("注册奖励拆分提示: %s (账号 %s)", warning, account))
	}

	if len(batches) == 0 && cfg.Gold <= 0 {
		return s.db.MarkRegisterDone(reg.ID)
	}

	if len(batches) == 0 {
		// 仅金币：单独一封金币邮件
		if err := s.db.SendMailWithGold(character.CharacterId, character.Name, cfg.Title, cfg.Body, cfg.Gold, nil, cfg.ItemExpireHours); err != nil {
			return err
		}
		if err := s.appendLog(account, reg.AccountID, character.CharacterId, character.Name, rbGold, 0, "", 0, cfg.Gold, rbStatusDelivered, ""); err != nil {
			return err
		}
		return s.db.MarkRegisterDone(reg.ID)
	}

	firstMail := true
	for _, batch := range batches {
		items := make([]database.MailItem, len(batch))
		for i, att := range batch {
			items[i] = database.MailItem{
				ItemTemplateId: att.ItemId,
				Count:          int(att.Count),
				Kind:           att.Kind,
				ItemType:       att.ItemType,
			}
		}
		gold := int64(0)
		if firstMail {
			gold = cfg.Gold
		}
		if err := s.db.SendMailWithGold(character.CharacterId, character.Name, cfg.Title, cfg.Body, gold, items, cfg.ItemExpireHours); err != nil {
			return err
		}

		if firstMail && cfg.Gold > 0 {
			if err := s.appendLog(account, reg.AccountID, character.CharacterId, character.Name, rbGold, 0, "", 0, cfg.Gold, rbStatusDelivered, ""); err != nil {
				return err
			}
		}
		for _, att := range batch {
			if err := s.appendLog(account, reg.AccountID, character.CharacterId, character.Name, rbItem,
				int64(att.ItemId), att.Name, att.Kind, att.Count, rbStatusDelivered, ""); err != nil {
				return err
			}
		}
		firstMail = false
	}

	s.logger.Info(fmt.Sprintf("注册奖励已发放: %s -> 角色 %s", account, character.Name))
	return s.db.MarkRegisterDone(reg.ID)
}

// appendLog 写入发放流水。
func (s *RegisterBonusService) appendLog(account string, accountID, characterID int64, characterName, rewardType string, itemID int64, itemName string, kind int, quantity int64, status, message string) error {
	return s.db.InsertRegisterLog(&models.RegisterBonusLogRow{
		Account:       account,
		AccountID:     accountID,
		CharacterID:   characterID,
		CharacterName: characterName,
		RewardType:    rewardType,
		ItemID:        itemID,
		ItemName:      itemName,
		Kind:          kind,
		Quantity:      quantity,
		Status:        status,
		Message:       message,
	})
}

// logWarn 输出注册奖励相关警告。
func (s *RegisterBonusService) logWarn(format string, args ...interface{}) {
	s.logger.Warn(fmt.Sprintf("[RegisterBonus] "+format, args...))
}

// QueryLogs 查询奖励日志。
func (s *RegisterBonusService) QueryLogs(account, rewardType, status string, page, pageSize int) (int, []map[string]interface{}) {
	total, entries, err := s.db.QueryRegisterLogs(account, rewardType, status, page, pageSize)
	if err != nil {
		s.logger.Warn(fmt.Sprintf("查询注册奖励日志失败: %v", err))
		return 0, nil
	}
	rows := make([]map[string]interface{}, len(entries))
	for i, e := range entries {
		rows[i] = map[string]interface{}{
			"id": e.ID, "account": e.Account, "account_id": e.AccountID,
			"character_id": e.CharacterID, "character_name": e.CharacterName,
			"reward_type": e.RewardType, "item_id": e.ItemID, "item_name": e.ItemName,
			"kind": e.Kind, "quantity": e.Quantity,
			"status": e.Status, "message": e.Message, "created_at": e.CreatedAt,
		}
	}
	return total, rows
}

// registerBonusExpired 判断登记时间是否超过过期小时数。
func registerBonusExpired(createdAt string, expireHours int) bool {
	if createdAt == "" {
		return false
	}
	t, err := time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return false
	}
	if expireHours < 1 {
		expireHours = 1
	}
	return time.Since(t) > time.Duration(expireHours)*time.Hour
}

// isValidRegisterKind kind 合法集合。
func isValidRegisterKind(kind int) bool {
	if kind < 1 || kind > 14 {
		return false
	}
	// 拒收 4/11/14
	switch kind {
	case 4, 11, 14:
		return false
	}
	return true
}

// isStackableRegisterKind 堆叠类 kind：2/3/9/10/13。
func isStackableRegisterKind(kind int) bool {
	switch kind {
	case 2, 3, 9, 10, 13:
		return true
	}
	return false
}

// registerBonusAttachment 注册奖励附件（含日志展示信息）。
type registerBonusAttachment struct {
	ItemId   int
	ItemType int
	Name     string
	Kind     int
	Count    int64
}

// mergeAndSplitRegisterItems 校验 items 并将堆叠物品合并、拆分为若干邮件批次。
func (s *RegisterBonusService) mergeAndSplitRegisterItems(cfg *models.RegisterBonusConfig) ([][]registerBonusAttachment, string) {
	var warning string
	all := make([]registerBonusAttachment, 0)
	merged := map[[3]int]struct {
		total int64
		name  string
	}{}
	var order [][3]int

	for _, item := range cfg.Items {
		if item.Count <= 0 {
			continue
		}
		if !isValidRegisterKind(item.Kind) {
			s.logWarn("注册奖励配置 kind 非法: item_id=%d kind=%d", item.ItemId, item.Kind)
			continue
		}
		key := [3]int{item.ItemId, item.Kind, item.ItemType}
		stackable := isStackableRegisterKind(item.Kind)
		if !stackable && item.Count != 1 {
			s.logWarn("注册奖励非堆叠类数量只能为 1: item_id=%d count=%d", item.ItemId, item.Count)
			continue
		}
		if existing, ok := merged[key]; ok {
			name := existing.name
			if item.Name != "" {
				name = item.Name
			}
			merged[key] = struct {
				total int64
				name  string
			}{total: existing.total + item.Count, name: name}
		} else {
			merged[key] = struct {
				total int64
				name  string
			}{total: item.Count, name: item.Name}
			order = append(order, key)
		}
	}

	split := cfg.ItemSplitCount
	if split < 1 {
		split = 1
	}
	stackLimit := cfg.ItemStackLimit
	if stackLimit < 1 {
		stackLimit = 20000
	}

	for _, key := range order {
		v := merged[key]
		stackable := isStackableRegisterKind(key[1])
		name := v.name
		if name == "" {
			name = fmt.Sprintf("#%d", key[0])
		}
		if stackable && v.total > int64(stackLimit) {
			s.logWarn("注册奖励堆叠数量超过上限: item_id=%d total=%d limit=%d", key[0], v.total, stackLimit)
			continue
		}
		maxPer := int64(1)
		if stackable {
			maxPer = int64(split)
		}
		remaining := v.total
		for remaining > 0 {
			batch := remaining
			if batch > maxPer {
				batch = maxPer
			}
			remaining -= batch
			all = append(all, registerBonusAttachment{
				ItemId:   key[0],
				ItemType: key[2],
				Name:     name,
				Kind:     key[1],
				Count:    batch,
			})
		}
	}

	perMail := cfg.ItemAttachmentsPerMail
	if perMail < 1 {
		perMail = 1
	}
	if perMail > 10 {
		perMail = 10
	}

	var batches [][]registerBonusAttachment
	for i := 0; i < len(all); i += perMail {
		end := i + perMail
		if end > len(all) {
			end = len(all)
		}
		batches = append(batches, all[i:end])
	}

	deliverLimit := cfg.ItemDeliverLimit
	if deliverLimit < 1 {
		deliverLimit = 100
	}
	if len(batches) > deliverLimit {
		warning = fmt.Sprintf("物品投递 %d 封邮件超过上限 %d，仍将全部投递", len(batches), deliverLimit)
	}

	return batches, warning
}

func validateRegisterBonusConfig(cfg *models.RegisterBonusConfig) error {
	if cfg == nil {
		return fmt.Errorf("配置不能为空")
	}
	if cfg.Cera < 0 || cfg.Cera > 10000000 {
		return fmt.Errorf("cera 取值范围 0~10000000")
	}
	if cfg.TokenCera < 0 || cfg.TokenCera > 10000000 {
		return fmt.Errorf("token_cera 取值范围 0~10000000")
	}
	if cfg.HappyTokenCera < 0 || cfg.HappyTokenCera > 10000000 {
		return fmt.Errorf("happy_token_cera 取值范围 0~10000000")
	}
	if cfg.Gold < 0 || cfg.Gold > 10000000 {
		return fmt.Errorf("gold 取值范围 0~10000000")
	}
	if cfg.ItemExpireHours < 1 || cfg.ItemExpireHours > 8760 {
		return fmt.Errorf("item_expire_hours 取值范围 1~8760")
	}
	if cfg.ItemSplitCount < 1 || cfg.ItemSplitCount > 100000 {
		return fmt.Errorf("item_split_count 取值范围 1~100000")
	}
	if cfg.ItemStackLimit < 1 || cfg.ItemStackLimit > 2000000 {
		return fmt.Errorf("item_stack_limit 取值范围 1~2000000")
	}
	if cfg.ItemAttachmentsPerMail < 1 || cfg.ItemAttachmentsPerMail > 10 {
		return fmt.Errorf("item_attachments_per_mail 取值范围 1~10")
	}
	if cfg.ItemDeliverLimit < 1 || cfg.ItemDeliverLimit > 10000 {
		return fmt.Errorf("item_deliver_limit 取值范围 1~10000")
	}

	for _, item := range cfg.Items {
		if item.ItemId <= 0 {
			return fmt.Errorf("物品 item_id 必须大于 0")
		}
		if !isValidRegisterKind(item.Kind) {
			return fmt.Errorf("物品 item_id=%d kind=%d 非法：kind 取值 1-14 且拒收 4/11/14", item.ItemId, item.Kind)
		}
		if item.Count <= 0 {
			return fmt.Errorf("物品 item_id=%d count 必须大于 0", item.ItemId)
		}
		if !isStackableRegisterKind(item.Kind) && item.Count != 1 {
			return fmt.Errorf("物品 item_id=%d kind=%d 非堆叠类数量只能为 1", item.ItemId, item.Kind)
		}
		if item.ItemType < 0 || item.ItemType > 7 {
			return fmt.Errorf("物品 item_id=%d item_type 取值 0~7", item.ItemId)
		}
	}
	return nil
}

// BonusService 泡点点券服务。
//
// 计费口径（2026-09-23 调整）：**按玩家真实在游戏频道内的时长**发放，
// 而不是「最近 N 分钟内有过 HTTP 心跳」。因此它必须能看到内存会话表，
// 由 cmd/gateway 在会话管理器建好后用 SetSessionManager 注入。
//
// 历史教训：旧实现从网关库 `accounts.last_heartbeat` 反推"谁在线"，与内存
// 会话表完全脱钩 —— 会话被 CleanExpiredSessions 清理之后，心跳字段仍是
// 两分钟内的旧值，于是出现「清理超时会话」下一行又打「泡点: X +100 cera」
// 的诡异日志（玩家早已掉线还在发钱）。
type BonusService struct {
	config     *config.GatewayConfig
	db         *database.Database
	sessionMgr *session.SessionManager
	logger     *logger.ConsoleLogger
	configPath string
	cancel     chan struct{}
	running    bool
	loggerMu   sync.Mutex
}

// BonusConfig 泡点配置。
type BonusConfig struct {
	Enabled           bool `json:"enabled"`
	IntervalSeconds   int  `json:"interval_seconds"`
	AmountPerInterval int  `json:"amount_per_interval"`
	// Timezone 判定「星期 / 时间段」所用的时区（IANA 名称，如 Asia/Shanghai）。
	//
	// 留空 = 服务器本地时区 —— 这是改造前的隐含行为，存量配置不受影响。
	// ★ 但服务器本地时区未必是运营心里的时区（Linux 云主机出厂常是 UTC），
	//   跨机器部署同一份 bonus.json 时**必须**显式写死，否则"6 点上班"
	//   在不同机器上指向不同时刻。
	Timezone string `json:"timezone"`
	// Rules 分档规则：按书写顺序匹配，**首条命中即用**，一条都没命中时
	// 回落到 AmountPerInterval。
	//
	// 老配置没有这个键 → 解析成 nil → 行为与改造前完全一致。
	Rules []BonusRule `json:"rules"`
	// ActiveThresholdMinutes 旧口径的「活跃阈值」（最近 N 分钟内有 HTTP 心跳
	// 即算在线）。2026-09-23 起泡点改为按真实在游戏内的时长计费，本字段
	// **不再参与发放判定**，仅为兼容既有 bonus.json / 部署脚本保留；
	// 缺省或为 0 都不影响运行。
	ActiveThresholdMinutes int `json:"active_threshold_minutes"`
}

// NewBonusService 创建泡点服务。
func NewBonusService(db *database.Database, cfg *config.GatewayConfig, logger *logger.ConsoleLogger) *BonusService {
	configPath := filepath.Join(filepath.Dir(cfg.Database.Path), "bonus.json")
	return &BonusService{db: db, config: cfg, logger: logger, configPath: configPath, cancel: make(chan struct{})}
}

// SetSessionManager 注入会话管理器。
//
// 泡点按「玩家真实在游戏频道内的时长」计费，必须能看到内存会话表；
// 由 cmd/gateway 在会话管理器建好之后调用本方法注入，之后才能 Start()。
//
// 未注入时不会退回旧口径（凭心跳发钱），而是直接跳过发放并打 WARN ——
// 宁可不发，也不能把「会话已清理还在发泡点」这个故障装回去。
func (s *BonusService) SetSessionManager(sm *session.SessionManager) {
	s.loggerMu.Lock()
	s.sessionMgr = sm
	s.loggerMu.Unlock()
}

// sessionManager 读回注入的会话管理器（加锁读，避免与 SetSessionManager 竞争）。
func (s *BonusService) sessionManager() *session.SessionManager {
	s.loggerMu.Lock()
	defer s.loggerMu.Unlock()
	return s.sessionMgr
}

// EnsureDefaultFile 确保默认配置文件存在。
func (s *BonusService) EnsureDefaultFile() {
	if !utils.FileExists(s.configPath) {
		defaultCfg := BonusConfig{
			Enabled:                true,
			IntervalSeconds:        60,
			AmountPerInterval:      100,
			ActiveThresholdMinutes: 2,
		}
		data, _ := json.MarshalIndent(defaultCfg, "", "  ")
		os.WriteFile(s.configPath, data, 0644)
	}
}

// ConfigPath 返回 bonus.json 的绝对路径（管理后台读取/写回用）。
func (s *BonusService) ConfigPath() string {
	return s.configPath
}

// GetConfig 读出当前泡点配置。
//
// 文件不存在或解析失败时返回错误 —— 这时**不返回默认值**：后台必须看到
// "配置读不出来"，而不是被一份看起来正常的默认配置骗过去（保存下去反而把
// 线上真正在跑的值覆盖掉）。
func (s *BonusService) GetConfig() (*BonusConfig, error) {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil, err
	}
	var cfg BonusConfig
	// 同 loadConfig：容忍 JSONC 注释（生产那份 bonus.json 是带注释的）。
	if err := json.Unmarshal([]byte(config.StripJsoncComments(string(data))), &cfg); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", filepath.Base(s.configPath), err)
	}
	return &cfg, nil
}

// SaveConfig 校验并原子写回 bonus.json。
//
// 生效时机：泡点主循环**每一轮都重新读盘**（runLoop -> loadConfig），所以
// 保存后最迟在下一个计费周期自动生效，**不需要重启网关**。周期调小的情况
// 要等当前这一轮睡完才会读到新值，这是"不重启"换来的一点点延迟，可接受。
//
// 写入用 "临时文件 + rename"：rename 在同一文件系统上是原子的，
// 避免主循环正好在写到一半时读到半截 JSON 而整轮不发放。
//
// ActiveThresholdMinutes 已废弃且不参与发放判定，前端也不展示它；
// 这里按原文件保留，防止把部署脚本仍在写的这个键悄悄抹掉。
func (s *BonusService) SaveConfig(cfg *BonusConfig) error {
	if cfg == nil {
		return errors.New("配置为空")
	}
	if err := s.validateConfig(cfg); err != nil {
		return err
	}

	if existing, err := s.GetConfig(); err == nil && existing != nil {
		if cfg.ActiveThresholdMinutes == 0 {
			cfg.ActiveThresholdMinutes = existing.ActiveThresholdMinutes
		}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := s.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.configPath); err != nil {
		// rename 失败时清掉临时文件，别在 Data 目录里攒垃圾。
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// Start 启动泡点服务（幂等，重复调用无副作用）。
func (s *BonusService) Start() {
	s.loggerMu.Lock()
	if s.running {
		s.loggerMu.Unlock()
		return
	}
	// 每次启动都创建全新的 cancel channel，并把局部变量传给 runLoop，
	// 避免 runLoop 读取被 Stop 置 nil 的字段导致永久阻塞或与 make 竞态。
	cancel := make(chan struct{})
	s.cancel = cancel
	s.running = true
	s.loggerMu.Unlock()

	go s.runLoop(cancel)
}

// Stop 停止泡点服务（幂等）。
func (s *BonusService) Stop() {
	s.loggerMu.Lock()
	if !s.running {
		s.loggerMu.Unlock()
		return
	}
	s.running = false
	cancel := s.cancel
	s.cancel = nil
	s.loggerMu.Unlock()

	// 在锁外 close，避免持锁期间唤醒阻塞的 goroutine 造成不必要的等待
	if cancel != nil {
		close(cancel)
	}
}

// runLoop 泡点主循环。cancel 由 Start 传入并独占持有，
// 不读取 s.cancel 字段，避免与 Stop 的置 nil 产生数据竞争。
//
// G-16（2026-10-08，审查报告）：循环体里原来用 `time.After(...)` —— 每轮都新建一个
// Timer，而 select 从 cancel 分支返回时那个 Timer **谁也不再持有**，要等它自己到点
// 才被回收（配置非法那条是 60 秒）。改成全程复用同一个 Timer + Reset。
//
// ★ Reset 之前必须先 Stop 并把 channel 排空：Timer 到点后 channel 里可能还留着一个
//   陈旧值，不排空的话下一次 select 会被这个假"到点"立刻唤醒（退化成空转）。
func (s *BonusService) runLoop(cancel <-chan struct{}) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	// wait 睡 d；返回 false 表示收到 cancel（调用方直接 return）。
	wait := func(d time.Duration) bool {
		if d < 0 {
			d = 0
		}
		timer.Reset(d)
		select {
		case <-cancel:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return false
		case <-timer.C:
			return true
		}
	}

	// lastSlot 上一轮生效的档位名，用于打「档位切换」日志。
	//
	// 只有跨档的那几轮才写日志 —— 每轮都写的话，60 秒一条噪声会把真正
	// 有用的切换记录淹掉；而这一条恰恰是"配了规则到底按哪档在发"的唯一凭据。
	lastSlot := ""

	for {
		select {
		case <-cancel:
			return
		default:
		}

		cfg := s.loadConfig()
		if cfg == nil || !cfg.Enabled {
			if !wait(5 * time.Second) {
				return
			}
			continue
		}

		if err := s.validateConfig(cfg); err != nil {
			s.logger.Warn(fmt.Sprintf("泡点配置非法: %v", err))
			if !wait(60 * time.Second) {
				return
			}
			continue
		}

		slot, err := s.grantBonusAt(cfg, time.Now())
		if err != nil {
			// grantBonusAt 已经因此一分未发，这里不重复发放，只补一条告警。
			s.logger.Warn(fmt.Sprintf("泡点: 分档配置不可用，本轮不发放: %v", err))
		} else if slot != lastSlot {
			if lastSlot == "" {
				s.logger.Info(fmt.Sprintf("泡点计费启动，当前档位: %s", slot))
			} else {
				s.logger.Info(fmt.Sprintf("泡点档位切换: %s → %s", lastSlot, slot))
			}
			lastSlot = slot
		}

		if !wait(time.Duration(cfg.IntervalSeconds) * time.Second) {
			return
		}
	}
}

func (s *BonusService) loadConfig() *BonusConfig {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil
	}

	var cfg BonusConfig
	// ★ 必须容忍 JSONC（// 与 /* */ 注释）。生产 8.138.9.216 那份 bonus.json 是
	//   .NET 管理页写出来的，**整篇带行注释**；直接 json.Unmarshal 会解析失败 →
	//   loadConfig 返回 nil → 泡点整轮跳过 + 每轮刷一条「泡点配置解析失败」。
	//   与 LoadConfig 读 appsettings.json 用同一套处理，口径一致。
	if err := json.Unmarshal([]byte(config.StripJsoncComments(string(data))), &cfg); err != nil {
		s.logger.Warn(fmt.Sprintf("泡点配置解析失败: %v", err))
		return nil
	}
	return &cfg
}

func (s *BonusService) validateConfig(cfg *BonusConfig) error {
	if cfg.IntervalSeconds < 1 || cfg.IntervalSeconds > 86400 {
		return fmt.Errorf("interval_seconds 取值范围 1~86400")
	}
	if cfg.AmountPerInterval < 0 || cfg.AmountPerInterval > 10000000 {
		return fmt.Errorf("amount_per_interval 取值范围 0~10000000")
	}
	// ActiveThresholdMinutes 已不参与发放判定（见 BonusConfig 注释），
	// 只在显式配置了非法值时提示，缺省 0 不再判为非法。
	if cfg.ActiveThresholdMinutes < 0 || cfg.ActiveThresholdMinutes > 1440 {
		return fmt.Errorf("active_threshold_minutes 取值范围 0~1440")
	}
	// 分档规则：非法就整份拒绝。
	//
	// 这里沿用本文件一贯的"失败即停"口径（见 GetConfig 注释）：任何一条规则
	// 解析不出来都让**整份配置判非法**，主循环跳过本轮并打 WARN，
	// 而不是悄悄忽略那一条 —— 忽略的后果是这条规则静默失效，
	// 玩家拿到的钱和运营以为的不一样，且没有任何地方报错。
	if err := validateBonusRules(cfg.Rules); err != nil {
		return err
	}
	// 时区同理：配了却解析不出来必须报错，不能退回 Local 了事。
	if _, err := cfg.Location(); err != nil {
		return err
	}
	return nil
}

// grantBonus 结算一轮泡点。
//
// 结算对象来自**内存会话表**（session.CollectBonusAwards），不再查网关库
// 的 last_heartbeat。发放条件是玩家真的连着游戏频道且累计满一个计费周期，
// 会话一旦被清理 / 踢下线就再也遍历不到，从根上杜绝「掉线还发泡点」。
func (s *BonusService) grantBonus(cfg *BonusConfig) {
	if _, err := s.grantBonusAt(cfg, time.Now()); err != nil {
		s.logger.Warn(fmt.Sprintf("泡点: 分档规则不可用，本轮不发放: %v", err))
	}
}

// grantBonusAt 结算一轮泡点，返回本轮生效的档位名。
//
// now 可注入是为了两件事：测试能构造确定的时刻（如"周三 23:59"），
// runLoop 能据此感知档位切换并打一条变更日志（排障时最需要先确认的就是
// "这台机器现在到底按哪一档在发"）。
//
// 返回值 err 非空表示**配置本身不可用**（时区解析失败 / 规则非法）→
// 本轮一分不发。这是刻意的失败即止：与其按猜出来的金额发钱，
// 不如停一轮并在日志里留痕。
//
// ★ 同样的档位适用于本轮所有会话：一次结算只差几十毫秒，
//   硬要为每人重算"他各自走到哪一段"只会把账算得更糊涂。
func (s *BonusService) grantBonusAt(cfg *BonusConfig, now time.Time) (string, error) {
	amountPerInterval, slot, err := cfg.ResolveBonus(now)
	if err != nil {
		return "", err
	}

	sm := s.sessionManager()
	if sm == nil {
		s.logger.Warn("泡点: 会话管理器未注入，本轮不发放（计费口径为「真实进入游戏才计时」）")
		return slot, nil
	}

	awards := sm.CollectBonusAwards(now.Unix(), int64(cfg.IntervalSeconds))
	for _, a := range awards {
		display := a.Account
		if display == "" {
			display = a.MId
		}
		// 本轮可能结算出多个周期（例如主循环被拖慢后补上），按周期数发放。
		// ★ 金额取**本轮档位** amountPerInterval，而不是 cfg.AmountPerInterval ——
		//   后者现在只是"没有任何规则命中时"的兜底档。
		delta := int64(amountPerInterval) * a.Intervals

		// 网关库镜像：登录器 CMD_ACCOUNT_INFO 与删除账号预演读这份。
		if err := s.db.UpdateAccountCera(a.MId, delta); err != nil {
			s.logger.Error(fmt.Sprintf("泡点发放失败 %s: %v", display, err))
			continue
		}
		// 游戏库才是玩家在游戏内看到的点券。历史版本只写网关库，
		// 游戏内点券一直是 0（2026-09-23 真机确认）。
		// 已进游戏的账号必然有游戏库账号行；affected==0 说明该账号还没落
		// 游戏库，点券只进了镜像，需人工关注。
		if n, err := s.db.AddCurrencyToGameAccount(a.MId, "cera", delta); err != nil {
			s.logger.Error(fmt.Sprintf("泡点写入游戏库失败 %s: %v", display, err))
		} else if n == 0 {
			s.logger.Warn(fmt.Sprintf("泡点: 账号 %s 在游戏库无账号行，本次 %d cera 只记入网关库镜像", display, delta))
		}
		// 带上档位名：同一套 rules 下金额会随时间变化，日志里没有档位名
		// 就没法回答"这几块钱是哪一档发的"。
		s.logger.Info(fmt.Sprintf("泡点[%s]: %s +%d cera（本轮 %d 个周期，累计已发 %d，余 %d 秒）",
			slot, display, delta, a.Intervals, a.Granted, a.Remainder))
	}
	return slot, nil
}

// DeviceCredentialService 设备凭证服务。
type DeviceCredentialService struct {
	db     *database.Database
	config *config.GatewayConfig
	logger *logger.ConsoleLogger
}

// DeviceResult 设备验证结果。
type DeviceResult struct {
	Secret          string
	Changed         bool
	DeniedErrorCode int
	DeniedMessage   string
}

// NewDeviceCredentialService 创建设备凭证服务。
func NewDeviceCredentialService(db *database.Database, cfg *config.GatewayConfig, logger *logger.ConsoleLogger) *DeviceCredentialService {
	return &DeviceCredentialService{db: db, config: cfg, logger: logger}
}

// VerifyAndIssue 验证设备密钥并签发。
func (s *DeviceCredentialService) VerifyAndIssue(account *database.Account, providedSecret, clientIP string) *DeviceResult {
	providedSecret = utils.TrimSpace(providedSecret)

	// 首次注册
	if account.DeviceSecret == "" {
		// G-15：拿不到随机源就**拒发**，绝不能把全零密钥写进库（那等于所有账号共用一把钥匙）。
		newSecret, err := security.GenerateDeviceSecret()
		if err != nil {
			s.logger.Error(fmt.Sprintf("生成设备密钥失败: %s, err=%v", account.MId, err))
			return &DeviceResult{
				Secret:          "",
				Changed:         false,
				DeniedErrorCode: models.Err.DatabaseError,
				DeniedMessage:   "服务器内部错误，请稍后重试",
			}
		}
		history := []string{formatDeviceEntry(clientIP)}
		s.updateDevice(account.MId, newSecret, history)
		s.logger.Info(fmt.Sprintf("首次设备注册: %s, IP: %s", account.MId, clientIP))
		return &DeviceResult{Secret: newSecret, Changed: false}
	}

	// 密钥匹配
	if security.ConstantTimeEquals(account.DeviceSecret, providedSecret) {
		return &DeviceResult{Secret: account.DeviceSecret, Changed: false}
	}

	// 强制绑定模式：拒绝登录
	if s.config.Device.EnforceBinding {
		s.logger.Warn(fmt.Sprintf("账号 %s 设备密钥不符且已开启强制绑定，拒绝登录, IP: %s", account.MId, clientIP))
		return &DeviceResult{
			Secret:          "",
			Changed:         true,
			DeniedErrorCode: models.Err.DeviceChanged,
			DeniedMessage:   "该账号已在其它设备登录，本次设备未通过绑定校验；请联系管理员核对身份后解除设备绑定",
		}
	}

	// 冷却期检查
	cooldownMinutes := s.config.Device.RotationCooldownMinutes
	if cooldownMinutes > 0 && account.DeviceSecretIssuedAt != "" {
		if issuedAt, err := time.Parse("2006-01-02 15:04:05", account.DeviceSecretIssuedAt); err == nil {
			issuedAt = issuedAt.UTC()
			if time.Now().UTC().Before(issuedAt.Add(time.Duration(cooldownMinutes) * time.Minute)) {
				elapsed := int(time.Since(issuedAt).Minutes())
				remaining := cooldownMinutes - elapsed
				if remaining < 1 {
					remaining = 1
				}
				s.logger.Warn(fmt.Sprintf("账号 %s 在设备密钥换发冷却期内被拒绝, IP: %s", account.MId, clientIP))
				return &DeviceResult{
					Secret:          "",
					Changed:         true,
					DeniedErrorCode: models.Err.DeviceRotationCooldown,
					DeniedMessage:   fmt.Sprintf("该账号刚更换过设备密钥，请 %d 分钟后再试", remaining),
				}
			}
		}
	}

	// 签发新密钥
	// G-15：同首次注册 —— 随机源失败就拒发，不落一个全零密钥。
	newSecret, err := security.GenerateDeviceSecret()
	if err != nil {
		s.logger.Error(fmt.Sprintf("换发设备密钥失败: %s, err=%v", account.MId, err))
		return &DeviceResult{
			Secret:          "",
			Changed:         false,
			DeniedErrorCode: models.Err.DatabaseError,
			DeniedMessage:   "服务器内部错误，请稍后重试",
		}
	}
	historyList := parseHistory(account.DeviceHistory)
	historyList = append([]string{formatDeviceEntry(clientIP)}, historyList...)

	maxHistory := s.config.Device.MaxHistory
	if maxHistory < 1 {
		maxHistory = 1
	}
	if len(historyList) > maxHistory {
		historyList = historyList[:maxHistory]
	}

	s.updateDevice(account.MId, newSecret, historyList)

	// 检查近期设备数
	recentDevices := 0
	seen := map[string]bool{}
	for _, h := range historyList {
		parts := strings.Split(h, "|")
		if len(parts) > 1 && !seen[parts[1]] {
			seen[parts[1]] = true
			recentDevices++
		}
	}
	if recentDevices >= s.config.Device.AlertThreshold {
		s.logger.Warn(fmt.Sprintf("账号 %s 近期在 %d 台不同设备登录", account.MId, recentDevices))
	}

	s.logger.Info(fmt.Sprintf("换设备登录: %s, IP: %s", account.MId, clientIP))
	return &DeviceResult{Secret: newSecret, Changed: true}
}

func (s *DeviceCredentialService) updateDevice(mId, secret string, history []string) {
	historyJSON, _ := json.Marshal(history)
	s.db.UpdateDeviceSecret(mId, secret, string(historyJSON))
}

func formatDeviceEntry(clientIP string) string {
	return fmt.Sprintf("%s|%s", time.Now().UTC().Format("2006-01-02"), clientIP)
}

func parseHistory(jsonStr string) []string {
	if jsonStr == "" {
		return []string{}
	}
	var history []string
	if err := json.Unmarshal([]byte(jsonStr), &history); err != nil {
		return []string{}
	}
	return history
}

// PreflightSystemdControl 启动自检：确认本进程有没有权限启停这些 systemd 单元。
//
// 为什么需要：管理后台的「启停服务 / 重启网关」按钮由 pkg/utils/systemctl.go
// 直接调用 systemctl（不带 sudo），能否成功取决于**宿主机**上的 polkit 规则。
// 规则文件不在二进制里，换台机器重装时很容易漏装 —— 那时按钮会以一句
// "Interactive authentication required" 失败，界面上一句话说不清原因。
//
// 这里在启动时探一次（对已 active 的单元做幂等 start，无副作用），
// 没放行就打一条带修复命令的 ERROR，让问题在启动日志里就暴露。
//
// 探测失败一律不阻断启动：启停只是后台的众多功能之一。
func PreflightSystemdControl(cfg *config.GatewayConfig, log *logger.ConsoleLogger) {
	if !utils.IsLinux() || cfg == nil {
		return
	}

	sc := utils.NewSystemdControl()
	targets := []struct {
		label   string
		unit    string
		enabled bool
	}{
		{"服务端", cfg.Server.Unit, cfg.Server.ControlEnabled},
		{"网关", cfg.GatewayControl.Unit, cfg.GatewayControl.ControlEnabled},
	}

	for _, t := range targets {
		if !t.enabled || t.unit == "" {
			continue
		}
		ok, note := sc.CheckControlPermission(t.unit)
		if ok {
			if log != nil {
				log.Info(fmt.Sprintf("[Control] %s启停权限自检通过（%s：%s）", t.label, t.unit, note))
			}
			continue
		}
		if log != nil {
			log.Error(fmt.Sprintf("[Control] %s启停权限自检**未通过**（%s）：后台的「启停服务」按钮会失败。\n%s",
				t.label, t.unit, note))
			log.Error("[Control] " + utils.AuthDeniedHint)
		}
	}
}

// ServerManager 服务端管理服务。
type ServerManager struct {
	config  *config.GatewayConfig
	logger  *logger.ConsoleLogger
	systemd *utils.SystemdControl
}

// NewServerManager 创建服务端管理服务。
func NewServerManager(cfg *config.GatewayConfig, logger *logger.ConsoleLogger) *ServerManager {
	return &ServerManager{config: cfg, logger: logger, systemd: utils.NewSystemdControl()}
}

// appendProcStats 把进程运行时长与内存写进状态 map（服务端页与网关页共用）。
//
// 字段名用 ping 一样直白的名字，前端不用再换算：
//
//	uptime_seconds 已运行秒数（前端格式化成 "3天 4小时 12分"）
//	started_at     启动时刻（Unix 秒，前端按本地时区显示）
//	rss_bytes      常驻内存字节数（前端格式化成 MB）
//
// 读不到就什么都不加，由前端统一显示"-" —— 不在后端编造 0 值，
// 否则"内存 0 B"看起来像服务挂了。
func appendProcStats(out map[string]interface{}, pid int) {
	if pid <= 0 {
		return
	}
	stats := utils.ReadProcStats(pid)
	if stats == nil {
		return
	}
	if stats.UptimeSeconds > 0 {
		out["uptime_seconds"] = stats.UptimeSeconds
		out["started_at"] = stats.StartedAt
	}
	if stats.RSSBytes > 0 {
		out["rss_bytes"] = stats.RSSBytes
	}
}

// GetStatus 获取服务端状态。
func (s *ServerManager) GetStatus() map[string]interface{} {
	status, _ := s.systemd.Status(s.config.Server.Unit)
	if status == nil {
		return map[string]interface{}{"active": "inactive", "sub_state": "dead"}
	}
	out := map[string]interface{}{
		"active": status.Active, "sub_state": status.SubState,
		"pid": status.PID, "exec_start": status.ExecStart,
	}
	// 运行时长与内存直接读 /proc（见 utils.ReadProcStats 的注释）。
	// 单元没在跑时 PID 为 0，这里自然什么都不加，前端显示"-"。
	appendProcStats(out, status.PID)
	return out
}

// Control 启停控制。
func (s *ServerManager) Control(action string) *ControlResult {
	if !s.config.Server.ControlEnabled {
		return &ControlResult{Ok: false, Error: "服务端控制已禁用"}
	}

	var err error
	switch action {
	case "start":
		err = s.systemd.Start(s.config.Server.Unit)
	case "stop":
		err = s.systemd.Stop(s.config.Server.Unit)
	case "restart":
		err = s.systemd.Restart(s.config.Server.Unit)
	default:
		return &ControlResult{Ok: false, Error: fmt.Sprintf("无效操作: %s", action)}
	}

	if err != nil {
		return &ControlResult{Ok: false, Error: err.Error()}
	}
	return &ControlResult{Ok: true, Error: ""}
}

// TailLog 读取日志尾部。
func (s *ServerManager) TailLog(key string, lines int) *LogResult {
	path := s.resolveLogPath(key)
	if path == "" {
		return &LogResult{Error: "未配置的日志键", Lines: nil}
	}
	fileLines, err := utils.TailFile(path, lines)
	if err != nil {
		return &LogResult{Error: err.Error(), Lines: nil}
	}
	return &LogResult{Error: "", Lines: fileLines}
}

// resolvePvfPath 解析服务端 PVF 的真实路径。
//
// 为什么需要（2026-09-27 修）：服务端实际跑在 WorkDir 的 publish/ 子目录里，
// PVF 在 <WorkDir>/publish/Data/Pvf/Script.pvf。而线上 WorkDir 配的是
// /opt/S4A21Server（**不带** publish），旧代码拿 WorkDir+"Data/Pvf/Script.pvf"
// 拼出一个并不存在的目录，于是：
//   - 上传 → open /opt/S4A21Server/Data/Pvf/Script.pvf.tmp: no such file or directory
//   - 备份 → PVF 静默跳过（连一行日志都没有，长期没进备份也没人发现）
//
// 日志侧的 resolveLogPath 当年已经补了 publish/ 回退，PVF 这两处漏了。
//
// 优先级（先显式配置、后探测，探测只认"目录已存在"）：
//  1. Server.PvfPath                 —— 显式指定，最高优先
//  2. Pvf.FilePath                   —— 网关自己的 PVF 配置（线上配的就是这个）
//  3. <WorkDir>/Data/Pvf/Script.pvf
//  4. <WorkDir>/publish/Data/Pvf/Script.pvf
//
// ★ 刻意**不** mkdir：探测式路径一旦 mkdir，配错 WorkDir 时就会在错的地方
// 建目录并写进一个服务端读不到的 PVF —— 那是最坏的"假成功"（界面报成功、
// 玩家拿到旧配置、没有报错可查）。宁可返回错误。单个配置源明确时（PvfService
// 只用 Pvf.FilePath）才 mkdir。
//
// 返回的 error 会直接展示在后台弹窗里，所以要把候选列表带上，别只说"找不到"。
// ResolvePvfPath 解析服务端 PVF 的实际路径（导出给 admin 端点做路径一致性守卫）。
func (s *ServerManager) ResolvePvfPath() (string, error) {
	return s.resolvePvfPath()
}

func (s *ServerManager) resolvePvfPath() (string, error) {
	var tried []string
	considered := func(p string) bool {
		if p == "" {
			return false
		}
		tried = append(tried, p)
		return utils.FileExists(p)
	}
	// dirExists：文件可以还没放（首次上传就是要创建它），但**父目录必须已存在**。
	dirExists := func(p string) bool {
		if p == "" {
			return false
		}
		tried = append(tried, p)
		if st, err := os.Stat(filepath.Dir(p)); err == nil && st.IsDir() {
			return true
		}
		return false
	}

	// 1. 显式配置的 PvfPath —— 配了就以它为准（存在直接返回，不存在也先用它，
	//    让"配置写错"的报错指向运维亲手填的那个路径）。
	if p := s.config.Server.PvfPath; p != "" {
		if utils.FileExists(p) || dirExists(p) {
			return p, nil
		}
		return p, fmt.Errorf("配置的 Server.PvfPath 不可用（%s）：文件与父目录都不存在", p)
	}

	// 2. Pvf.FilePath —— 网关侧一直在用的那份配置，线上通常已配成绝对路径。
	if p := s.config.Pvf.FilePath; p != "" && filepath.IsAbs(p) {
		if utils.FileExists(p) || dirExists(p) {
			return p, nil
		}
	}

	// 3/4. 按 WorkDir 探测两个候选位置。
	workDir := s.config.Server.WorkDir
	if workDir != "" {
		if p := filepath.Join(workDir, "Data/Pvf/Script.pvf"); considered(p) {
			return p, nil
		}
		if p := filepath.Join(workDir, "publish", "Data/Pvf/Script.pvf"); considered(p) {
			return p, nil
		}
	}

	return "", fmt.Errorf(
		"找不到服务端 PVF 路径，已尝试：%s。请检查 Server.WorkDir / Server.PvfPath / Pvf.FilePath 配置",
		strings.Join(tried, "、"))
}

// ReplacePvf 替换**服务端使用的** PVF（明文，DfoServer 读的那份）。
//
// ★★ 与 PvfService.ReplacePvf 的分工（2026-09-30 方案调整）：
//
//	ServerManager.ReplacePvf（本函数）→ 服务端文件夹，给 DfoServer 用。
//	    **不**登记客户端校验指纹、**不**生成增量包、**不**写版本历史、**不**通知网关。
//	PvfService.ReplacePvf            → 网关侧保存的「客户端基准」（将来是加密版）。
//	    客户端的校验指纹 / 增量更新 / 版本历史全部围绕它。
//
// 两条路径必须指向**不同文件**（调用方负责守卫）。若同一个文件，这个函数会把
// 客户端的 `.bak` 覆盖成新版自己，导致 rebuildDelta 产出 from==to 的自差分，
// 全体旧版客户端进不去 —— 2026-09-30 线上事故的完整成因。
//
// 备份写在本文件自己的 `<path>.bak`（服务端目录内），与网关侧的
// `<Pvf.FilePath>.bak` 是两个文件，互不影响。
func (s *ServerManager) ReplacePvf(src io.Reader) *PvfResult {
	path, err := s.resolvePvfPath()
	if err != nil {
		return &PvfResult{Ok: false, Error: err.Error()}
	}

	utils.BackupFile(path)
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return &PvfResult{Ok: false, Error: err.Error()}
	}
	defer f.Close()

	if _, err := io.Copy(f, src); err != nil {
		return &PvfResult{Ok: false, Error: err.Error()}
	}
	f.Close()

	if err := os.Rename(tmpPath, path); err != nil {
		return &PvfResult{Ok: false, Error: err.Error()}
	}

	// 落盘后回读指纹 —— 让后台能确认「服务端那份现在是哪个版本」，
	// 也便于与服务端的 .bak 对拍（回滚时要用）。
	res := &PvfResult{Ok: true, Path: path, Algo: security.FileFingerprintAlgo}
	if hash, err := security.ComputeFileFingerprintPath(path); err == nil {
		res.Hash = hash
	}
	if stats, err := utils.GetFileStats(path); err == nil {
		res.Size = stats.Size
		res.ModifiedUtc = stats.ModifiedUtc
	}
	s.logger.Info(fmt.Sprintf("服务端 PVF 已替换: %s (%s, %d 字节)",
		path, shortHash(res.Hash), res.Size))
	return res
}

// ServerPvfInfo 读服务端 PVF 的当前落盘信息（只读，不写盘）。
//
// 用于后台展示「服务端那份现在是什么」—— 它与客户端校验指纹（Pvf.FilePath）
// 是两件事，页面必须分别显示，否则运维会误以为改一个另一个也跟着变。
func (s *ServerManager) ServerPvfInfo() (*PvfResult, error) {
	path, err := s.resolvePvfPath()
	if err != nil {
		return nil, err
	}
	res := &PvfResult{Ok: true, Path: path, Algo: security.FileFingerprintAlgo}
	if !utils.FileExists(path) {
		return res, nil
	}
	if hash, err := security.ComputeFileFingerprintPath(path); err == nil {
		res.Hash = hash
	}
	if stats, err := utils.GetFileStats(path); err == nil {
		res.Size = stats.Size
		res.ModifiedUtc = stats.ModifiedUtc
	}
	return res, nil
}

// Backup 备份数据库与 PVF 到 BackupDir。
//
// 备份对象：游戏库存库（inventory.db）+ 网关库（gateway.db）+ 服务端 PVF。
// 采用 SQLite 官方推荐的 VACUUM INTO 方式做热备份（无需停机、保证一致性）；
// PVF 走文件复制。任一目标缺失只跳过，不算失败。
//
// 第 4 步（可选，Server.BackupPurgeAuditLog，默认开）：库存库**备份成功之后**
// 清空背包审计日志并 VACUUM 收缩文件。顺序不能反 —— 这些日志清掉后就只存在于
// 备份里了，没有备份副本时绝不删线上数据。
func (s *ServerManager) Backup() *BackupResult {
	// 2026-10-16 起真正的实现在 BackupWith：可勾选目标 + 分类 tar.gz 打包。
	// 这里保留旧签名与旧语义（空选项 = 默认目标集 = 两个库 + PVF），
	// 现有调用方（后台「立即备份」、更新流程向导第 8 步、旧单测）一行都不用改。
	//
	// ★ 差异只有一处且是刻意的：产物从「三份散装文件」变成「db-/pvf- 两个 .tar.gz」。
	//   恢复时要先解压（tar -xzf），界面上已写明。
	return s.BackupWith(BackupOptions{})
}

// auditPurgeBatchRows 是单批删除的行数。
//
// 为什么不一条 DELETE 全删：审计表在现网能到百万行 / 数百 MB，单条大事务会把
// 写锁一直攥在手里，VACUUM 前还会把 WAL 撑到与表同量级（500MB+）。
// 分批提交让服务端的背包落库能在批与批之间插进去跑，锁等待从"一次几十秒"
// 摊成"多次几秒"，WAL 也能被自动 checkpoint 收掉。
const auditPurgeBatchRows = 200000

// auditPurgeMaxBatches 兜底上限，防止数据异常时无限循环（200000 × 500 = 1 亿行）。
const auditPurgeMaxBatches = 500

// purgeGameAuditLog 清空游戏库里的背包审计日志（inventory_audit_log）并 VACUUM 收缩文件。
//
// ⚠️ 只应在库存库已经成功备份之后调用：清掉之后这些日志就只存在于备份里。
//
// 为什么必须 VACUUM：SQLite 的 DELETE 只把页标成空闲、还给 freelist，
// **文件大小不会变**（只会被后续写入复用）。要真正把 500MB 还给文件系统，
// 只能 VACUUM（重建库文件）。实测现网 145 万行审计日志占库 91%（514MB/563MB）。
//
// 表不存在时静默跳过（返回值 rows=0、err=nil）：开发库/老库可能没有这张表，
// 不该因为这个让备份报错。
func purgeGameAuditLog(path string, logger *logger.ConsoleLogger) (rows, before, after int64, err error) {
	if fi, e := os.Stat(path); e == nil {
		before, after = fi.Size(), fi.Size()
	}

	// busy_timeout 给足：服务端在跑，写锁要排队等
	db, e := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(60000)", path))
	if e != nil {
		return 0, before, after, fmt.Errorf("打开游戏库失败: %v", e)
	}
	defer db.Close()

	// 0) 表在不在：不在就跳过（开发库/老库没有这张表）
	var tblCount int
	if e := db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='inventory_audit_log'",
	).Scan(&tblCount); e != nil {
		return 0, before, after, fmt.Errorf("检查审计表失败: %v", e)
	}
	if tblCount == 0 {
		return 0, before, after, nil
	}

	// 1) 分批删除。
	// 用 rowid 子查询而不是 DELETE ... LIMIT：LIMIT 需要 SQLITE_ENABLE_UPDATE_DELETE_LIMIT
	// 编译开关，驱动不一定带。表若是 WITHOUT ROWID，rowid 会报错 —— 此时退回整表删除。
	batch := int64(0)
	useRowid := true
	for i := 0; i < auditPurgeMaxBatches; i++ {
		var res sql.Result
		var e error
		if useRowid {
			res, e = db.Exec(fmt.Sprintf(
				"DELETE FROM inventory_audit_log WHERE rowid IN (SELECT rowid FROM inventory_audit_log LIMIT %d)",
				auditPurgeBatchRows))
			if e != nil && strings.Contains(strings.ToLower(e.Error()), "rowid") {
				useRowid = false // WITHOUT ROWID 表 → 换整表删除
				res, e = db.Exec("DELETE FROM inventory_audit_log")
			}
		} else {
			res, e = db.Exec("DELETE FROM inventory_audit_log")
		}
		if e != nil {
			return batch, before, after, fmt.Errorf("删除审计日志失败（已删 %d 行）: %v", batch, e)
		}
		n, _ := res.RowsAffected()
		batch += n
		if !useRowid || n < auditPurgeBatchRows {
			break // 已删完
		}
	}

	// 2) 先把 WAL 落盘并截断，再 VACUUM —— WAL 里还压着已删页时 VACUUM 回收不到那部分。
	// checkpoint 是尽力而为：服务端持有读快照时会返回 busy，不影响后续 VACUUM。
	if _, e := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil && logger != nil {
		logger.Warn(fmt.Sprintf("[备份] wal_checkpoint 未完成（不影响继续）: %v", e))
	}

	// 3) VACUUM 重建库文件，把空闲页真正还给文件系统。
	// 这一步需要独占写锁，是本次操作里唯一可能让服务端写入短暂排队的时刻。
	if _, e := db.Exec("VACUUM"); e != nil {
		if fi, se := os.Stat(path); se == nil {
			after = fi.Size()
		}
		return batch, before, after, fmt.Errorf(
			"审计日志已清空 %d 行，但 VACUUM 收缩失败（库文件未变小，可停服后重试）: %v", batch, e)
	}

	// 4) VACUUM 会把改动再写一遍 WAL，收尾再截断一次，避免残留大 WAL 文件。
	if _, e := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil && logger != nil {
		logger.Warn(fmt.Sprintf("[备份] 收尾 wal_checkpoint 未完成: %v", e))
	}

	if fi, se := os.Stat(path); se == nil {
		after = fi.Size()
	}
	return batch, before, after, nil
}

// backupSqliteFile 使用 SQLite 的 VACUUM INTO 做一致性热备份。
// 失败时回退为文件复制（对非 SQLite 文件或旧版本驱动更稳）。
//
// 回退路径（P2-2）：不能一律文件复制。源库正在写入时，WAL 里还有未并回主库的页，
// 纯文件复制不经过 SQLite，复制出来的 .db 会停在半写入状态 —— 而这份副本是要
// 当"备份"交付给运维的。所以回退分成两种情况，见 fallbackCheckpoint。
func backupSqliteFile(src, dst string) error {
	// 目标文件已存在时 VACUUM INTO 会报错，先确保不存在
	_ = os.Remove(dst)

	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", src))
	if err == nil {
		// VACUUM INTO 需要目标路径用单引号转义
		quoted := "'" + strings.ReplaceAll(dst, "'", "''") + "'"
		if _, err := db.Exec("VACUUM INTO " + quoted); err == nil {
			db.Close()
			return nil
		}

		// VACUUM INTO 不可用 → 回退。顺序要紧：先用连接做 checkpoint，
		// 再关连接，最后才复制文件（复制时不带自己的句柄/读锁）。
		cerr := fallbackCheckpoint(db, src)
		db.Close()
		if cerr != nil {
			return cerr
		}
	}

	// 回退：文件复制。
	//   - src 不是 SQLite 库（PVF / 文本 / 旧驱动）→ 文件复制正是要的行为；
	//   - src 是 SQLite → fallbackCheckpoint 已把 WAL 并回主库，副本一致。
	_ = os.Remove(dst)
	return utils.CopyFile(src, dst)
}

// fallbackCheckpoint 在 VACUUM INTO 不可用时，对「确认是 SQLite 库」的源先做
// wal_checkpoint(FULL)，把 WAL 里未并回主库的页落进主库文件。
//
// 为什么（P2-2）：备份副本要能被当成"某一时刻的完整库"打开并查询。
// 带着未 checkpoint 的 WAL 直接复制 .db，副本会缺最近的事务，甚至读到半写入页。
// checkpoint 也失败时返回错误 —— 宁可这次备份失败，也不交付一个不确定的副本。
//
// 非 SQLite 源（PVF / 文本）直接返回 nil：那些文件没有 WAL 概念，复制即可。
func fallbackCheckpoint(db *sql.DB, src string) error {
	if !isSQLiteFile(src) {
		return nil
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(FULL)"); err != nil {
		return fmt.Errorf("VACUUM INTO 失败后 wal_checkpoint(FULL) 也不成功，拒绝交付可能不一致的备份副本: %w", err)
	}
	return nil
}

// isSQLiteFile 按文件头判定是否 SQLite 库（前 16 字节固定为 "SQLite format 3\0"）。
//
// 不用扩展名判定：备份清单里的 .db 可能被改名，而文件头是格式自身的定义。
// 这个判定存在的意义是区分「回退该不该做 checkpoint」——
// 对 PVF/文本硬跑 checkpoint 会让原本能成功的文件复制备份整体失败。
func isSQLiteFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var head [16]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return false
	}
	return string(head[:]) == "SQLite format 3\x00"
}

// BackupDir 获取备份目录。
func (s *ServerManager) BackupDir() string {
	return s.config.Server.BackupDir
}

func (s *ServerManager) resolveLogPath(key string) string {
	workDir := s.config.Server.WorkDir
	switch key {
	case "server":
		if s.config.Server.LogPath != "" {
			return s.config.Server.LogPath
		}
		// 202 实测：服务端真实日志在 WorkDir 下的 publish/ 子目录
		// （WorkDir=/opt/S4A21Server，日志=/opt/S4A21Server/publish/server.log）。
		// 按"先 WorkDir 根、再 publish/ 子目录"的顺序取第一个存在的文件。
		root := filepath.Join(workDir, "server.log")
		sub := filepath.Join(workDir, "publish", "server.log")
		if _, err := os.Stat(root); err == nil {
			return root
		}
		if _, err := os.Stat(sub); err == nil {
			return sub
		}
		return root
	case "packet":
		return filepath.Join(workDir, "packet.log")
	case "gateway":
		return filepath.Join(workDir, "gateway.log")
	case "error":
		return filepath.Join(workDir, "error.log")
	}
	return ""
}

// ControlResult 控制操作结果。
type ControlResult struct {
	Ok    bool
	Error string
}

// LogResult 日志读取结果。
type LogResult struct {
	Error string
	Lines []string
}

// PvfResult PVF 替换结果。
type PvfResult struct {
	Ok    bool
	Error string
	// 以下为替换成功后的实际落盘信息，供后台核对「服务端那份到底是什么」。
	Path        string
	Hash        string
	Algo        string
	Size        int64
	ModifiedUtc string
}

// BackupResult 备份结果。
//
// AuditPurge* / GameDbBytes* 是第 4 步（清理审计日志）的结果：
// 清理失败只体现在 AuditPurgeError 上，**不影响 Ok**（备份本身是成功的）。
type BackupResult struct {
	Ok    bool   `json:"Ok"`
	Error string `json:"Error"`

	AuditPurgedRows   int64  `json:"AuditPurgedRows"`   // 实际删除的审计日志行数
	AuditPurgeError   string `json:"AuditPurgeError"`   // 清理失败原因（不影响备份成功）
	AuditPurgeSkipped string `json:"AuditPurgeSkipped"` // 为什么没清理（未启用/游戏库未备份）
	GameDbBytesBefore int64  `json:"GameDbBytesBefore"` // 清理前库存库文件大小
	GameDbBytesAfter  int64  `json:"GameDbBytesAfter"`  // 清理（VACUUM）后库存库文件大小

	// 以下三项是 2026-10-16「可勾选目标 + 分类 tar.gz」改造新增。
	// 保留旧字段不动：前端向导第 8 步只认 AuditPurge* / GameDbBytes*，
	// 加字段不影响它，删字段会立刻把它打回「备份失败」。
	Archives    []BackupArchive `json:"Archives"`     // 本次产出的压缩包（db/pvf/logs 各一个）
	Selected    []string        `json:"Selected"`     // 实际备份进去的目标 key
	RetainError []string        `json:"RetainError"`  // 保留策略清理失败的原因（不影响备份成功）
}

// GatewayManager 网关自身管理服务。
type GatewayManager struct {
	config         *config.GatewayConfig
	logger         *logger.ConsoleLogger
	systemd        *utils.SystemdControl
	controlEnabled bool
	gatewayLogPath string
	errorLogPath   string
}

// NewGatewayManager 创建网关管理服务。
func NewGatewayManager(cfg *config.GatewayConfig, logger *logger.ConsoleLogger, workDir string) *GatewayManager {
	logDir := filepath.Join(workDir, "logs")
	return &GatewayManager{
		config:         cfg,
		logger:         logger,
		systemd:        utils.NewSystemdControl(),
		controlEnabled: cfg.GatewayControl.ControlEnabled,
		gatewayLogPath: filepath.Join(logDir, "gateway.log"),
		errorLogPath:   filepath.Join(logDir, "error.log"),
	}
}

// GetStatus 获取网关状态。
func (s *GatewayManager) GetStatus() map[string]interface{} {
	status, _ := s.systemd.Status(s.config.GatewayControl.Unit)
	if status == nil {
		return map[string]interface{}{"active": "inactive", "sub_state": "dead"}
	}
	out := map[string]interface{}{
		"active": status.Active, "sub_state": status.SubState,
		"pid": status.PID, "exec_start": status.ExecStart,
	}
	appendProcStats(out, status.PID)
	return out
}

// Control 启停控制。
func (s *GatewayManager) Control(action string) *ControlResult {
	if !s.controlEnabled {
		return &ControlResult{Ok: false, Error: "网关控制已禁用"}
	}

	var err error
	switch action {
	case "start":
		err = s.systemd.Start(s.config.GatewayControl.Unit)
	case "stop":
		err = s.systemd.Stop(s.config.GatewayControl.Unit)
	case "restart":
		err = s.systemd.Restart(s.config.GatewayControl.Unit)
	default:
		return &ControlResult{Ok: false, Error: fmt.Sprintf("无效操作: %s", action)}
	}

	if err != nil {
		return &ControlResult{Ok: false, Error: err.Error()}
	}
	return &ControlResult{Ok: true, Error: ""}
}

// TailLog 读取网关日志尾部。
func (s *GatewayManager) TailLog(key string, lines int) *LogResult {
	var path string
	switch key {
	case "gateway":
		path = s.gatewayLogPath
	case "error":
		path = s.errorLogPath
	default:
		return &LogResult{Error: fmt.Sprintf("无效日志键: %s", key), Lines: nil}
	}

	fileLines, err := utils.TailFile(path, lines)
	if err != nil {
		return &LogResult{Error: err.Error(), Lines: nil}
	}
	return &LogResult{Error: "", Lines: fileLines}
}

// ControlEnabled 获取控制开关状态。
func (s *GatewayManager) IsControlEnabled() bool {
	return s.controlEnabled
}

// GatewayLogPath 获取网关日志路径。
func (s *GatewayManager) GetGatewayLogPath() string {
	return s.gatewayLogPath
}

// ErrorLogPath 获取错误日志路径。
func (s *GatewayManager) GetErrorLogPath() string {
	return s.errorLogPath
}

// AppSettingsEditor 配置编辑器。
type AppSettingsEditor struct {
	configDir string
	config    *config.GatewayConfig
}

// NewAppSettingsEditor 创建配置编辑器。
func NewAppSettingsEditor(configDir string, config *config.GatewayConfig) *AppSettingsEditor {
	return &AppSettingsEditor{configDir: configDir, config: config}
}

// SaveOverride 保存热更新配置。
func (s *AppSettingsEditor) SaveOverride(updates map[string]interface{}) error {
	return config.SaveOverride(s.configDir, updates)
}
