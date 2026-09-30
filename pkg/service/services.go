package service

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/session"
	"s4a21-gateway/pkg/utils"
)

// AccountService 账号服务。
type AccountService struct {
	db     *database.Database
	config *config.GatewayConfig
	logger *logger.ConsoleLogger
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
	for _, a := range accounts {
		names = append(names, a.Name)
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

	for _, a := range accounts {
		cera := a.Cera
		if c, _, _, ok := s.db.GetCurrencyTripleByMId(a.MId); ok {
			cera = c
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
type PvfService struct {
	config *config.GatewayConfig
	logger *logger.ConsoleLogger
	mu     sync.RWMutex
	info   *models.PvfInfo
	mode   string
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

// RefreshCache 刷新 PVF 指纹缓存。
//
// 采用流式计算全文件 SHA-256（PVF 可达数百 MB），避免整文件读入内存；
// 指纹按**大写**返回，与登录器侧比对口径一致。
func (s *PvfService) RefreshCache() error {
	path := s.config.Pvf.FilePath
	if !utils.FileExists(path) {
		s.mu.Lock()
		s.info = &models.PvfInfo{Path: path, Hash: "", Algo: security.FileFingerprintAlgo, Size: 0, ModifiedUtc: ""}
		s.mu.Unlock()
		return nil
	}

	hash, err := security.ComputeFileFingerprintPath(path)
	if err != nil {
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
	s.mu.Unlock()
	return nil
}

// ReplacePvf 替换 PVF 文件。
func (s *PvfService) ReplacePvf(src io.Reader) (*models.PvfInfo, error) {
	path := s.config.Pvf.FilePath
	if err := utils.MkdirAll(filepath.Dir(path)); err != nil {
		return nil, err
	}

	// 备份旧文件
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

// IntegrityStore 完整性策略存储。
//
// 策略会持久化到 <configDir>/integrity_policy.json，重启后自动加载，
// 避免进程重启导致全部白/黑名单与放行模块丢失。
type IntegrityStore struct {
	mu         sync.RWMutex
	snapshot   *models.IntegritySnapshot
	policyPath string
	logger     *logger.ConsoleLogger
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
		s.load()
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

// load 从磁盘加载策略。文件不存在或解析失败时保持默认空策略（不阻断启动）。
func (s *IntegrityStore) load() {
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
	}
}

// Snapshot 获取快照的深拷贝，避免调用方在锁外读取时与写操作产生数据竞争。
func (s *IntegrityStore) Snapshot() *models.IntegritySnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSnapshot(s.snapshot)
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
func (s *BonusService) runLoop(cancel <-chan struct{}) {
	for {
		select {
		case <-cancel:
			return
		default:
		}

		cfg := s.loadConfig()
		if cfg == nil || !cfg.Enabled {
			select {
			case <-cancel:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		if err := s.validateConfig(cfg); err != nil {
			s.logger.Warn(fmt.Sprintf("泡点配置非法: %v", err))
			select {
			case <-cancel:
				return
			case <-time.After(60 * time.Second):
			}
			continue
		}

		s.grantBonus(cfg)

		select {
		case <-cancel:
			return
		case <-time.After(time.Duration(cfg.IntervalSeconds) * time.Second):
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
	return nil
}

// grantBonus 结算一轮泡点。
//
// 结算对象来自**内存会话表**（session.CollectBonusAwards），不再查网关库
// 的 last_heartbeat。发放条件是玩家真的连着游戏频道且累计满一个计费周期，
// 会话一旦被清理 / 踢下线就再也遍历不到，从根上杜绝「掉线还发泡点」。
func (s *BonusService) grantBonus(cfg *BonusConfig) {
	sm := s.sessionManager()
	if sm == nil {
		s.logger.Warn("泡点: 会话管理器未注入，本轮不发放（计费口径为「真实进入游戏才计时」）")
		return
	}

	awards := sm.CollectBonusAwards(time.Now().Unix(), int64(cfg.IntervalSeconds))
	for _, a := range awards {
		display := a.Account
		if display == "" {
			display = a.MId
		}
		// 本轮可能结算出多个周期（例如主循环被拖慢后补上），按周期数发放。
		delta := int64(cfg.AmountPerInterval) * a.Intervals

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
		s.logger.Info(fmt.Sprintf("泡点: %s +%d cera（本轮 %d 个周期，累计已发 %d，余 %d 秒）",
			display, delta, a.Intervals, a.Granted, a.Remainder))
	}
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
		newSecret := security.GenerateDeviceSecret()
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
	newSecret := security.GenerateDeviceSecret()
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

// ReplacePvf 替换服务端 PVF。
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

	return &PvfResult{Ok: true, Error: ""}
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
	dir := s.config.Server.BackupDir
	if dir == "" {
		return &BackupResult{Ok: false, Error: "未配置备份目录 BackupDir"}
	}
	if err := utils.MkdirAll(dir); err != nil {
		return &BackupResult{Ok: false, Error: err.Error()}
	}

	stamp := time.Now().UTC().Format("20060102-150405")
	var done []string
	var errs []string

	// 1. 游戏库存库（最关键的数据）
	gamePath := s.config.Database.GamePath
	gameBackedUp := false
	if gamePath != "" && utils.FileExists(gamePath) {
		dst := filepath.Join(dir, fmt.Sprintf("inventory-%s.db", stamp))
		if err := backupSqliteFile(gamePath, dst); err != nil {
			errs = append(errs, fmt.Sprintf("inventory: %v", err))
		} else {
			done = append(done, dst)
			gameBackedUp = true
		}
	}

	// 2. 网关库
	gwPath := s.config.Database.Path
	if gwPath != "" && utils.FileExists(gwPath) {
		dst := filepath.Join(dir, fmt.Sprintf("gateway-%s.db", stamp))
		if err := backupSqliteFile(gwPath, dst); err != nil {
			errs = append(errs, fmt.Sprintf("gateway: %v", err))
		} else {
			done = append(done, dst)
		}
	}

	// 3. 服务端 PVF
	//
	// 解析不出路径**不算备份失败**（备份主目标是两个库），但绝不静默 ——
	// 2026-09-27 之前这段一声不吭，PVF 长期没进备份也没人发现。
	if pvfPath, err := s.resolvePvfPath(); err != nil {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("[备份] 跳过 PVF：%v", err))
		}
	} else if utils.FileExists(pvfPath) {
		dst := filepath.Join(dir, fmt.Sprintf("Script-%s.pvf", stamp))
		if err := utils.CopyFile(pvfPath, dst); err != nil {
			errs = append(errs, fmt.Sprintf("pvf: %v", err))
		} else {
			done = append(done, dst)
		}
	} else if s.logger != nil {
		s.logger.Error(fmt.Sprintf("[备份] 跳过 PVF：解析到的路径上还没有文件（%s）", pvfPath))
	}

	if len(done) == 0 && len(errs) == 0 {
		return &BackupResult{Ok: false, Error: "没有找到可备份的目标文件（请检查 GamePath / Path / PvfPath 配置）"}
	}
	if len(errs) > 0 {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("[备份] 部分失败: %v，成功 %d 项", errs, len(done)))
		}
		return &BackupResult{Ok: false, Error: strings.Join(errs, "; ")}
	}

	// 4. 审计日志清理 + 库文件收缩（只在库存库备份成功之后做）
	result := &BackupResult{Ok: true}
	if !s.config.Server.PurgeAuditLogEnabled() {
		result.AuditPurgeSkipped = "未启用（Server.BackupPurgeAuditLog=false）"
	} else if !gameBackedUp {
		result.AuditPurgeSkipped = "游戏库未备份（GamePath 未配置或文件不存在），为避免丢数据跳过清理"
	} else {
		rows, before, after, err := purgeGameAuditLog(gamePath, s.logger)
		result.AuditPurgedRows = rows
		result.GameDbBytesBefore = before
		result.GameDbBytesAfter = after
		if err != nil {
			// 清理失败**不回滚备份**：备份本身是成功的，这里只作为告警回报。
			result.AuditPurgeError = err.Error()
			if s.logger != nil {
				s.logger.Warn(fmt.Sprintf("[备份] 审计日志清理告警: %v", err))
			}
		} else if rows > 0 && s.logger != nil {
			s.logger.Info(fmt.Sprintf("[备份] 已清理审计日志 %d 条，游戏库 %.1fMB -> %.1fMB",
				rows, float64(before)/1048576.0, float64(after)/1048576.0))
		}
	}

	if s.logger != nil {
		s.logger.Info(fmt.Sprintf("[备份] 完成，共 %d 项 -> %s", len(done), dir))
	}
	return result
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
