package database

// 注册流水（register_logs）的读写。
//
// 这张表只有一个用途：给注册限额当**计数依据**（同 IP 当日注册数 / 同机器码累计注册数）。
// 它是纯追加的审计式数据，不做更新、不做删除，所以这里只有 insert + count。

// InsertRegistrationLog 写入一条注册流水。
//
// machineID 允许为空串（老登录器不带该字段）。ip 允许为空串（TCP 远端地址解析失败时），
// 但调用方应当尽量避免 —— 空 IP 的流水在"同 IP 计数"里会与其它空 IP 行混在一起。
//
// ★ 写失败**不该**让注册失败：账号已经建好了，把玩家挡在门外是最坏的结果。
// 由调用方决定降级（记日志），本函数只如实返回错误。
func (db *Database) InsertRegistrationLog(account, mID, ip, machineID string, at int64) error {
	_, err := db.gatewayDB.Exec(
		"INSERT INTO register_logs (account, m_id, ip, machine_id, created_at) VALUES (?, ?, ?, ?, ?)",
		account, mID, ip, machineID, at)
	return err
}

// CountRegistrationsByIPSince 统计某来源 IP 在 since（含）之后注册的账号数。
//
// since 由调用方按**网关进程时区**的零点算好（见 service.startOfToday）：
// 数据库这一层不做时区推断，否则两个调用点各按各的口径切分"今天"。
//
// ip 为空时直接返回 0 而不是去查空串：查空串会把所有"没取到 IP"的历史行
// 算成一个共同来源，反而误杀。宁可不限，也不要拦错人。
func (db *Database) CountRegistrationsByIPSince(ip string, since int64) (int, error) {
	if ip == "" {
		return 0, nil
	}
	var n int
	err := db.gatewayDB.QueryRow(
		"SELECT COUNT(*) FROM register_logs WHERE ip = ? AND created_at >= ?", ip, since).Scan(&n)
	return n, err
}

// CountRegistrationsByMachine 统计某机器码累计注册的账号数（不限时间窗）。
//
// machineID 为空时返回 0：空串代表"客户端没上报"，不是"同一台机器"。
// 这里绝不能退化成 `WHERE machine_id = ''` —— 那会让所有老登录器共用一个配额，
// 上线第一天就把全服的注册堵死。
func (db *Database) CountRegistrationsByMachine(machineID string) (int, error) {
	if machineID == "" {
		return 0, nil
	}
	var n int
	err := db.gatewayDB.QueryRow(
		"SELECT COUNT(*) FROM register_logs WHERE machine_id = ?", machineID).Scan(&n)
	return n, err
}

// ListRecentRegistrationLogsByIP 返回某 IP 最近的注册流水（排查用：后台/日志核对
// "这条 IP 到底注册了哪些号"）。limit <= 0 时按 20 条。
func (db *Database) ListRecentRegistrationLogsByIP(ip string, limit int) ([]RegistrationLog, error) {
	if ip == "" {
		return nil, nil
	}
	return db.queryRegistrationLogs("ip = ?", ip, limit)
}

// ListRecentRegistrationLogsByMachine 返回某机器码最近的注册流水。
// 与 ByIP 对称：后台按"这台机器注册了哪些号"排查时用。
func (db *Database) ListRecentRegistrationLogsByMachine(machineID string, limit int) ([]RegistrationLog, error) {
	if machineID == "" {
		return nil, nil
	}
	return db.queryRegistrationLogs("machine_id = ?", machineID, limit)
}

// queryRegistrationLogs 按 where 条件取最近的注册流水。
//
// where 只由本文件的三个调用点传入**字面量**（不是外部输入），值一律走占位符 ——
// 不拼字符串，避免 SQL 注入，也让这条约束在 code review 时一眼可见。
func (db *Database) queryRegistrationLogs(where string, arg interface{}, limit int) ([]RegistrationLog, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := db.gatewayDB.Query(
		"SELECT account, m_id, ip, machine_id, created_at FROM register_logs WHERE "+where+" ORDER BY id DESC LIMIT ?",
		arg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RegistrationLog
	for rows.Next() {
		var r RegistrationLog
		if err := rows.Scan(&r.Account, &r.MID, &r.IP, &r.MachineID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RegistrationLog 是一条注册流水。
type RegistrationLog struct {
	Account   string
	MID       string
	IP        string
	MachineID string
	CreatedAt int64
}
