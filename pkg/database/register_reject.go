package database

// 注册**被拒**流水（register_rejects）的读写。
//
// 与 register_logs 的分工：
//   - register_logs：只记**成功**的注册，是「同 IP / 同机器码注册数」的计数依据，
//     删账号时会按 purgeLogs 一并清理；
//   - register_rejects：只记**失败**的尝试（限额、邀请码无效、重名、库错），
//     纯审计，不参与任何计数，也不跟着删号消失。
//
// 为什么需要它（2026-11-01）：玩家来问「为什么我注册不了」时，运营原来只能翻
// 网关日志；后台「注册流水」页看不到任何失败痕迹 —— 因为失败的注册根本没落库。

// RegisterReject 是一条被拒的注册尝试。
type RegisterReject struct {
	ID         int64  `json:"id"`
	Account    string `json:"account"`
	IP         string `json:"ip"`
	MachineID  string `json:"machine_id"`
	ReasonCode int    `json:"reason_code"`
	Reason     string `json:"reason"`
	CreatedAt  int64  `json:"created_at"`
}

// InsertRegisterReject 记一条被拒的注册尝试。
//
// ★ 写失败**不该**影响注册流程：这是审计数据，不是业务数据。
// 调用方忽略返回值，只在日志里提一句。
func (db *Database) InsertRegisterReject(
	account, ip, machineID string, reasonCode int, reason string, at int64,
) error {
	_, err := db.gatewayDB.Exec(
		`INSERT INTO register_rejects (account, ip, machine_id, reason_code, reason, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		account, ip, machineID, reasonCode, reason, at)
	return err
}

// ListRecentRegisterRejects 取最近的被拒记录。ip 为空表示不过滤（全量最近 N 条）。
func (db *Database) ListRecentRegisterRejects(ip string, limit int) ([]RegisterReject, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	q := `SELECT id, account, ip, machine_id, reason_code, reason, created_at
	        FROM register_rejects`
	args := make([]interface{}, 0, 2)
	if ip != "" {
		q += " WHERE ip = ?"
		args = append(args, ip)
	}
	q += " ORDER BY created_at DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.gatewayDB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]RegisterReject, 0, limit)
	for rows.Next() {
		var r RegisterReject
		if err := rows.Scan(&r.ID, &r.Account, &r.IP, &r.MachineID,
			&r.ReasonCode, &r.Reason, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
