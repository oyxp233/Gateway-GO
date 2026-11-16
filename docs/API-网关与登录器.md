# 网关 ↔ 登录器 接口文档

> 适用：`Gateway-GO`（分支 `feature/s5a3-standalone`）与 `Launcher-WPF`（分支 `s5a3`）
> 最后更新：2026-11-16（新增下载限速后）
> ★ **本文件随代码仓库分发，是接口的唯一权威描述**。改路由/改字段必须同批改这里。

---

## 0. 一分钟版

```
玩家侧（8080，HTTPS，免鉴权）
  登录器启动 → GET /api/launcher/policy      拉策略 + PVF 期望值 + 门禁开关
            → GET /api/launcher/servers     拉服清单（签名）
            → GET /api/launcher/plugins     拉插件清单（内容寻址 sha256）
            → GET 上述清单里的下载 URL       插件 / PVF 增量 / 自更新 / DNF.exe

管理侧（8443，HTTPS，X-Auth-Key）
  发版 → POST /api/admin/launcher/upload     登录器新版本（★ 唯一正确入口）
       → POST /api/admin/dnfexe/upload       DNF.exe 新版本
       → POST /api/admin/upload-pvf          PVF 新版本
       → POST /api/admin/plugins/upload      插件文件
```

**所有更新文件都必须走管理侧 API 上传，禁止直接覆盖服务器上的 `current.exe`。**
原因见 §3.3：手拷不会写 `history/`，客户端就拿不到增量包，只能全量重下。

---

## 1. 监听端口与用途

| 端口 | 协议 | 绑定 | 用途 | 鉴权 |
|---|---|---|---|---|
| 8080 | HTTPS | `0.0.0.0` | 登录器 HTTP 通道（策略/清单/下载/上报） | 免鉴权 |
| 8443 | HTTPS | `127.0.0.1` | 管理 API（后台页面与发版） | `X-Auth-Key` |
| 18080 | HTTP 明文 | `127.0.0.1` | 网关 ↔ admin 进程内部 API | `X-Internal-Key` |
| 8000 | TCP | `0.0.0.0` | 登录/注册二进制协议（非 HTTP） | — |
| 7001 | TCP | `0.0.0.0` | 频道口 1:1 透传 | — |
| 10001~10508（按 `proxy_ports.json`） | TCP | `0.0.0.0` | 游戏口 1:1 透传 | — |
| 30000~30063 | UDP | `0.0.0.0` | 组队中继 | — |

> 双进程形态下，8080 只注册「公开路由」，管理路由只出现在 8443。
> **不要把管理 API 暴露到公网**；8443 正常只绑回环，需要远程访问时用 SSH 隧道或
> `socat` 做 TLS 透传（测试 VM 就是这么做的）。

---

## 2. 通用约定

### 2.1 鉴权

| 场景 | 方式 |
|---|---|
| 管理 API | 请求头 `X-Auth-Key: <key>`，或 `Authorization: Bearer <key>` |
| 内部 API | 请求头 `X-Internal-Key: <key>` |
| 公开 API | 无 |

key 在服务器 `/opt/s5a3/gateway/gateway.env`：

```bash
S4A21_ADMIN_AUTH_KEY=...      # 对应 X-Auth-Key
S4A21_ADMIN_INTERNAL_KEY=...  # 对应 X-Internal-Key
```

> ★ `appsettings.*.json` 里的 `Admin.AuthKey` 可能是**空串**（被 EnvironmentFile 覆盖），
> 以 `gateway.env` 为准。

鉴权失败统一返回：

```json
HTTP/1.1 401 Unauthorized
{"ok":false,"message":"unauthorized"}
```

### 2.2 响应格式

- 成功：`200` + JSON，绝大多数带 `"ok": true`
- 业务失败：`4xx/5xx` + `{"ok":false,"message":"..."}`
- **下载接口不返回 JSON**，直接回二进制字节流

### 2.3 下载接口的共同约定

所有文件下载（PVF 增量、插件、登录器、DNF.exe）都满足：

| 特性 | 说明 |
|---|---|
| 方法 | `GET` |
| Range | 支持（`http.ServeFile`），断点续传可用 |
| 缓存 | `Cache-Control: no-store`（中间层留旧字节会造成「更新完还提示更新」） |
| 校验 | 一律以调用方给的 `sha256` 为唯一判据；服务端只负责给字节 |
| 相对 URL | 清单里给 `/api/...` 相对路径，客户端拼自己连的网关；换 CDN 只改服务端 |

### 2.4 下载限速（2026-11-16 起）

四条下载通道共用一套闸门，**不会因为并发下载打满上行而拖慢游戏**。

| 闸门 | 代码默认 | 环境变量 |
|---|---|---|
| 全局总出口 | 8 MB/s | `S5A3_DL_RATE_MBPS` |
| 单 IP | 2 MB/s | `S5A3_DL_PER_IP_MBPS` |
| 并发下载路数 | 8 | `S5A3_DL_CONCURRENCY` |
| 排队等待上限 | 45 s | `S5A3_DL_GATE_WAIT_SECONDS` |

#### ★★★ 默认值不是建议值，必须按服务器实际出口带宽重设

代码里的 `8 MB/s` 只是「别把千兆机打满」的兜底，**直接用在带宽小于 8MB/s 的机器上等于没有限速**。
部署到任何服务器前，先算出这台机器的出带宽，再按下面的比例配：

```
出口带宽(Mbps) ÷ 8 = 出口带宽(MB/s)
下载配额      ≈ 出口带宽 × 55%      （剩下 45% 留给游戏 / API / 心跳）
单 IP 配额    ≈ 下载配额 ÷ 2~4
并发路数      ≈ 4~8（带宽越小越少）
```

**已部署实例（2026-11-16）**

| 实例 | 出口带宽 | 下载配额 | 单 IP | 并发 | 配置位置 |
|---|---|---|---|---|---|
| 90CN 生产 | **14 Mbps（1.75 MB/s）** | `1 MB/s`（8 Mbps） | 2（实际受全局约束） | 4 | systemd drop-in `throttle.conf` |
| 测试 VM | 千兆内网 | 8 MB/s（默认） | 2 MB/s | 8 | 默认，未覆盖 |

90CN 的分配：`14 Mbps = 8 Mbps 下载 + 6 Mbps 游戏/API`。可用下载带宽只有 1.13 MB/s 余量，
84 MB 的增量包在独占时要 **84 秒/人**；多人并发会按比例更慢——这是 14 Mbps 的物理上限，调参解决不了。

#### 踩过的坑（2026-11-16）

把「带宽 14Mbps」误读成「上行 12MB/s」，按 8MB/s 配限速 ⇒ 8MB/s = 64Mbps，
是物理上限的 **4.5 倍**，限速形同虚设。表现是发版时监控一直贴 **13Mbps（93%）**，
游戏卡顿。改成 1MB/s 后监控稳定在 8~10Mbps。

★ 排查时先确认监控单位：云厂商「公网出带宽」通常按 **Mbps**，`13.039` 是 1.63MB/s，
不是 13MB/s。单位看错会得出完全相反的结论。

#### 已知限制

- `S5A3_DL_*_MBPS` 只解析**整数**。填 `0.5` 这类小数值会解析失败并**回落默认值 8**，
  比不配更危险。需要亚 MB/s 精度时，先改 `envInt` 为支持 KB/s（或用整数近似）。
- 限速只在**应用层**生效。同一台机器上的其他服务（GM 后台、鉴权代理、DB）不在此闸门内，
  它们的大流量仍会占满出口带宽。

#### 行为

- 名额满时请求**排队等待**，超过 45 s 才返回：
  ```json
  HTTP/1.1 503 Service Unavailable
  Retry-After: 10
  download busy, please retry later
  ```
- 一键回原行为：`S5A3_DL_RATE_MBPS=0`（同时关闭并发闸门）。
- 改完需要 `systemctl restart s5a3-gateway`。

#### 验证（部署后必做）

在服务器本机并发 12 路拉全量包，10 秒的总下载量就应等于设定值：

```bash
for i in $(seq 1 12); do
  curl -sk -o /dev/null -w '%{size_download}' --max-time 10 \
    https://127.0.0.1:8080/api/launcher/update/exe > /tmp/n$i.txt &
done; wait
awk '{s+=$1} END{printf "%.2f MB/s\n", s/10/1048576}' /tmp/n*.txt
# 1MB/s 配额 ⇒ 应输出 ~1.00；单路也会被压到 1MB/s
```

---

## 3. 玩家侧接口（8080，免鉴权）

### 3.1 `GET /api/health`

存活探针。返回 `{"ok":true,...}`，不含敏感信息。

### 3.2 `GET /api/launcher/policy`

登录器启动后第一请求：安全策略 + PVF 期望值 + 门禁开关 + 频道表。

| 参数 | 必填 | 说明 |
|---|---|---|
| `game` | 否 | 服务器 id（如 `s5a3`）。空 = 默认服。老登录器不带，行为不变 |
| `rev` | 否 | 本地缓存的 `fingerprint`；相同且未 `force` ⇒ `changed=false`，不下发大名单 |
| `force` | 否 | `1`/`true` = 强制全量下发 |

响应关键字段：

```json
{
  "ok": true,
  "changed": true,
  "fingerprint": "…",          // 黑白名单+PVF+驱动名单的合成摘要
  "revision": 12,
  "pvf": {
    "hash": "…", "algo": "sha256", "size": 74900000, "modified_utc": "…",
    "delta": {                 // 只有「上一版→当前版」增量存在时才出现
      "from_hash": "…", "to_hash": "…", "to_size": 74900000,
      "size": 219000, "url": "/api/launcher/pvf/delta", "algo": "block2048"
    }
  },
  "white_digest": "…", "black_digest": "…", "allowed_digest": "…", "driver_digest": "…",
  "white_count": 0, "black_count": 0, "allowed_count": 0, "driver_count": 0,
  "game": "s5a3", "game_found": true,
  "gates": { "policy": true, "pvf": true, "plugins": true,
             "integrity": true, "kernel": true, "dnfexe": false },
  "channels": { "…": "…" },
  "white": [], "black": [], "allowed": [], "driver": []
}
```

要点：

- `gates` 与 `channels` **恒返回**，不受 `changed` 短路影响（切服/改频道要立即生效）。
- `white/black/allowed/driver` 只在 `changed=true` 时全量下发。
- `pvf.delta` 缺失 ⇒ 客户端只能等整文件校验（本地 hash 不匹配就提示手动更新）。
- `gates.dnfexe` 控制「DNF.exe 哈希门禁」是否执行；老网关没有该键 ⇒ 客户端按 `true` 处理。

### 3.3 `GET /api/launcher/servers`

服清单（带签名）。响应字段见 `launcher_servers.go` 的 `buildServerListManifest`。
每项包含 `id / name / protocol / host / http_port / auth_port / tls / caps / min_launcher_version`。

`caps` 决定该服开哪些门禁（`policy/pvf/plugins/integrity/kernel/dnfexe`），
与 §3.2 的 `gates` 同源（`config.GateSwitchesFor`）。

### 3.4 `GET /api/launcher/pvf/delta`

PVF 增量包（A21D 格式）。

| 参数 | 必填 | 说明 |
|---|---|---|
| `from` | 否 | 客户端本地 PVF 的 sha256。**带上 = 按需增量**；不带 = 固定增量 `current.delta` |

- `200`：二进制增量包，响应头带 `X-Delta-From` / `X-Delta-To` / `X-Delta-To-Size`
- `404`：没有可用增量（没上传过 / 历史里没有该基线 / 包已过期）
  —— 客户端必须把 404 当「本次没增量」，**不能**当错误重试

### 3.5 `GET /api/launcher/plugins`

插件清单（内容寻址）。

```json
{
  "ok": true, "enabled": true, "degraded": false, "revision": "…",
  "plugins": [
    { "key": "AC-S5A3", "display_name": "反外挂", "is_core": true,
      "default_enabled": true, "config_kind": "None", "order": 10,
      "files": [ { "name": "AC-S5A3.dll", "sha256": "…", "url": "/api/launcher/plugins/file/AC-S5A3.dll" } ] }
  ]
}
```

- `enabled=false`：下发被关（一键回滚），登录器用内置插件、不下载
- `degraded=true`：清单不可信（`plugins.json` 缺失/条目非法/引用文件不存在）⇒ **客户端必须拒绝启动**
- `revision`：`plugins` 数组的 sha256，客户端用来判断"清单变没变"

### 3.6 `GET /api/launcher/plugins/file/{name}`

单个插件文件。

- `200` + `X-Content-SHA256: <sha256>`
- `404`：文件名不合法 / 不在清单 / 文件不存在
- 客户端**必须**校验 sha256 后落盘（内容寻址缓存按 sha 分目录）

### 3.7 `GET /api/launcher/update`

登录器自更新清单。

```json
{
  "ok": true, "enabled": true,
  "version": "2.7.3", "hash": "1A9D15C2…", "size": 136085741,
  "min_version": "2.7.2", "stored_utc": "2026-11-16T06:23:40.101Z",
  "full_url": "/api/launcher/update/exe",
  "delta_url": "/api/launcher/update/delta"
}
```

- 永远 `200`（除非服务端错误）：`enabled=false` / 无版本信息是**有效状态**
- `min_version` 是强更阈值：本地版本 < 它 ⇒ 不给跳过
- 客户端判据：**本地 exe 的 sha256 == hash** 才算最新，版本号只用于展示与强更

### 3.8 `GET /api/launcher/update/exe`

当前版全量 exe（约 130 MB）。`404` = 未启用/文件不存在。

### 3.9 `GET /api/launcher/update/delta?from=<本地hash>`

按需增量（A21D）。`from` 必填。

- `200` + `X-Delta-From` / `X-Delta-To` / `X-Delta-To-Size`
- `404` = 历史里没有该基线（客户端 exe 被改过 / 太老 / history 被清）⇒ 回退全量

### 3.10 `GET /api/dnfexe/update`

DNF.exe 更新清单，字段与 §3.7 同构：

```json
{ "ok": true, "enabled": true, "version": "…", "hash": "…", "size": 20000000,
  "min_version": "…", "full_url": "/api/dnfexe/update/exe",
  "delta_url": "/api/dnfexe/update/delta" }
```

### 3.11 `GET /api/dnfexe/update/exe`

DNF.exe 全量。支持 Range（客户端断点续传）。

### 3.12 `GET /api/dnfexe/update/delta?from=<本地hash>`

DNF.exe 按需增量。语义与 §3.9 完全一致。

### 3.13 其他只读接口

| 接口 | 用途 | 备注 |
|---|---|---|
| `GET /api/launcher/notice` | 更新公告 | 后台「客户端配置」维护 |
| `GET /api/launcher/online` | 在线人数 | 口径 = 「在游戏里」，只开登录器不算 |
| `GET /api/launcher/item-ranking` | 物品排行 | — |
| `GET /api/launcher/version` | 网关版本 | 兼容老登录器 |

### 3.14 `POST /api/heartbeat`

登录器心跳（60 s 一次）。会话超时由网关判定，停心跳 ⇒ 会话被清。

### 3.15 `POST /api/anticheat/report`

反外挂上报。

```json
{
  "reportToken": "…",
  "account": "…",
  "playerName": "…",
  "detections": [
    { "ruleName": "ModuleUnlisted", "description": "…",
      "actualValue": 0, "thresholdValue": 0, "timestamp": 0,
      "evidence": "…", "exempt": 0, "dedupId": "0" }
  ]
}
```

- `reportToken` 由登录器经**命名管道**下发（不落盘）
- `exempt=1` 表示命中时自研组件在场（只作区分，**照常入库**）
- 返回 `401` 表示 token 不符（网关无法归因）

### 3.16 `POST /api/account/helper`

玩家内辅（NF 系列）的服务端代理入口。请求体与鉴权见 `player_helper_proxy.go`；
令牌由登录器通过**环境变量**交给游戏进程，不落盘。

---

## 4. 管理侧接口（8443，`X-Auth-Key`）

> 本节只列与**发版/更新**相关的接口。GM 业务接口（账号/封禁/邮件/活动/拍卖行等）
> 见 `server.go` 的 `registerAdminRoutes`，不属于本文范围。

### 4.1 登录器自更新

| 接口 | 方法 | 参数 | 说明 |
|---|---|---|---|
| `/api/admin/launcher/versions` | GET | — | 当前版 + 历史表 |
| `/api/admin/launcher/upload` | POST | multipart：`file`、`version`、`name` | **唯一正确入口** |
| `/api/admin/launcher/rollback` | POST | JSON：`{"hash":"…"}` | 回退到历史版本 |

`upload` 做的事（缺一不可）：

1. 校验并落盘 `launcher_update/current.exe`
2. 复制一份到 `launcher_update/history/<HASH>.exe`
3. 追加 `history/index.json`（hash / version / size / name / stored_utc）
4. 触发 PeerSync 把新版本推给从网关（如果配了）

响应：

```json
{"ok":true,"version":"2.7.3","hash":"1A9D15C2…","size":136085741}
```

### 4.2 DNF.exe 更新

| 接口 | 方法 | 参数 |
|---|---|---|
| `/api/admin/dnfexe/versions` | GET | — |
| `/api/admin/dnfexe/upload` | POST | multipart：`file`、`version`、`name` |
| `/api/admin/dnfexe/rollback` | POST | JSON：`{"hash":"…"}` |

行为与 4.1 完全同构（current + history + index + PeerSync）。

### 4.3 PVF

| 接口 | 方法 | 参数 | 说明 |
|---|---|---|---|
| `/api/pvf/info` | GET | — | 当前 PVF hash/size/algo |
| `/api/admin/upload-pvf` | POST | multipart：`file`、`name` | 上传即替换，自动留 `.bak` 并重建增量 |
| `/api/admin/pvf/history` | GET | — | 历史版本表 |
| `/api/admin/pvf/rollback` | POST | JSON：`{"hash":"…"}` | 回退 |
| `/api/admin/pvf/register` | POST | JSON | 把已有文件登记为某版本（不重新上传） |
| `/api/admin/pvf/unregister` | POST | JSON | 移除某历史版本 |
| `/api/admin/refresh-pvf` | POST | — | 强制重算当前 PVF 摘要 |

`upload-pvf` 会在 `pvf_delta/` 下重建「上一版 → 当前版」增量；
`pvf_history/` 用于按需增量（`?from=`）。

### 4.4 插件

| 接口 | 方法 | 参数 | 说明 |
|---|---|---|---|
| `/api/admin/plugins` | GET | — | 清单 + 目录扫描结果 |
| `/api/admin/plugins/upload` | POST | multipart：`file`（文件名即插件名） | 只允许扁平文件名 |
| `/api/admin/plugins/delete` | POST | JSON：`{"name":"…"}` | — |
| `/api/admin/plugins/meta` | POST | JSON | 改显示名/说明/顺序/是否核心 |

### 4.5 完整性策略

| 接口 | 方法 | 参数 |
|---|---|---|
| `/api/admin/integrity` | GET | — |
| `/api/admin/integrity/upload` | POST | multipart：`file`（白名单/黑名单 JSON） |
| `/api/admin/integrity/add` | POST | JSON：条目 |
| `/api/admin/integrity/remove` | POST | JSON：条目 |
| `/api/admin/integrity/allow` | POST | JSON：放行模块 |
| `/api/admin/drivers` / `/upload` / `/remove` | GET/POST | 驱动白名单 |

### 4.6 运行时开关

| 接口 | 方法 | 用途 |
|---|---|---|
| `/api/admin/launcher-config` | GET/POST | 客户端配置（更新公告、最低版本、插件开关等） |
| `/api/admin/maintenance` | GET/POST | 维护模式 |
| `/api/admin/register-limit` | GET/POST | 注册限额 |
| `/api/admin/heartbeat` | GET/POST | 心跳超时（30~3600 s） |
| `/api/admin/game-ports` | GET/POST | 游戏端口表（频道开关） |
| `/api/admin/anticheat/detections` | GET | 反外挂检测记录 |
| `/api/admin/anticheat/players` | GET | 按账号聚合 |

---

## 5. 内部接口（18080，`X-Internal-Key`）

网关与 admin 进程之间的同步通道。**不对公网开放，也不给登录器用。**

| 接口 | 方法 | 方向 | 用途 |
|---|---|---|---|
| `/internal/online` | GET | admin→gw | 在线列表 |
| `/internal/kick` | POST | admin→gw | 踢人 |
| `/internal/pvf-info` | GET | admin→gw | 当前 PVF 元数据 |
| `/internal/refresh-pvf` | POST | admin→gw | 让网关重算 PVF 摘要 |
| `/internal/active-ports` / `apply-ports` | GET/POST | admin→gw | 端口表 |
| `/internal/runtime-config` | GET/POST | admin→gw | 运行时配置（维护模式等） |
| `/internal/launcher/sync` / `push` | GET/POST | gw↔gw | 登录器版本同步（主→从） |
| `/internal/dnfexe/sync` / `push` | GET/POST | gw↔gw | DNF.exe 版本同步 |
| `/internal/announce/*` | — | admin→gw | 公告队列 |
| `/internal/account/events` / `credential` | GET | admin→gw | 账号事件/凭据 |

---

## 6. 状态码与错误约定

| 码 | 场景 | 客户端应做什么 |
|---|---|---|
| `200` | 正常 | — |
| `401` | 管理 key 错误 / 反外挂 token 不符 | 不要重试（配置问题） |
| `404` | 增量包不存在 / 文件未上传 / 端点未启用 | 按语义分支：delta → 回退全量；清单 → 跳过 |
| `503` | 下载排队超时 | 等 `Retry-After` 后重试 |
| `5xx` | 服务端内部错误 | 有限重试 |

★ 客户端不要把 `404` 当故障：**「没有增量」是设计内的正常路径**。

---

## 7. 变更记录

| 日期 | 变更 |
|---|---|
| 2026-11-16 | 下载通道限速；新增 `S5A3_DL_*`。★ 代码默认 8MB/s 必须按服务器出口带宽重设（见 §2.4），90CN 生产实配 1MB/s |
| 2026-11-12 | 新增 `gates.dnfexe`（DNF.exe 哈希门禁） |
| 2026-10-25 | 新增 `/api/dnfexe/update*` 三件套 |
| 2026-10-01 | 新增 `/api/launcher/update*` 三件套（自更新 + 按需增量） |
| 2026-09-30 | 新增 `/api/launcher/pvf/delta`（PVF 增量 + 按需增量） |
