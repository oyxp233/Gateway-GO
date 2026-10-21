# S5A3 接入说明（网关 + 登录器）

本文说明 `feature/s5a3-standalone` 分支如何把 **S5A3（DNF90 / ServerS5A3）**
接进 S4A21 网关与登录器。改动全部是**新增分支**，S4A21 / S5A95 两条老链路
一个字节都没动。

---

## 1. 一句话架构

网关对 S5A3 只做三件事：**账号转发、端口 1:1 透传、组队 UDP 中继**。
下行帧**一个字节都不改写** —— 频道表里的 IP / 端口由服务端自己配成网关地址。

```
玩家客户端 ──TCP 8000──> 网关（登录 / 注册，账号转发给 S5A3 HTTP API）
           ──TCP 7001──> 网关 ──> S5A3 频道口（透传，不改写 CHANNELINFO）
           ──TCP 10006~10508──> 网关 ──> S5A3 游戏口（1:1 透传）
           ──UDP 30000~30063──> 网关 ──> S5A3 组队口（每客户端独立后端 socket）
```

## 2. 为什么 S5A3 不需要改写频道表

S4A21 / S5A95 的频道表把"后端自己看到的 IP"写在下行帧里，网关插在中间就必须
改写。S5A3 不是这样：

- 频道表在 `class0/op1 CHANNELINFO` 里下发，`serverIP` 字段直接取服务端的
  `DNFBRIDGE_SERVER_IP`，端口取服务端自己的频道表；
- 客户端**拿到什么就连什么**。

所以只要让 `DNFBRIDGE_SERVER_IP` 等于网关的对外地址，CHANNELINFO 里天然就是
网关地址，中间层没有任何需要改的字节。硬要解析并改写这个 protobuf，等于把
S5A3 的编码格式复制成第二份真源 —— 服务端一改编码，网关就静默改坏帧。

代码见 `pkg/proxy/adapter_s5a3.go`（`s5a3PassthroughAdapter`）。

## 3. 端口布局（同机部署）

| 端口 | 谁监听 | 说明 |
|---|---|---|
| 8000 / 8080 | 网关 `192.168.1.91` | 登录 TCP / 登录器 HTTP |
| 7001 | 网关 `192.168.1.91` → 后端 `127.0.0.1:7001` | 频道口，1:1 |
| 10006~10508（118 个，含空洞） | 网关 `192.168.1.91` → 后端 `127.0.0.1` 同名端口 | 游戏口，1:1 |
| 30000~30063 | 网关 `192.168.1.91` → 后端 `127.0.0.1` 同名端口 | 组队 UDP，1:1 |
| 17002 | 网关（仅内网调用） | S5A3 账号 API |
| 13306 | 仅本机工具（GM） | MariaDB 回环映射 |

**关键约束：网关和后端不能监听同一个 `host:port`。** 同机部署时把后端的
游戏口 / UDP 收回到回环上（`instance.json` 的 `game_host`），网关继续在
对外地址上占同名端口。

## 4. 部署步骤

### 4.1 S5A3 服务端侧

`runtime/docker/instance.json` 增加一行：

```json
"game_host": "127.0.0.1"
```

`host_ip`（= `DNFBRIDGE_SERVER_IP`）**保持网关的对外地址不变**。然后重新生成编排：

```bat
python deploy\docker\manage.py prepare
python deploy\docker\manage.py up
```

`game_host` 只影响 Docker 把游戏口 / UDP 发布到哪个宿主地址，不改
`DNFBRIDGE_SERVER_IP`，所以 CHANNELINFO 里仍然是玩家能连到的网关地址。

### 4.2 网关侧

用生成器产出配置（端口清单从 S5A3 自己的 compose 里读，别手抄）：

```bat
python deploy\s5a3\gen_s5a3_appsettings.py ^
    --s5a3-runtime E:\S5A3\ServerS5A3\runtime\docker ^
    --base appsettings.json ^
    --out appsettings.s5a3.json ^
    --public-ip 192.168.1.91
```

生成的配置里 `GameServers` 只有一项：

| 字段 | 值 | 为什么 |
|---|---|---|
| `Protocol` | `s5a3` | 选透传适配器 + 账号提供方 + 门禁全关 |
| `BackendHost` | `127.0.0.1` | 后端收在回环 |
| `ChannelListenerPort` | `7001` | 与后端同号（1:1） |
| `GamePorts` | 118 个离散端口 | 从 compose 抄，**不能改号** |
| `AccountApiUrl` | `http://127.0.0.1:17002` | S5A3 账号 API |
| `PartyUDPPorts` | 30000~30063 | 组队 UDP 中继 |
| `LaunchArgsFormat` | `99?{ip}?{port}?{initial_game_port}?{token}?...` | 第 5 段是服务端签发的 token |

启动：

```bat
gateway.exe -config appsettings.s5a3.json
```

日志里应能看到：

```
[Proxy] 多服代理已启动: s5a3(channel=7001, game=118 个端口)
[UDP] 服 s5a3 组队中继已启动: 64/64 个端口 → 127.0.0.1（1:1 透传，每客户端独立后端源端口）
```

### 4.3 登录器侧

```bat
build-s5a3.bat
```

产出 `dist\s5a3\SimpleLauncher_s5a3_<版本>.exe`，编译期钉死
`GatewayHost=192.168.1.91` / `TlsEnabled=false`。

## 5. 账号：为什么密码要分两条路

S5A3 的账号 API（`POST /api/account/register|login`）收**明文密码**，自己用
bcrypt 落库；S4A21 / S5A95 只认 `password_md5`。所以登录器必须**在发登录请求
之前**知道这一服用哪种口径。

链路是：

1. 登录器启动时拉 `GET /api/launcher/notice`（本来就要拉公告 + 多开上限）；
2. 该响应新增 `servers: [{id, name, protocol}]`，登录器缓存到 `ServerProtocols`；
3. 登录 / 注册时按 `protocol == "s5a3"` 决定填 `password` 还是 `password_md5`。

**为什么协议不放在本地配置**：`launcher-config.json` 落在游戏目录、玩家可写。
若让本地决定"这服是不是 s5a3"，玩家就能把 S4A21 服标成 s5a3 从而跳过整套门禁。
拉不到服清单时一律按"非 S5A3"处理 —— 宁可让 S5A3 玩家看到一条明确报错
（"该服要求登录器上报明文密码，请使用支持 S5A3 的登录器版本"），
也不把明文密码发给一个身份未确认的服。

## 6. 门禁：S5A3 全部跳过

`config.GateSwitchesFor` 是唯一判定点，登录响应与 `/api/launcher/policy` 共用：

| 服 | policy | pvf | plugins | integrity | kernel |
|---|---|---|---|---|---|
| s4a21 | ✅ | ✅ | ✅ | ✅ | ✅ |
| s5a95 | ✅ | ❌ | ❌ | ❌ | ❌ |
| s5a3 | ❌ | ❌ | ❌ | ❌ | ❌ |

S5A3 关掉 policy 的**连带效果**：登录器不再为了拿 gates 去拉策略。
原先"策略拉取失败 = 阻止启动"是个硬依赖，对一道门禁都不跑的服来说，
一次网络抖动就能把玩家挡在门外，而拉回来的白名单毫无用处。

为此 gates 改为**随登录响应下发**（`GatewayResponse.Gates`）：

- 新网关：登录响应带 `gates`，登录器直接执行，`policy=false` 时不再拉策略；
- 老网关：不带 `gates`，登录器按"全开"处理，行为与改造前逐字节一致（fail-closed）。

S5A3 关掉这些门禁不是"放水"：网关侧根本没有它的 PVF 登记、插件清单和
完整性白名单，开着只会拦人、拦不到真东西（客户端与 PVF 由服务端自己校验）。

## 7. 组队 UDP：可以做，代价是每客户端一个后端 socket

S5A3 的组队走 UDP 30000~30063，服务端是 **observed endpoint** 模型：按收到的
数据报的真实来源地址记住每个玩家的端点，再把队友的包转发过去。

**朴素做法是错的**：一个监听 socket 收所有人的包转给后端、后端回什么就转给
最后一个人 —— 这样服务端看到的永远是同一个 `(网关IP, 同一端口)`，所有队友被
折叠成一个端点，转发全乱。

所以中继为**每个客户端分配一个独立的后端 socket**（`DialUDP`，源端口随机）。
服务端看到 `(网关IP, 各自不同的端口)`，正好一对一；它回给某个端点的包落在
那个 socket 上，再转回对应客户端。语义与"玩家直连"完全等价。

细节（`pkg/proxy/udp_relay.go`）：

- 端口 **1:1 透传**，不做重映射 —— 重映射会破坏服务端下发给客户端的端点字段；
- 会话空闲 120s 回收（每 30s 扫一次），避免玩家掉线后一直占着后端源端口；
- 单个端口监听失败只记录并继续（部分可用好过全不可用）；
- `PartyUDPPorts` 留空 = 完全不启用，行为与改造前一致。

**已知边界**：UDP 端口表不支持热加载。改 `PartyUDPPorts` 需要重启网关 ——
换端口意味着服务端已注册的端点全部失效，热切只会让在线玩家静默失去组队。

## 8. 未做的部分

- **游戏口不做端口重映射**。S5A3 的频道表把端口写死在里面，重映射就必须改写
  下行帧，与本分支"零改写"的前提冲突。要跨网段重映射，得先接受"网关理解并
  改写 S5A3 频道表编码"这件事。
- **改密不支持**。S5A3 账号 API 只有 `register` / `login` / `status`，没有改密
  接口。网关显式拒绝并提示走服务端控制台，而不是让玩家撞到"账号不存在"。
- **S5A3 侧没有封禁 / 设备绑定 / QQ 绑定**。这些数据都在网关 SQLite 里，
  S5A3 账号在那边没有行。相关能力由服务端自己负责。
