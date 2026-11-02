#!/usr/bin/env python3
"""从 S5A3 实例生成网关的 appsettings.s5a3.json。

为什么要有这个脚本
==================
S5A3 的游戏端口**不是连续段**，而是由频道表（channel_info.etc）派生的
离散集合（实测 118 个，10006~10508 之间带大量空洞）。手抄 118 个端口
进 JSON 一定会错，而且服务端加一个频道就作废一次。

所以：端口清单只从 S5A3 自己生成的 compose.json 里读 —— 那是服务端
已经算好的权威结果，网关只是照抄。UDP 段同理（party_udp_relay_port_*）。

用法
====
    python deploy/s5a3/gen_s5a3_appsettings.py \
        --s5a3-runtime E:/S5A3/ServerS5A3/runtime/docker \
        --base appsettings.json \
        --out appsettings.s5a3.json \
        --public-ip 192.168.1.91

默认值是本机测试端的位置，通常可以不带参数直接跑。

生成结果里 Gateway.ListenAddress 会被改成 --public-ip：
网关必须在**玩家能连到的那个地址**上监听，而后端（S5A3 容器）在同一台
机器的 127.0.0.1 上监听同名端口 —— 这样两边不会抢端口，CHANNELINFO 里
服务端写出的 serverIP 也天然就是网关地址，中间层不需要改写任何字节。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_RUNTIME = Path("E:/S5A3/ServerS5A3/runtime/docker")
DEFAULT_BASE = Path("appsettings.json")

# 回环上发布但不属于游戏口的固定端口：频道引导 / 账号 API / 管理口 / 数据库。
NON_GAME_PORTS = {7001, 17002, 18111, 13306}

# S5A3 启动串第 4 段（首个游戏口）填 0：客户端从 CHANNELINFO 自己挑，
# 与 deploy/windows/local_client.py 的口径一致。
LAUNCH_ARGS = (
    "99?{ip}?{port}?{initial_game_port}?{token}?01?1?0?0?0?0?1?"
    "9n2b1c8r3w7y?0?0?19847"
)


def load_compose(runtime: Path) -> dict:
    path = runtime / "compose.json"
    if not path.exists():
        sys.exit(f"找不到 {path}：请先在该目录跑一次 manage.py prepare，让 S5A3 生成编排文件")
    return json.loads(path.read_text(encoding="utf-8"))


def parse_ports(compose: dict) -> tuple[list[int], list[int]]:
    """从 compose 的端口发布里拆出 (TCP 游戏口, UDP 组队口)。

    只认 "host:host/tcp" 这种 1:1 映射（S5A3 就是这么生成的），
    频道口 / 账号 API / 管理口是 "127.0.0.1:x:x"，按 127.0.0.1 前缀排除。
    """
    server = compose.get("services", {}).get("server", {})
    tcp_ports: list[int] = []
    udp_ports: list[int] = []

    for spec in server.get("ports") or []:
        text = str(spec)
        if "/udp" in text:
            # 形如 192.168.1.91:30000-30063:30000-30063/udp
            match = re.search(r":(\d+)-(\d+):(\d+)-(\d+)/udp$", text)
            if match:
                start, end = int(match.group(1)), int(match.group(2))
                udp_ports.extend(range(start, end + 1))
            continue
        # 形如 192.168.1.91:10006:10006/tcp
        match = re.search(r"^([\d.]+):(\d+):(\d+)/tcp$", text)
        if not match:
            continue
        host_ip, host_port, container_port = match.group(1), match.group(2), match.group(3)
        if host_ip.startswith("127.") and int(host_port) in NON_GAME_PORTS:
            # 频道口 / 账号 API / 管理口 / 数据库：固定这几个端口，按端口号排除。
            # 网关前置部署时游戏口本身也发布在回环上（game_host=127.0.0.1），
            # 不能按 IP 一律跳过，否则一个游戏口都解析不到。
            continue
        if host_port != container_port:
            sys.exit(f"端口映射不是 1:1（{text}）：S5A3 透传形态要求端口号一致")
        tcp_ports.append(int(host_port))

    tcp_ports = sorted(set(tcp_ports))
    udp_ports = sorted(set(udp_ports))
    if not tcp_ports:
        sys.exit("compose 里没有解析到任何游戏口，检查 server.ports 是否已生成")
    return tcp_ports, udp_ports


def load_database_env(runtime: Path) -> dict:
    """读 S5A3 的 database.env（MariaDB 库名 / 账号 / 密码）。

    这个文件由 S5A3 的 manage.py prepare 生成，是数据库凭据的唯一权威来源。
    网关要直连游戏库（全服邮件/泡点/注册奖励/角色查询），必须拿到同一份凭据。
    """
    path = runtime / "database.env"
    if not path.exists():
        return {}
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


def build_game_dsn(runtime: Path) -> str:
    """拼出网关直连 S5A3 游戏库的 DSN。

    ★ 用宿主机映射端口（instance.json 的 database_host_port，默认 13306），
      不是容器内网的 database_ip:3306 —— 网关跑在宿主上，进不去 docker 内网。

    ★ 账号是 dnf（不是 root）：只给它需要的业务库权限，比用 root 更安全。

    读不到凭据时返回空串：生成出来的配置里 GameDSN 为空，网关会明确报
    "未配置 S5A3 游戏库"，相关功能不工作但**不影响登录**。
    """
    instance_path = runtime / "instance.json"
    if not instance_path.exists():
        return ""
    instance = json.loads(instance_path.read_text(encoding="utf-8"))
    db_env = load_database_env(runtime)

    user = db_env.get("MARIADB_USER", "")
    password = db_env.get("MARIADB_PASSWORD", "")
    database = db_env.get("MARIADB_DATABASE", "dnf_local")
    port = instance.get("database_host_port", 13306)
    if not user or not password:
        return ""
    return (
        f"{user}:{password}@tcp(127.0.0.1:{port})/{database}"
        "?charset=utf8mb4&parseTime=true&loc=Local&timeout=10s"
    )


def build(base: dict, public_ip: str, tcp_ports: list[int], udp_ports: list[int], game_dsn: str = "") -> dict:
    cfg = json.loads(json.dumps(base))  # 深拷贝

    gateway = cfg.setdefault("Gateway", {})
    # 网关只绑对外地址：后端在同机 127.0.0.1 上占同名端口，两边不冲突。
    gateway["ListenAddress"] = public_ip

    # S5A3 游戏库（MariaDB）：全服邮件 / 泡点 / 注册奖励 / 角色查询都靠它。
    # 空 = 该部署没有 S5A3 后端，相关功能会明确报"未配置"。
    database = cfg.setdefault("Database", {})
    database["GameDSN"] = game_dsn
    database["GameTablePrefix"] = "dnf"
    database["GameAccountTable"] = "dnf90_web_accounts"
    # S4A21 的 SQLite 游戏库路径在 S5A3 部署里没有意义，清掉避免走错后端
    # （GameBackend() 是 SQLite 优先，留着 GamePath 会让 S5A3 分支永远不生效）。
    database["GamePath"] = ""

    # 老的单服段留着会被 NormalizeGameServers 当成默认服，清掉避免歧义。
    cfg.pop("GameServer", None)

    entry = {
        "Id": "s5a3",
        "Name": "S5A3",
        "Protocol": "s5a3",
        "Enabled": True,
        "PublicIP": public_ip,
        # 后端（S5A3 容器）发布在回环上；见 docs/S5A3_INTEGRATION.md
        "BackendHost": "127.0.0.1",
        "BackendChannelPort": 7001,
        # 1:1 透传：频道口与游戏口都跟后端同号，CHANNELINFO 不用改写
        "ChannelListenerPort": 7001,
        "GamePorts": tcp_ports,
        "GamePortMap": [],
        "LaunchArgsFormat": LAUNCH_ARGS,
        "InitialGamePort": 0,
        "AccountApiUrl": "http://127.0.0.1:17002",
        "AccountApiTimeoutSeconds": 8,
        "PartyUDPPorts": udp_ports,
        "MaxConnectionsPerIP": 8,
        "FirstReadTimeoutSeconds": 30,
        "IdleTimeoutSeconds": 1800,
        "BackendConnectTimeoutSeconds": 10,
        "TcpKeepAliveSeconds": 60,
    }
    cfg["GameServers"] = [entry]
    return cfg


def main() -> None:
    parser = argparse.ArgumentParser(description="生成网关的 S5A3 配置文件")
    parser.add_argument("--s5a3-runtime", type=Path, default=DEFAULT_RUNTIME,
                        help=f"S5A3 的 runtime/docker 目录（默认 {DEFAULT_RUNTIME}）")
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE,
                        help="以哪个 appsettings 为基底（默认 appsettings.json）")
    parser.add_argument("--out", type=Path, default=Path("appsettings.s5a3.json"))
    parser.add_argument("--public-ip", default=None,
                        help="网关对外 IP（默认取 S5A3 instance.json 的 host_ip）")
    args = parser.parse_args()

    if not args.base.exists():
        sys.exit(f"找不到基底配置 {args.base}")

    public_ip = args.public_ip
    if not public_ip:
        instance = args.s5a3_runtime / "instance.json"
        if not instance.exists():
            sys.exit("没给 --public-ip，且读不到 S5A3 的 instance.json")
        public_ip = json.loads(instance.read_text(encoding="utf-8"))["host_ip"]

    compose = load_compose(args.s5a3_runtime)
    tcp_ports, udp_ports = parse_ports(compose)
    game_dsn = build_game_dsn(args.s5a3_runtime)

    base = json.loads(args.base.read_text(encoding="utf-8-sig"))
    cfg = build(base, public_ip, tcp_ports, udp_ports, game_dsn)
    args.out.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"已生成 {args.out}")
    print(f"  对外地址   : {public_ip}")
    print(f"  游戏口     : {len(tcp_ports)} 个（{tcp_ports[0]}~{tcp_ports[-1]}，含空洞）")
    print(f"  组队 UDP   : {len(udp_ports)} 个" + (f"（{udp_ports[0]}~{udp_ports[-1]}）" if udp_ports else ""))
    print(f"  后端       : 127.0.0.1:7001（频道） / 127.0.0.1:17002（账号 API）")
    if game_dsn:
        # 不打印密码，只报库名和端口
        tail = game_dsn.split("@", 1)[-1]
        print(f"  S5A3 游戏库: {tail.split('?')[0]}（全服邮件/泡点/注册奖励可用）")
    else:
        print("  S5A3 游戏库: 未配置（读不到 database.env 的凭据）")
        print("               ⇒ 全服邮件/泡点/注册奖励/角色查询将不可用，登录不受影响")
    print()
    print("下一步：")
    print("  1) S5A3 的 instance.json 里加 \"game_host\": \"127.0.0.1\"，再跑 manage.py prepare")
    print("     （否则后端会占住对外地址的游戏口，网关绑不上）")
    print("  2) 用 appsettings.s5a3.json 启动网关")


if __name__ == "__main__":
    main()
