#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把登录器源码树里的插件文件同步到网关的 plugins/ 目录。

为什么需要它
------------
插件文件的**唯一真源**在登录器的 `S4A21Launcher-WPF/PluginResources/`
—— 那些文件同时被 `<EmbeddedResource>` 嵌进 exe，作为玩家首次冷启动时的
初始内容（理论上零下载，因为远端清单的 sha256 与内嵌的一致）。
网关这边只是**分发副本**。手工拷贝迟早会漏文件或带错版本，而"带错版本"
的表现是登录器 sha256 校验失败、全体拒绝启动。

★ 同步范围严格按 plugins.json 的引用走，**不做 *.dll 通配**
------------------------------------------------------------
`PluginResources/GameGaurd.ini` 是一个历史残留文件：csproj 并没有把它列进
`<EmbeddedResource>`，而且登录器每次运行都会**自己生成** GameGaurd.ini
（内容 = 按清单顺序的启用插件列表，见 PluginManager.WriteGameGaurdIni）。
用通配符同步会把它一起带进网关，一旦被写进 plugins.json 下发出去，
就会覆盖登录器生成的那份，插件加载顺序直接错乱。

用法
----
    python tools/sync_plugins.py              # 同步（覆盖同名文件）
    python tools/sync_plugins.py --dry-run    # 只看会做什么
    python tools/sync_plugins.py --prune      # 额外删除 plugins/ 里没被引用的文件
"""

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATEWAY_DIR = HERE.parent
DST = GATEWAY_DIR / "plugins"
LAUNCHER_RES = GATEWAY_DIR.parent / "S4A21Launcher-WPF" / "PluginResources"

META_NAME = "plugins.json"
FIELDS = ("dll", "ini", "xui")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_source(name: str):
    """在登录器资源目录里找文件。先找根目录，再递归（xui 在子目录里）。"""
    direct = LAUNCHER_RES / name
    if direct.is_file():
        return direct
    hits = sorted(p for p in LAUNCHER_RES.rglob(name) if p.is_file())
    return hits[0] if hits else None


def main() -> int:
    ap = argparse.ArgumentParser(description="同步登录器插件文件到网关 plugins/")
    ap.add_argument("--dry-run", action="store_true", help="只报告，不写文件")
    ap.add_argument("--prune", action="store_true",
                    help="删除 plugins/ 里未被 plugins.json 引用的文件（默认保留）")
    args = ap.parse_args()

    meta_path = DST / META_NAME
    if not meta_path.is_file():
        print(f"[ERR] 找不到元数据 {meta_path}", file=sys.stderr)
        return 2
    if not LAUNCHER_RES.is_dir():
        print(f"[ERR] 找不到登录器资源目录 {LAUNCHER_RES}", file=sys.stderr)
        return 2

    doc = json.loads(meta_path.read_text(encoding="utf-8"))
    entries = doc.get("plugins") or []
    if not entries:
        print(f"[ERR] {meta_path} 里没有任何插件条目", file=sys.stderr)
        return 2

    wanted = []      # (key, field, name, src)
    missing = []     # (key, field, name)
    for entry in entries:
        key = entry.get("key") or "?"
        for field in FIELDS:
            name = (entry.get(field) or "").strip()
            if not name:
                continue
            src = find_source(name)
            if src is None:
                missing.append((key, field, name))
            else:
                wanted.append((key, field, name, src))

    if not args.dry_run:
        DST.mkdir(parents=True, exist_ok=True)
    else:
        print("[dry-run] 不会写任何文件\n")

    copied, unchanged = [], []
    for key, field, name, src in wanted:
        dst = DST / name
        if dst.is_file() and sha256_of(dst) == sha256_of(src):
            unchanged.append(name)
            continue
        action = "覆盖" if dst.is_file() else "新增"
        print(f"  {action}  {name:24s} ({field:3s} of {key})  <- {src.relative_to(GATEWAY_DIR.parent)}")
        if not args.dry_run:
            shutil.copy2(src, dst)
        copied.append(name)

    pruned = []
    if args.prune:
        keep = {name for _, _, name, _ in wanted} | {META_NAME}
        for p in sorted(DST.iterdir()):
            if p.is_dir() or p.name in keep:
                continue
            print(f"  删除  {p.name}（未被 {META_NAME} 引用）")
            if not args.dry_run:
                p.unlink()
            pruned.append(p.name)

    print()
    print(f"清单条目 : {len(entries)} 个插件")
    print(f"应同步   : {len(wanted)} 个文件")
    print(f"已同步   : {len(copied)} 个" + (f"（{', '.join(copied)}）" if copied else "（全部已是最新）"))
    if pruned:
        print(f"已清理   : {len(pruned)} 个（{', '.join(pruned)}）")
    if missing:
        print(f"\n[ERR] 以下引用在登录器资源目录里找不到（plugins.json 写错或漏拷）:", file=sys.stderr)
        for key, field, name in missing:
            print(f"  {key}.{field} = {name}", file=sys.stderr)
        return 1

    if not copied and not pruned:
        print("\n没有需要改动的东西。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
