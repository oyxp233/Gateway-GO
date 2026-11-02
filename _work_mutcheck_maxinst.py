# -*- coding: utf-8 -*-
"""MaxInstances 回退验证：把实现换回去，新断言必须变红。

两个变异点：
  M1  notice 响应去掉 max_instances      → TestLauncherNoticeIncludesMaxInstances 必须 FAIL
  M2  local backend 不透传 maxInstances  → TestLauncherRuntimeMaxInstances 必须 FAIL

自愈：finally 里从 .mutbak 还原；被 SIGTERM 打断也不会把源码留在变异状态
（上次 P1 验证脚本就被腰斩过，留下半棵回退树）。
"""
import io
import os
import shutil
import subprocess
import sys

ROOT = r"E:\DNF-Server\Gateway-GO"
GO = r"C:\Program Files\Go\bin\go.exe"
PY = sys.executable

FILES = {
    "notice": os.path.join(ROOT, "pkg", "httprouter", "launcher_online.go"),
    "backend": os.path.join(ROOT, "pkg", "httprouter", "backends.go"),
}

M1_OLD = '\t\t"max_instances": lz.MaxInstances,\n'
M2_OLD = '\tb.cfg.SetLauncherRuntime(minVersion, downloadURL, updateNotice, maxInstances)'
M2_NEW = '\tb.cfg.SetLauncherRuntime(minVersion, downloadURL, updateNotice, nil) // MUTATION: drop passthrough'

results = []


def run_test(name):
    env = dict(os.environ)
    env["PATH"] = r"C:\Program Files\Go\bin;" + env.get("PATH", "")
    env["GOPROXY"] = "https://goproxy.cn,direct"
    p = subprocess.run([GO, "test", "./pkg/httprouter/", "-run", name, "-count=1"],
                       cwd=ROOT, env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=300)
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out


def mutate(path, old, new):
    with io.open(path, encoding="utf-8") as f:
        text = f.read()
    if old not in text:
        raise SystemExit("变异锚点没找到: %s" % path)
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text.replace(old, new, 1))


def main():
    backups = {}
    try:
        for key, path in FILES.items():
            bak = path + ".mutbak"
            shutil.copy2(path, bak)
            backups[key] = (path, bak)

        # M1: notice 去掉 max_instances
        mutate(FILES["notice"], M1_OLD, "")
        rc, out = run_test("TestLauncherNoticeIncludesMaxInstances")
        ok = rc != 0
        results.append(("M1 notice 缺 max_instances", ok))
        print("[M1] exit=%d -> %s" % (rc, "RED(预期)" if ok else "GREEN(断言没有区分力!)"))
        shutil.move(backups["notice"][1], backups["notice"][0])
        backups.pop("notice")

        # M2: local backend 丢弃 maxInstances 入参
        mutate(FILES["backend"], M2_OLD, M2_NEW)
        rc, out = run_test("TestLauncherRuntimeMaxInstances")
        ok = rc != 0
        results.append(("M2 backend 不透传 maxInstances", ok))
        print("[M2] exit=%d -> %s" % (rc, "RED(预期)" if ok else "GREEN(断言没有区分力!)"))
        tail = [l for l in out.splitlines() if "FAIL" in l or "MaxInstances" in l or "max_instances" in l]
        for l in tail[:6]:
            print("    | " + l)
        shutil.move(backups["backend"][1], backups["backend"][0])
        backups.pop("backend")
    finally:
        # 自愈：任何异常/SIGTERM 都把变异还原
        for key, (path, bak) in list(backups.items()):
            if os.path.exists(bak):
                shutil.move(bak, path)
                print("[restore] %s" % os.path.basename(path))

    bad = [n for n, ok in results if not ok]
    print("RESULT=%s" % ("OK" if not bad else "PROBLEM: " + ";".join(bad)))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
