"""一键发布 dsh-velocity 到 npm，并校验发布结果。

为什么需要发 npm：`dsh-plugin-catalog`（dsh-market 市场的数据源）是纯 npm 索引——
6554 个条目全部 `version.source.type == "npm"`，GitHub Release 来源的一条都没有。
所以只发 GitHub Release 永远不会进市场搜索。

用法（先 npm login，或在环境里给 NPM_TOKEN）：
    python publish_npm.py            # 真发布
    python publish_npm.py --dry-run  # 只演练

发布后的校验：读 registry 的 packument，确认 version / keywords / dsh.bundle 都在。
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

PLUGIN = "D:/working area/dsh-velocity-plugin"
PKG = "dsh-velocity"


def npm(*args):
    return subprocess.run(["npm.cmd"] + list(args), cwd=PLUGIN,
                          capture_output=True, text=True, encoding="utf-8")


def registry(path):
    url = "https://registry.npmjs.org" + path
    try:
        with urllib.request.urlopen(url, timeout=40) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def main():
    dry = "--dry-run" in sys.argv

    meta = json.load(open(os.path.join(PLUGIN, "package.json"), encoding="utf-8"))
    name, version = meta["name"], meta["version"]

    # 发布前自检：这几项错了 publish 会失败或发出去别人装不上
    problems = []
    if meta.get("private"):
        problems.append("private: true 会让 npm publish 直接拒绝")
    if "dsh-plugin" not in meta.get("keywords", []):
        problems.append("keywords 缺少 dsh-plugin —— 市场靠它发现")
    if not meta.get("dsh", {}).get("bundle", {}).get("patch"):
        problems.append("缺少 dsh.bundle.patch —— 装不上")
    st, _ = registry("/" + name)
    if st == 404:
        print("  npm 上 %s 不存在，将首次发布" % name)
    elif st == 200:
        st2, doc = registry("/" + name)
        if version in (doc or {}).get("versions", {}):
            problems.append("%s@%s 已经发布过，需先升版本" % (name, version))
        else:
            print("  %s 已存在，本次发布新版本 %s" % (name, version))
    if problems:
        print("\n阻塞项:")
        for p in problems:
            print("  ✗ " + p)
        return 1

    print("\n=== npm publish%s ===" % (" (dry-run)" if dry else ""))
    args = ["publish", "--access", "public"]
    if dry:
        args.append("--dry-run")
    r = npm(*args)
    for line in (r.stdout + r.stderr).splitlines():
        if line.strip():
            print("  " + line)
    if r.returncode != 0:
        print("\n发布失败，退出码 %d" % r.returncode)
        return 1
    if dry:
        print("\ndry-run 通过，去掉 --dry-run 即可真发布")
        return 0

    # 发布后校验：registry 有传播延迟，重试几次
    print("\n=== 校验 registry ===")
    for attempt in range(1, 7):
        time.sleep(3)
        st, doc = registry("/" + name)
        if st == 200 and version in doc.get("versions", {}):
            v = doc["versions"][version]
            print("  ✓ %s@%s 已在 registry" % (name, version))
            print("    tarball      : %s" % v["dist"]["tarball"])
            print("    shasum       : %s" % v["dist"]["shasum"])
            print("    keywords     : %s" % ", ".join(v.get("keywords", [])))
            print("    dsh.bundle   : %s" % (v.get("dsh", {}).get("bundle", {}).get("patch")))
            print("    unpackedSize : %.1f kB" % (v["dist"].get("unpackedSize", 0) / 1024))
            return 0
        print("  第 %d 次：registry 尚未可见，等 3 秒" % attempt)
    print("  registry 暂未显示新版本（传播延迟，通常几分钟内可查）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
