"""创建 GitHub Release 并上传 tarball。

用 git credential 拿到的 token 走 API。token 从环境变量读，不写进文件。
"""
import json
import os
import sys
import urllib.request

OWNER = "htfy23"
REPO = "dsh-velocity"
TAG = "v1.0.0"
ASSET_NAME = "dsh-velocity.tgz"      # 不带版本号：latest/download 只解析 latest，文件名照字面取
TOKEN = os.environ.get("GITHUB_TOKEN", "")

API = "https://api.github.com"


def call(method, path, data=None, raw=None, content_type="application/json"):
    url = API + path
    body = raw if raw is not None else (
        json.dumps(data).encode("utf-8") if data is not None else None)
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "dsh-velocity-release")
    if body is not None:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req) as r:
            payload = r.read()
            return r.status, (json.loads(payload) if payload else None)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        return e.code, {"error": detail[:500]}


def main():
    if not TOKEN:
        print("GITHUB_TOKEN 未设置")
        return 2

    # 1) 建 Release（已存在则复用）
    status, doc = call("POST", "/repos/%s/%s/releases" % (OWNER, REPO), {
        "tag_name": TAG,
        "name": "dsh-velocity 1.0.0",
        "body": (
            "First public release.\n\n"
            "- **12 session signals**: four speed signals whose durations add up to "
            "net savings (`起后台即阻塞等`, `盲等`, `命令可合并`, `超时转后台`), plus eight "
            "correctness signals\n"
            "- **4 tools**: `blackhole_audit`, `blackhole_lessons`, "
            "`blackhole_batch_review`, `velocity_speedup` (new-vs-old conversation A/B)\n"
            "- **Verified-lesson library** with record → recommend → adopt → verify\n"
            "- **Resident context ≈3750 tokens**, paid per turn; the plugin trades fewer "
            "turns for time, not more context\n\n"
            "Install with the tarball asset below (skips the build-from-source step)."
        ),
        "draft": False,
        "prerelease": False,
    })
    if status not in (200, 201):
        # 422 = 该 tag 已有 release
        if status == 422:
            print("Release 已存在，尝试复用")
            status, doc = call("GET", "/repos/%s/%s/releases/tags/%s" % (OWNER, REPO, TAG))
        if status not in (200, 201):
            print("建 Release 失败:", status, doc)
            return 1
    release_id = doc["id"]
    upload_url = doc["upload_url"].split("{")[0]
    print("Release id=%s" % release_id)

    # 2) 删掉同名旧资产（重复上传会 422）
    status, assets = call("GET", "/repos/%s/%s/releases/%s/assets" % (OWNER, REPO, release_id))
    if status == 200:
        for a in assets:
            if a["name"] == ASSET_NAME:
                call("DELETE", "/repos/%s/%s/releases/assets/%s" % (OWNER, REPO, a["id"]))
                print("删除旧资产 %s" % ASSET_NAME)

    # 3) 上传 tarball
    with open(ASSET_NAME, "rb") as f:
        blob = f.read()
    req = urllib.request.Request(
        upload_url + "?name=" + ASSET_NAME, data=blob, method="POST")
    req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("Content-Type", "application/gzip")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "dsh-velocity-release")
    try:
        with urllib.request.urlopen(req) as r:
            up = json.loads(r.read())
            print("上传成功: %s (%d bytes)" % (up["name"], up["size"]))
            print("下载地址:", up["browser_download_url"])
    except urllib.error.HTTPError as e:
        print("上传失败:", e.code, e.read().decode("utf-8", "replace")[:400])
        return 1

    print("\nRelease 页面: https://github.com/%s/%s/releases/tag/%s" % (OWNER, REPO, TAG))
    return 0


if __name__ == "__main__":
    sys.exit(main())
