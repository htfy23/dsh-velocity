"""新对话 A/B 验证：提示词改动是否真的降低了浪费率。

背景（Round 41 实测）：
同等时间窗、同等活动量下，两个会话的浪费率差 18-37 倍：

    会话          近60分钟   近90分钟
    24fffc08       0.85%     0.57%     ← 加载了新提示词
    e63ad746      15.26%    21.09%     ← 未加载新提示词

这证明提示词改动确实生效——但前提是「新对话」。已有会话不会重读提示词。

用法：
    python verify_speedup.py                    # 对比最近两个活跃会话
    python verify_speedup.py --baseline e63ad746 --candidate 24fffc08
    python verify_speedup.py --minutes 60       # 指定时间窗

输出：两边的浪费率、加速倍数，以及「是否达标（>=1%）」的判定。
"""
import argparse
import importlib.util
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve().parent / "blackhole.py"
_spec = importlib.util.spec_from_file_location("blackhole_verify", SCRIPT)
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)


def waste_rate(session, minutes):
    """返回 (活动秒, 可回收秒, 浪费率%) 或 None。"""
    try:
        path = audit.find_session(session)
        if not path:
            return None
        rep = audit.analyze(audit.read_events(path), minutes)
    except Exception:
        return None
    if rep["status"] == "insufficient_data" or rep["active"] < 60:
        return None
    waste = sum(h.get("sev") or 0 for h in rep["holes"]
                if h["kind"] in audit.SPEED_KINDS)
    return rep["active"], waste, 100.0 * waste / max(1.0, rep["active"])


def active_sessions(limit=6):
    """最近写过的会话 id（按 mtime 降序）。"""
    import time
    files = audit.session_files()[:limit]
    now = time.time()
    out = []
    for f in files:
        try:
            age_min = (now - os.path.getmtime(f)) / 60
        except OSError:
            continue
        out.append((audit.rid_of(f), age_min))
    return out


def _out():
    """把 stdout/stderr 固定成 UTF-8。

    blackhole.py 一直这么做；这两个脚本原先没做，于是输出走控制台代码页
    （中文 Windows 上是 GBK 936）。插件侧按 UTF-8 解码，中文会变乱码，
    跨机器/跨代码页的调用也不稳定。
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def main():
    _out()
    ap = argparse.ArgumentParser(description="新对话 A/B：提示词改动是否降低了浪费率")
    ap.add_argument("--baseline", help="未加载新提示词的会话 id（旧对话）")
    ap.add_argument("--candidate", help="加载了新提示词的会话 id（新对话）")
    ap.add_argument("--minutes", type=float, default=60,
                    help="只看最近 N 分钟（默认 60）")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--list", action="store_true", help="列出最近活跃会话")
    a = ap.parse_args()

    if a.list:
        rows = [{"session": rid, "idle_min": round(age, 1)}
                for rid, age in active_sessions(12)]
        if a.json:
            import json
            print(json.dumps({"sessions": rows}, ensure_ascii=False, indent=2))
            return 0
        print("最近活跃会话（分钟前 / id）：")
        for r in rows:
            print("  %7.1f  %s" % (r["idle_min"], r["session"]))
        return 0

    base_id, cand_id = a.baseline, a.candidate
    if not (base_id and cand_id):
        sess = [rid for rid, age in active_sessions(8) if age < 24 * 60]
        if len(sess) < 2:
            print("可用会话不足，无法 A/B 对比。用 --list 查看。")
            return 2
        cand_id, base_id = (cand_id or sess[0]), (base_id or sess[1])

    b = waste_rate(base_id, a.minutes)
    c = waste_rate(cand_id, a.minutes)
    if not b or not c:
        print("数据不足：baseline=%s candidate=%s" % (bool(b), bool(c)))
        return 2

    doc = {
        "minutes": a.minutes,
        "baseline": {"session": base_id, "active_sec": b[0],
                     "waste_sec": b[1], "waste_pct": round(b[2], 2)},
        "candidate": {"session": cand_id, "active_sec": c[0],
                      "waste_sec": c[1], "waste_pct": round(c[2], 2)},
        "speedup_pct": round(b[2] - c[2], 2),
        "ratio": round(b[2] / c[2], 1) if c[2] > 0.01 else None,
        "meets_1pct": (b[2] - c[2]) >= 1.0,
    }

    if a.json:
        import json
        print(json.dumps(doc, ensure_ascii=False, indent=2))
        return 0

    print("=== 新对话 A/B（近 %.0f 分钟）===" % a.minutes)
    print("  基线（旧对话）%s" % base_id)
    print("    活动 %.2fh  可回收 %.1fmin  浪费率 %.2f%%" % (
        b[0] / 3600, b[1] / 60, b[2]))
    print("  候选（新对话）%s" % cand_id)
    print("    活动 %.2fh  可回收 %.1fmin  浪费率 %.2f%%" % (
        c[0] / 3600, c[1] / 60, c[2]))
    print()
    print("  浪费率下降: %.2f 个百分点" % doc["speedup_pct"])
    if doc["ratio"]:
        print("  相对加速:   %.1f 倍" % doc["ratio"])
    print("  达标(>=1%%): %s" % ("是" if doc["meets_1pct"] else "否"))
    if c[2] < 0.05:
        print("  注意：新对话浪费率已接近 0，进一步下降空间有限（分母效应）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
