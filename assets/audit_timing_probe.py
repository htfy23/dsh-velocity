#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_timing_probe.py — 回溯验证「审计时机」的影响。

回答一个问题：如果 agent 在会话中途就跑审计，能否提前发现问题？

做法：把一个已结束会话按时间切成若干前缀（25% / 50% / 75%），
对每个前缀跑一次 analyze，看当时能检出哪些信号。信号在早期就出现，
说明「晚审计」确实是纯粹的损失。

只读：不写经验库、不改会话日志。用法：

    python audit_timing_probe.py --session <id|path> [--cuts 0.25,0.5,0.75]
    python audit_timing_probe.py --recent 5          # 批量看最近 5 个大会话
    python audit_timing_probe.py --recent 20 --json  # 机器可读
"""
import argparse
import importlib.util
import json
import os
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location("blackhole_probe", os.path.join(HERE, "blackhole.py"))
bh = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bh)


def prefix_at(events, fraction):
    """按时间比例截取事件前缀。

    用事件时间戳而不是事件下标：会话里常有长时间的等待间隔，
    按条数切会把「刚开会话」和「跑了很久」混在一起。
    """
    stamped = [e for e in events if isinstance(e.get("time"), (int, float))]
    if not stamped:
        return []
    times = sorted(e["time"] for e in stamped)
    t0, t1 = times[0], times[-1]
    if t1 <= t0:
        return list(events)
    cut = t0 + (t1 - t0) * fraction
    return [e for e in events if isinstance(e.get("time"), (int, float)) and e["time"] <= cut]


def probe_one(path, cuts):
    events = list(bh.read_events(path))
    out = {"session": bh.rid_of(path), "cuts": []}
    for frac in cuts:
        prefix = prefix_at(events, frac)
        try:
            rep = bh.analyze(prefix)
        except Exception as exc:          # 单点失败不影响整份报告
            out["cuts"].append({"at": frac, "error": str(exc)})
            continue
        out["cuts"].append({
            "at": frac,
            "status": rep["status"],
            "calls": rep["calls"],
            "steps": len(rep["rows"]),
            "holes": [h["kind"] for h in rep["holes"]],
        })
    full = bh.analyze(events)
    out["full"] = {
        "calls": full["calls"],
        "holes": [h["kind"] for h in full["holes"]],
    }
    return out


def summarize(rec):
    """早期已出现的信号数 / 全量信号数 —— 衡量「提前量」。"""
    full = set(rec["full"]["holes"])
    if not full:
        return None
    results = [c for c in rec["cuts"] if "holes" in c]
    if not results:
        return None
    first = results[0]                      # 最早那个切点
    early = set(first["holes"]) & full
    return {
        "at": first["at"],
        "early": len(early),
        "total": len(full),
        "ratio": len(early) / len(full),
        "missed": sorted(full - early),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="回溯验证审计时机的影响（只读）")
    ap.add_argument("--session", default=None, help="会话 id 或日志路径")
    ap.add_argument("--recent", type=int, default=0, help="批量分析最近 N 个会话")
    ap.add_argument("--min-calls", type=int, default=200,
                    help="--recent 时只保留调用数 ≥ 此值的会话（大会话才有意义）")
    ap.add_argument("--cuts", default="0.25,0.5,0.75", help="切点比例，逗号分隔")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    cuts = [float(x) for x in a.cuts.split(",") if x.strip()]

    if a.recent:
        files = bh.session_files()[:max(a.recent, 1)]
        paths = []
        for f in files:
            try:
                rep = bh.analyze(bh.read_events(f))
            except Exception:
                continue
            if rep["calls"] >= a.min_calls:
                paths.append(f)
    else:
        one = bh.find_session(a.session)
        if not one:
            sys.stderr.write("[!] 找不到会话；核对 --session 或 DSH_SESSION_ID\n")
            return 2
        paths = [one]

    if not paths:
        sys.stderr.write("[!] 没有符合条件的会话（可用 --min-calls 放宽）\n")
        return 2

    records = [probe_one(p, cuts) for p in paths]
    if a.json:
        print(json.dumps(records, ensure_ascii=False, indent=2))
        return 0

    gain_total = 0
    for rec in records:
        print("=" * 66)
        print(rec["session"])
        for c in rec["cuts"]:
            if "error" in c:
                print("  %.0f%%  分析失败: %s" % (c["at"] * 100, c["error"]))
                continue
            print("  %.0f%%  calls=%-5d steps=%-5d %-8s %s" % (
                c["at"] * 100, c["calls"], c["steps"], c["status"],
                ", ".join(c["holes"]) or "（无信号）"))
        print("  终局  calls=%-5d %s" % (
            rec["full"]["calls"], ", ".join(rec["full"]["holes"]) or "（无信号）"))
        s = summarize(rec)
        if s:
            gain_total += 1
            print("  → 最早 %.0f%% 处已能检出 %d/%d 个信号（%.0f%%）" % (
                s["at"] * 100, s["early"], s["total"], s["ratio"] * 100))
            if s["missed"]:
                print("     当时还未出现: %s" % ", ".join(s["missed"]))
    print()
    print("可提前检出信号的大会话: %d / %d" % (gain_total, len(records)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
