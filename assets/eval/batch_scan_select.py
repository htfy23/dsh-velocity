# -*- coding: utf-8 -*-
"""B1a 批量复盘·『已结束』判定定标 + 最近 20 个已结束会话选取（只读探针）。

问题：批量复盘需要"一批已结束的 DSH 任务"，但语料没有显式 session/end
（样本核验：正常会话末事件为 turn/end）。需要用全量数据定出一个可辩护
的『已结束』判定，并选出最近 20 个已结束会话供 B1b 提取证据。

方法（复用 blackhole.py 同源接口，零产品代码改动）：
- session_files() 枚举全部会话（同会话多格式已去重，mtime 降序）
- 每会话：read_events() → 末事件 type/time、截断警告；analyze() →
  status/步数/总耗时/holes 数
- 活跃判定：文件 mtime 距今 < ACTIVE_MIN 分钟视为可能仍在写入
  （防把本任务等活跃会话算进去；turn/end 之后会话仍可能继续新 turn）
- 时间戳单位自校准：用 mtime 与末事件 time 差的两种假设（ms vs s）
  取更合理者，校准结果落盘
- 『已结束』定标（b1a_endseed_check.py 实证后）：会话内 ≥1 次 turn/end
  且 age>=ACTIVE_MIN——session/end-seed(40)/job/settled(8) 等尾随事件
  全部出现在 turn/end 之后（合法结束标记），不能按"末事件==turn/end"
  误杀；唯一零 turn/end 的 1 个孤儿会话排除。
- 证据权重分类：A=末事件 turn/end（干净收尾）B=末事件为尾随元事件
  （session/end-seed 等，正常结束）C=无 turn/end（孤儿，排除）。
- 运行前后核验 lessons.jsonl 哈希（工作副本+正式），证明零写入
"""
import hashlib
import importlib.util
import json
import os
import sys
import time
from collections import Counter

WORK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPT_MOD = os.path.join(WORK, "blackhole.py")
OUT_JSON = os.path.join(WORK, "eval", "batch_scan_select.json")
ACTIVE_MIN = 30.0          # mtime 距今小于该值 → 可能仍活跃
SELECT_N = 20              # 用户规格：最近 20 个已结束会话
SUBST_DUR_S = 60.0         # "实质会话"下限：总耗时 ≥60s 且 ≥5 步
SUBST_STEPS = 5


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha16(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


def main():
    lessons_paths = {
        "work": os.path.join(WORK, "lessons.jsonl"),
        "official": os.path.join(os.path.expanduser("~"),
                                 ".dsh", "skills", "time-blackhole-audit", "lessons.jsonl"),
    }
    before = {k: sha16(p) for k, p in lessons_paths.items()}
    opt = load_module("bh_optimized", OPT_MOD)

    files = opt.session_files()
    now = time.time()
    sys.stderr.write("sessions=%d\n" % len(files))

    recs = []
    errors = []
    t0 = time.perf_counter()
    for path in files:
        sdir = os.path.dirname(path)
        sid = os.path.basename(sdir)
        ws = os.path.basename(os.path.dirname(sdir))
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        try:
            eb = opt.read_events(path)
            evs = eb
            last = evs[-1] if evs else None
            last_type = last.get("type") if isinstance(last, dict) else None
            last_time = last.get("time") if isinstance(last, dict) else None
            trunc = any(opt.TRUNCATION_WARNING in w for w in eb.warnings)
            n_warn = len(eb.warnings)
            n_te = sum(1 for e in evs
                       if isinstance(e, dict) and e.get("type") == "turn/end")
            rep = opt.analyze(evs)
            rws = rep.get("rows") or []
            recs.append({
                "ws": ws, "sid": sid,
                "mtime": mtime,
                "n_events": len(evs),
                "last_type": last_type,
                "last_time": last_time,
                "n_turn_end": n_te,
                "trunc": trunc, "n_warn": n_warn,
                "status": rep.get("status"),
                "n_steps": len(rws),
                "dur_s": round(sum(r["dur"] for r in rws), 1),
                "n_holes": len(rep.get("holes") or []),
                "size": os.path.getsize(path),
            })
        except Exception as exc:
            errors.append({"sid": sid, "ws": ws, "err": type(exc).__name__})
    elapsed = time.perf_counter() - t0

    # ---- 时间戳单位自校准（ms vs s，看哪种假设使 末事件<=mtime 且差值合理）
    def unit_score(unit):
        bad = 0
        for r in recs:
            if r["last_time"] is None:
                continue
            t = r["last_time"] if unit == "ms" else r["last_time"] * 1000.0
            if t > r["mtime"] * 1000.0 + 5000 or r["mtime"] * 1000.0 - t > 7 * 86400 * 1000.0:
                bad += 1
        return bad
    bad_ms, bad_s = unit_score("ms"), unit_score("s")
    ts_unit = "ms" if bad_ms <= bad_s else "s"

    for r in recs:
        r["age_min"] = round((now - r["mtime"]) / 60.0, 1)
        if r["last_time"] is not None:
            t = r["last_time"] if ts_unit == "ms" else r["last_time"] * 1000.0
            r["end_age_min"] = round((now * 1000.0 - t) / 60000.0, 1)
        else:
            r["end_age_min"] = None
        r["substantive"] = bool(r["dur_s"] >= SUBST_DUR_S and r["n_steps"] >= SUBST_STEPS)
        if r["n_turn_end"] >= 1:
            r["end_class"] = "A" if r["last_type"] == "turn/end" else "B"
        else:
            r["end_class"] = "C"

    active = [r for r in recs if r["age_min"] < ACTIVE_MIN]
    ended = [r for r in recs if r["age_min"] >= ACTIVE_MIN]
    finished = [r for r in ended if r["end_class"] in ("A", "B")]
    orphan = [r for r in recs if r["end_class"] == "C"]

    def brief(r):
        return {"ws": r["ws"], "sid": r["sid"], "age_min": r["age_min"],
                "end_age_min": r["end_age_min"], "n_steps": r["n_steps"],
                "dur_s": r["dur_s"], "status": r["status"],
                "n_holes": r["n_holes"], "trunc": r["trunc"],
                "substantive": r["substantive"]}

    # 主口径：已结束（≥1 turn/end 且不活跃）按 mtime 降序取 20；
    # B 类（尾随元事件）与截断会话带降权标记，不静默丢弃。
    # B5b 部署反馈修正：自动化/冒烟会持续产生微型会话（单次模型调用
    # 10-25s），纯新近度选取会被它们占满——DSH 实调实证最近 20 个已
    # 结束全为 0 证据组的 smoke 会话，真实工作会话被挤出，批量复盘永远
    # 空转。因此改为**实质会话优先**：最近的实质会话至多 20 个；不足
    # 时用剩余最近的非实质会话补齐（保持「最近 20 个已结束」规模，只是
    # 排序偏好；reason 仍如实标注实质/小样本）。substantive 定义不变
    # （dur_s≥60 且 n_steps≥5）。
    finished_sorted = sorted(finished, key=lambda r: r["mtime"], reverse=True)
    selected = ([r for r in finished_sorted if r["substantive"]]
                + [r for r in finished_sorted if not r["substantive"]])[:SELECT_N]
    backfill = []
    for r in selected:
        r["reason"] = (
            "已结束(%s类末事件=%s); age=%.1fh; %d步/%s; status=%s; holes=%d; %s%s" % (
                r["end_class"], r["last_type"], r["age_min"] / 60.0, r["n_steps"],
                ("%.1fmin" % (r["dur_s"] / 60.0)) if r["dur_s"] < 5400
                else ("%.2fh" % (r["dur_s"] / 3600.0)),
                r["status"], r["n_holes"],
                "实质会话" if r["substantive"] else "疑似小样本(smoke/短任务)",
                "; 数据截断,证据降权" if r["trunc"] else ""))

    # 备选：finished 全体按新近排在前 20 之外的近邻
    chosen = {r["sid"] for r in selected}
    near = sorted((r for r in finished if r["sid"] not in chosen),
                  key=lambda r: r["mtime"], reverse=True)[:15]

    def dist(rs, key):
        return dict(Counter(r[key] if r[key] is not None else "null" for r in rs))

    summary = {
        "n_sessions": len(files),
        "analyze_errors": errors,
        "ts_unit": ts_unit,
        "ts_unit_check": {"bad_under_ms": bad_ms, "bad_under_s": bad_s},
        "active_min_threshold": ACTIVE_MIN,
        "counts": {
            "active_maybe": len(active),
            "ended_all": len(ended),
            "finished_ge1_turn_end": len(finished),
            "orphan_no_turn_end": len(orphan),
            "end_class_dist": dict(Counter(r["end_class"] for r in recs)),
            "selected": len(selected),
            "selection_rule": "substantive_first_fill_trivial",
            "selected_by_class": dict(Counter(r["end_class"] for r in selected)),
            "selected_substantive": sum(1 for r in selected if r["substantive"]),
            "selected_trivial": sum(1 for r in selected if not r["substantive"]),
        },
        "last_type_dist_all": dist(recs, "last_type"),
        "last_type_dist_ended": dist(ended, "last_type"),
        "status_dist_ended": dist(ended, "status"),
        "workspace_dist": dict(Counter(r["ws"] for r in recs).most_common()),
        "active_sessions": [brief(r) for r in
                            sorted(active, key=lambda r: r["mtime"], reverse=True)],
        "selected_20": [{k: r[k] for k in
                         ("ws", "sid", "mtime", "age_min", "end_age_min", "last_type",
                          "end_class", "trunc", "status", "n_steps", "dur_s",
                          "n_holes", "substantive", "reason")} for r in selected],
        "near_miss_next15": [brief(r) for r in near],
        "elapsed_s": round(elapsed, 1),
        "lessons_before": before,
        "lessons_after": None,   # 运行末尾填
    }
    after = {k: sha16(p) for k, p in lessons_paths.items()}
    summary["lessons_after"] = after
    if before != after:
        sys.stderr.write("FATAL: lessons hash changed %r -> %r\n" % (before, after))
        sys.exit(3)

    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=1)
    out = {k: v for k, v in summary.items()
           if k not in ("selected_20", "near_miss_next15", "active_sessions",
                        "analyze_errors")}
    out["selected_20_brief"] = [
        "%s|%s|%s steps|%ss|%s|%s" % (r["ws"], r["sid"][:20], r["n_steps"],
                                      r["dur_s"], r["status"],
                                      "subst" if r["substantive"] else "trivial")
        for r in selected]
    print(json.dumps(out, ensure_ascii=False)[:3000])


if __name__ == "__main__":
    main()
