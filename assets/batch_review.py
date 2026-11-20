# -*- coding: utf-8 -*-
"""批量复盘·证据提取器（B1b）。

对 eval/batch_scan_select.json 选中的最近 20 个已结束 DSH 会话，提取
四类耗时集中片段（用户规格：把有用的长计算、等待、反复失败和重复检查
分开），产出脱敏证据组 JSON（eval/batch_evidence.json），供 B1c 跨会话
聚合与 B2 模型归因消费。

设计口径（与 blackhole.py 同源，禁止旁路）：
- 会话枚举/读取/解析：session_files() / read_events() / build()
- 逐步耗时：analyze()（rows 的 tool/poll 已是 interval_seconds 区间并集）
- 单调用区间：tool_interval(call, result, SegIndex, horizon=0)——继承
  CROSS_MS 跨段伪影剔除；片段耗时用区间并集汇总，并行重叠不重复计
- 错误模板归一：norm_err_text()（纯路径轴，v8 口径）作为跨会话合并键
- 重复调用判定：与 analyze() 重复指纹规则同语义（≥3 步或单步 ≥3 次、
  输出各不相同则不算、POLL_LIKE 归等待、hot edit 文件归反复编辑）

四类核心片段 + 两个补充片段（产品已有 hole kind，映射到 KNOWN_KINDS，
标注 extra=true）：
- long_compute  长计算：单次非 poll 调用 tool 区间 ≥ LONG_CALL_S；
  跑满超时（"still running after"）≥ TIMEOUT_CALL_S 即提取并打 timeout 标
- wait          等待：会话级 poll 聚集（与产品「任务轮询」同阈值）；
  单次 poll 调用区间 ≥ LONG_CALL_S 也单独成片段（single_poll）
- repeated_failure 反复失败：norm_err_text 同模板错误 ≥ ERR_GROUP_MIN 次
- repeated_check   重复检查：重复指纹组（同参同果 ≥3）
- extra: no_output_span 无产出长段（≥6 步连续零写入且 ≥300s，含探索守卫）。
  注意与产品规则的文档差异：analyze() 只报 span 最大的一段（best）且仅对
  best 做守卫判断；本提取器为证据完整性提取所有合格段、逐段做守卫——
  因此会出现"产品 status=ok 但本提取器有片段"（如最大段被守卫跳过、
  次大段不属探索形态）。这是有意为之，不是口径 bug（轮次4 教训）。
- extra: repeated_edit  反复编辑同处（同 old_string 补丁式改动）

脱敏（Sanitizer）：显示文本用会话内稳定编号占位符（PATH1/URL2/HEX1/USER1
——同一原值→同一占位符，保留「同文件反复出现」的证据价值，映射不落盘）；
斜杠 token 仅在含反斜杠/类 unix 前缀/末段带扩展名时才算 PATH（纯 "3/10"
"and/or" 保留，避免破坏失败循环 evidence 可读性）。合并键不编号
（norm_key 只做 ≥16 位十六进制 → HEX 的确定性折叠，跨会话、跨运行稳定）。
指纹 fp 本就是 sha256，可直接作为合并键。

防误伤（「正常长任务不出现在证据里」）：阈值保守 + 冒烟/健康会话零片段
断言（本批 non-substantive 会话 groups 必须为 0）；片段本身只陈述「耗时
集中在这里」，不替模型下低效结论（必要/可避免由 B2 归因）。

零写入断言：运行前后核验 lessons.jsonl 哈希（工作副本+正式两份），
任何变化立即 FATAL——本提取器只读。
"""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict

WORK = os.path.dirname(os.path.abspath(__file__))
OPT_MOD = os.path.join(WORK, "blackhole.py")
SELECT_JSON = os.path.join(WORK, "eval", "batch_scan_select.json")
OUT_JSON = os.path.join(WORK, "eval", "batch_evidence.json")

# ---- 阈值（保守；与产品规则对齐的注明出处）
LONG_CALL_S = 120.0        # 单次非 poll 调用提取阈值
TIMEOUT_CALL_S = 60.0      # 跑满超时的调用不论长短都提取（超时=信号）
ERR_GROUP_MIN = 2          # 同模板错误最少出现次数（跨会话聚合在 B1c）
WAIT_TOTAL_S = 120.0       # 会话级等待聚集阈值 = 产品「任务轮询」poll_total
WAIT_MIN_N = 3             # = 产品「任务轮询」poll_n
NOPROD_MIN_STEPS = 6       # = 产品「无产出长段」
NOPROD_MIN_S = 300.0
EDIT_HOT_MIN = 5           # = 产品「反复编辑同处」

_CORE_TYPES = ("long_compute", "wait", "repeated_failure", "repeated_check")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha16(path):
    """缺文件的哈希=稳定哨兵 'no-file'（插件兜底/沙箱部署时脚本目录可能
    尚无 lessons.jsonl；before==after 比较语义不变：出现/消失都算变化）。"""
    if not os.path.exists(path):
        return "no-file"
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


# ---------------------------------------------------------------- sanitizer

_URL_RE = re.compile(r"https?://\S+")
_WINPATH_RE = re.compile(r"[A-Za-z]:[\\/][^\s'\"<>]*")
_ANYSLASH_RE = re.compile(r"[^\s'\"<>]*[\\/][^\s'\"<>]*")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# 显示层斜杠 token 算路径的资格：含反斜杠、类 unix 前缀、或末段带扩展名。
# 纯 "a/b"（and/or、3/10 等分数与普通词组）不算——过度脱敏会破坏
# 失败循环 evidence（"失败步 3/10"）这类证据的可读性，伤 B2 归因。
# 注意：这只约束**显示**；聚合键 norm_err_text 仍用产品的激进口径。
_SLASHY_RE = re.compile(r"\.[A-Za-z0-9]{1,8}$")


class Sanitizer(object):
    """显示文本脱敏：同一原值 → 同一编号占位符（会话级稳定，映射不落盘）。

    - USER1：本机用户名（含路径中出现的形式）
    - URL<n> / PATH<n> / HEX<n> / MAIL<n>：按出现顺序编号
    - collapse_hex(s)：合并键用——不做编号，≥16 位十六进制统一折叠为
      HEX，跨会话/跨运行确定性一致
    """

    def __init__(self, usernames=()):
        self._users = [u for u in usernames if u]
        self._maps = {k: {} for k in ("USER", "URL", "PATH", "HEX", "MAIL")}

    def _slot(self, cat, raw):
        m = self._maps[cat]
        if raw not in m:
            m[raw] = "%s%d" % (cat, len(m) + 1)
        return m[raw]

    def _usersub(self, s):
        for u in self._users:
            s = s.replace(u, self._slot("USER", u))
        return s

    def _slash_repl(self, m):
        tok = m.group(0)
        if ("\\" in tok or tok.startswith(("./", "../", "/", "~/"))
                or _SLASHY_RE.search(tok)):
            return self._slot("PATH", tok)
        return tok

    def text(self, s):
        """脱敏一段显示文本。"""
        if not s:
            return ""
        s = self._usersub(str(s))
        s = _URL_RE.sub(lambda m: self._slot("URL", m.group(0)), s)
        s = _WINPATH_RE.sub(lambda m: self._slot("PATH", m.group(0)), s)
        s = _ANYSLASH_RE.sub(self._slash_repl, s)
        s = _HEX_RE.sub(lambda m: self._slot("HEX", m.group(0)), s)
        s = _EMAIL_RE.sub(lambda m: self._slot("MAIL", m.group(0)), s)
        return s

    @staticmethod
    def collapse_hex(s):
        """合并键专用：不编号的确定性折叠（十六进制 token → HEX）。"""
        return _HEX_RE.sub("HEX", str(s))


# ---------------------------------------------------------------- extraction

def _call_interval(opt, c, r, idx):
    iv = opt.tool_interval(c, r, idx, 0)
    if iv is None:
        return None
    return (iv[0], iv[1], (iv[1] - iv[0]) / 1000.0)


def _frag(session, typ, **kw):
    g = {"session": session, "type": typ, "extra": typ not in _CORE_TYPES}
    g.update(kw)
    return g


def _union_s(intervals):
    """区间并集秒数（毫秒入参），并行重叠不重复计。"""
    return opt_mod.interval_seconds([(a, b) for a, b, *_ in intervals]) if intervals else 0.0


opt_mod = None   # main() 里装载


def extract_session(opt, path, sid):
    """单会话证据提取。返回 (groups, session_summary)。"""
    san = Sanitizer(usernames=(os.environ.get("USERNAME") or "",
                               os.path.expanduser("~").replace("\\", "/").split("/")[-1]))
    evs = opt.read_events(path)
    rep = opt.analyze(evs)
    all_calls, all_results, _steps, missing = opt.build(evs)
    idx = opt.SegIndex(opt.segments(evs))

    groups = []
    frag_intervals = defaultdict(list)   # type -> [(a,b,dur_s)] 供并集统计

    # ---- 1) long_compute：单次非 poll 调用 tool 区间超阈
    for cid, c in all_calls.items():
        if not isinstance(c.get("time"), (int, float)):
            continue
        r = all_results.get(cid)
        if r is None or c["name"] in opt.POLL_LIKE:
            continue
        iv = _call_interval(opt, c, r, idx)
        if iv is None:
            continue
        a, b, d = iv
        timeout = "still running after" in r["text"]
        if d < LONG_CALL_S and not (timeout and d >= TIMEOUT_CALL_S):
            continue
        groups.append(_frag(sid, "long_compute",
                            turn=c.get("turn"), step=c.get("step"),
                            tool=c["name"], tool_s=round(d, 1),
                            timeout=timeout, error=bool(r["error"]),
                            out_chars=len(r["text"]),
                            args=san.text(opt.brief_args(c, 200)),
                            result=san.text(r["text"][:400])))
        frag_intervals["long_compute"].append((a, b, d))

    # ---- 2) wait：会话级 poll 聚集（产品「任务轮询」同阈值）+ 单次长 poll
    poll_rows = [r for r in rep["rows"] if r["polls"] > 0]
    if rep["polls"] > WAIT_TOTAL_S and rep["polls"] and rep["poll_n"] >= WAIT_MIN_N:
        top = sorted(poll_rows, key=lambda r: -r["poll_sec"])[:5]
        poll_calls = sorted(
            ((iv, c) for c in all_calls.values()
             if c["name"] in opt.POLL_LIKE and c["name"] and c.get("time") is not None
             and all_results.get(c["id"]) is not None
             and (iv := _call_interval(opt, c, all_results[c["id"]], idx)) is not None),
            key=lambda x: -x[0][2])[:3]
        groups.append(_frag(sid, "wait",
                            poll_total_s=round(rep["polls"], 1),
                            poll_n=rep["poll_n"],
                            top_steps=["T%s.S%s(%ss)" % (r["turn"], r["step"], round(r["poll_sec"]))
                                       for r in top],
                            sample_args=[san.text(opt.brief_args(c, 120)) for _iv, c in poll_calls],
                            tools=sorted(opt.POLL_LIKE)))
        for iv, _c in poll_calls:
            frag_intervals["wait"].append(iv)

    for c in all_calls.values():
        if c["name"] not in opt.POLL_LIKE or not isinstance(c.get("time"), (int, float)):
            continue
        r = all_results.get(c["id"])
        if r is None:
            continue
        iv = _call_interval(opt, c, r, idx)
        if iv is None or iv[2] < LONG_CALL_S:
            continue
        groups.append(_frag(sid, "wait", kind="single_poll",
                            turn=c.get("turn"), step=c.get("step"),
                            tool=c["name"], tool_s=round(iv[2], 1),
                            args=san.text(opt.brief_args(c, 150)),
                            result=san.text(r["text"][:300])))
        frag_intervals["wait"].append(iv[:2] + (iv[2],))

    # ---- 3) repeated_failure：同模板错误（norm_err_text 纯路径轴）
    err_groups = defaultdict(list)
    for c in all_calls.values():
        r = all_results.get(c["id"])
        if r and r["error"] and r["text"]:
            key = opt.norm_err_text(r["text"])
            if key:
                err_groups[key].append((c, r))
    for key, items in err_groups.items():
        if len(items) < ERR_GROUP_MIN:
            continue
        ivs = [iv for iv in (_call_interval(opt, c, r, idx) for c, r in items) if iv]
        groups.append(_frag(sid, "repeated_failure",
                            n=len(items),
                            tools=sorted({c["name"] for c, _r in items}),
                            steps=["T%s.S%s" % (c.get("turn"), c.get("step")) for c, _r in items[:8]],
                            sample_args=[san.text(opt.brief_args(c, 150)) for c, _r in items[:3]],
                            sample_err=[san.text(r["text"][:250]) for _c, r in items[:3]],
                            norm_key=Sanitizer.collapse_hex(key)[:300],
                            union_s=round(_union_s(ivs), 1)))
        frag_intervals["repeated_failure"].extend(ivs)

    # ---- 4) repeated_check：重复指纹（产品同语义；含输出各不相同排除）
    fp_calls = defaultdict(list)
    fp2call = {}
    for c in all_calls.values():
        if not isinstance(c.get("time"), (int, float)):
            continue
        r = all_results.get(c["id"])
        if r:
            fp2call.setdefault(c["fp"], c)
            fp_calls[c["fp"]].append(c)
    cnt = {}
    step_occ = {}
    for r in rep["rows"]:
        row_counts = Counter(r["fps"])
        for f, k in row_counts.items():
            cnt[f] = cnt.get(f, 0) + 1
            if k > step_occ.get(f, 0):
                step_occ[f] = k
    cands = {f for f, n in cnt.items() if n >= 3} | {f for f, n in step_occ.items() if n >= 3}
    # hot edit 文件先算（与产品一致：这些文件由 repeated_edit 报告，不重复计）
    edits = defaultdict(list)
    for c in all_calls.values():
        if c["name"] != "edit":
            continue
        r = all_results.get(c["id"])
        if not r or r["error"]:
            continue
        a = c.get("aobj")
        if not isinstance(a, dict):
            continue
        p = a.get("file_path") or a.get("path") or ""
        if p and isinstance(a.get("old_string"), str) and a["old_string"]:
            edits[p].append(hashlib.sha256(a["old_string"].encode()).hexdigest())
    hot = []
    for p, hs in edits.items():
        n = len(hs)
        if n < EDIT_HOT_MIN:
            continue
        uniq = len(set(hs))
        if uniq / float(n) <= 0.6:
            hot.append((p, n, uniq))
    hot.sort(key=lambda x: -x[1])
    hot_files = {p for p, _n, _u in hot}

    for f in cands:
        c = fp2call.get(f)
        if c is None or c["name"] in opt.POLL_LIKE:
            continue
        matching = fp_calls.get(f) or []
        if len(matching) < 3:
            continue
        outputs = [all_results[x["id"]]["text"].strip() for x in matching]
        if len(set(outputs)) == len(outputs):
            continue    # 每次都有新信息 = 不是重复空转
        if c["name"] == "edit":
            a = c.get("aobj")
            p = (a.get("file_path") or a.get("path") or "") if isinstance(a, dict) else ""
            if p in hot_files:
                continue
        n = max(cnt.get(f, 0), step_occ.get(f, 0))
        ivs = [iv for iv in (_call_interval(opt, x, all_results[x["id"]], idx) for x in matching) if iv]
        groups.append(_frag(sid, "repeated_check",
                            n=n, single_step_occ=step_occ.get(f, 0),
                            tool=c["name"],
                            steps=["T%s.S%s" % (x.get("turn"), x.get("step")) for x in matching[:8]],
                            args=san.text(opt.brief_args(c, 150)),
                            n_distinct_outputs=len(set(outputs)),
                            fp=f,
                            union_s=round(_union_s(ivs), 1)))
        frag_intervals["repeated_check"].extend(ivs)

    # ---- extra 5) repeated_edit：同 old_string 补丁式改动
    for p, n, uniq in hot:
        edit_calls = [c for c in all_calls.values()
                      if c["name"] == "edit" and isinstance(c.get("aobj"), dict)
                      and (c["aobj"].get("file_path") or c["aobj"].get("path") or "") == p
                      and all_results.get(c["id"])]
        ivs = [iv for iv in (_call_interval(opt, c, all_results[c["id"]], idx) for c in edit_calls) if iv]
        groups.append(_frag(sid, "repeated_edit",
                            n=n, uniq_old=uniq, tool="edit",
                            file=san.text(os.path.basename(p)),
                            steps=["T%s.S%s" % (c.get("turn"), c.get("step")) for c in edit_calls[:8]],
                            union_s=round(_union_s(ivs), 1)))
        frag_intervals["repeated_edit"].extend(ivs)

    # ---- extra 6) no_output_span：连续零写入长段（含探索守卫，产品同口径）
    rows = rep["rows"]
    i = 0
    while i < len(rows):
        if rows[i]["writes"] == 0:
            j = i
            while j + 1 < len(rows) and rows[j + 1]["writes"] == 0:
                j += 1
            span_rows = rows[i:j + 1]
            span = sum(r["dur"] for r in span_rows)
            if (j - i + 1) >= NOPROD_MIN_STEPS and span >= NOPROD_MIN_S:
                seg_fps = [f for r in span_rows for f in r["fps"]]
                seg_cnt = Counter(seg_fps)
                seg_share = (max(seg_cnt.values()) / len(seg_fps)) if seg_fps else 0.0
                seg_read_n = len({f for f in seg_fps if f.split("|")[0] in opt.READ_LIKE})
                seg_out = sum(r["out"] for r in span_rows)
                explore_guard = seg_read_n >= 4 and seg_share <= 0.3 and seg_out >= 1000
                if not explore_guard:
                    groups.append(_frag(sid, "no_output_span",
                                        n_steps=j - i + 1, span_s=round(span, 1),
                                        out_chars=seg_out, explore_like=False,
                                        steps=["T%s.S%s" % (r["turn"], r["step"]) for r in span_rows[:8]],
                                        tools=sorted({f.split("|")[0] for r in span_rows for f in r["fps"]})[:8]))
            i = j + 1
        else:
            i += 1

    # ---- 汇总（片段耗时一律并集口径，防并行重复计）
    for g in groups:
        g["extra"] = bool(g.get("extra"))
    type_counts = Counter(g["type"] for g in groups)
    summary = {
        "session": sid,
        "status": rep["status"],
        "total_s": round(rep["total"], 1),
        "active_s": round(rep["active"], 1),
        "n_steps": len(rep["rows"]),
        "warnings": list(rep["warnings"])[:3],
        "groups": groups,
        "type_counts": dict(type_counts),
        "type_union_s": {t: round(_union_s(ivs), 1) for t, ivs in frag_intervals.items()},
    }
    return groups, summary


# ---------------------------------------------------------------- grouping (B1c)

import math

# 片段耗时字段的统一取法（各类型不同名；取不到按 0）
def _frag_time(g):
    for k in ("union_s", "tool_s", "poll_total_s", "span_s"):
        v = g.get(k)
        if isinstance(v, (int, float)):
            return float(v)
    return 0.0


def _frag_n(g):
    """发生次数：带 n 字段的类型（repeated_failure/repeated_check/repeated_edit）
    用 n；单事件片段（long_compute/single_poll/no_output_span）记 1。"""
    n = g.get("n")
    return int(n) if isinstance(n, (int, float)) and n > 0 else 1


def _merge_key(g):
    """跨会话合并键。repeated_failure=repeated_failure 用产品同源键（norm_key/fp，
    脱敏且跨运行稳定）；其余按「工具+形态骨架」（args 数字归一——任务 id 等
    跨会话必然不同的编号是形态噪声不是内容；占位符 PATH1/HEX4 的序号一并归一，
    编号是会话内局部状态）。键不含原始敏感值（占位符或折叠后文本）。"""
    t = g["type"]
    if t == "repeated_failure":
        return g.get("norm_key") or "?"
    if t == "repeated_check":
        return g.get("fp") or "?"
    if t == "wait" and g.get("kind") != "single_poll":
        return "session_multi_poll"
    if t == "no_output_span":
        # 「段」不是「模式」：跨会话只按工具形态聚类，不同工具组合的段不混组
        return "no_output_span|" + ",".join(sorted(g.get("tools") or []))[:120]
    tool = g.get("tool") or ""
    args = g.get("args") or ""
    return "%s|%s" % (tool, re.sub(r"\d+", "#", args)[:120])


# 每组片段引用上限：B2 prompt 与人工抽查都不需要全量展开
PTR_LIMIT = 12


def group_evidence(evidence, lessons_items):
    """B1c：把 batch_evidence.json 的片段跨会话聚合成证据组。

    - 同模式合并：同模板错误（norm_key）/同指纹（fp）/同工具同形态空转
      （tool+args 数字归一）跨会话合成一组；组内标会话数与总耗时
    - 总耗时口径：repeated_failure/repeated_check 各片段已是会话内区间并集
      （union_s），跨会话直接求和（不同会话区间不重叠）；long_compute/
      single_poll 按单调用时长求和——B1b 实证本语料并集≈求和（±0.3s），
      且每会话该类型的权威并集口径在 sessions[].type_union_s
    - existing_lesson 对齐：组检索文本命中既有经验条目 match 全部关键词
      （AND 子串，轮次9 语义）→ 标 existing_lesson（B3 写库时合并入该条
      而非新条目）
    - 优先级：score = time_s × (1 + log2(n_sessions))——耗时×跨会话广度
      的几何加权，单会话大耗时与多会话重复都有量级；另出 n_occurrences
      top（非时间信号，repeated_failure union≈0 但反复 11 次这类组）
    """
    kind_order = {k: i for i, k in enumerate(
        ("repeated_failure", "wait", "repeated_check", "long_compute",
         "no_output_span", "repeated_edit"))}
    buckets = defaultdict(list)
    for s in evidence.get("sessions", []):
        for g in s.get("groups", []):
            buckets[(g["type"], _merge_key(g))].append((s["session"], g))

    groups = []
    for (typ, key), items in buckets.items():
        items.sort(key=lambda x: x[0])    # 会话号稳定序
        sids = sorted({sid for sid, _g in items})
        n_occ = sum(_frag_n(g) for _sid, g in items)
        time_s = round(sum(_frag_time(g) for _sid, g in items), 1)
        ptrs, samples = [], []
        for sid, g in items[:PTR_LIMIT]:
            ptrs.append({"session": sid, "turn": g.get("turn"),
                         "step": g.get("step"), "tool": g.get("tool"),
                         "time_s": _frag_time(g)})
        for sid, g in items[:3]:
            d = {"session": sid}
            for k in ("args", "sample_err", "result", "tools", "steps",
                      "poll_total_s", "poll_n", "n", "timeout"):
                if g.get(k) is not None:
                    d[k] = g[k]
            samples.append(d)
        # 既有经验对齐：组检索文本 = 工具名 + 合并键 + args/err 样本
        hay = " ".join([str(g.get("tool") or "") for _s, g in items]
                       + [key] + [str(x.get("args") or "") for x in samples]
                       + [str(e) for x in samples for e in (x.get("sample_err") or [])])
        hits = []
        for it in lessons_items:
            m = it.get("match")
            if m and all(str(w) in hay for w in m):
                # 真实路径=lesson_id 派生哈希；合成测试对象无 _idx 时存原对象
                hits.append(it.get("_idx", it))
        score = round(time_s * (1.0 + math.log2(len(sids))), 1)
        groups.append({
            "kind": typ,
            "merge_key": key[:200],
            "n_sessions": len(sids),
            "sessions": sids,
            "n_fragments": len(items),
            "n_occurrences": n_occ,
            "time_s": time_s,
            "time_note": "union_per_fragment_sum" if typ in
                         ("repeated_failure", "repeated_check", "repeated_edit")
                         else "call_or_span_sum(会话级权威并集=sessions[].type_union_s)",
            "priority_score": score,
            "existing_lesson_idx": hits,
            "evidence_ptrs": ptrs,
            "samples": samples,
            "attribution_status": "pending",   # B2 归因回填
        })

    # 稳定排序：核心四类在前、extra 在后；kind 内 score 降序；gid 顺序编号
    groups.sort(key=lambda g: (g.get("kind") not in _CORE_TYPES,
                               kind_order.get(g["kind"], 99),
                               -g["priority_score"], g["merge_key"]))
    for i, g in enumerate(groups, 1):
        g["gid"] = "G%03d" % i

    ranked = sorted(groups, key=lambda g: -g["priority_score"])[:15]
    n_top = sorted(groups, key=lambda g: -g["n_occurrences"])[:5]
    return {
        "groups": groups,
        "priority_ranked": [{"gid": g["gid"], "kind": g["kind"],
                             "score": g["priority_score"],
                             "time_s": g["time_s"], "n_sessions": g["n_sessions"],
                             "n_occurrences": g["n_occurrences"],
                             "key": g["merge_key"][:90]} for g in ranked],
        "n_time_signal_top": [{"gid": g["gid"], "kind": g["kind"],
                               "n_occurrences": g["n_occurrences"],
                               "time_s": g["time_s"],
                               "key": g["merge_key"][:90]} for g in n_top],
    }


def find_existing_lessons(lessons_path):
    """只读加载 lessons.jsonl（每行 dict，附 _idx=lesson_id 派生哈希前16）。
    id 不落盘（blackhole.lesson_id(kind+fix) 派生），对齐时用派生值。
    文件不存在返回空表（插件兜底/沙箱部署，库尚未建立属正常状态）。"""
    items = []
    if not os.path.exists(lessons_path):
        return items
    with open(lessons_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            it = json.loads(line)
            it["_idx"] = opt_mod.lesson_id(it)
            items.append(it)
    return items


def run_groups(in_json, out_json, lessons_paths):
    """B1c CLI 路径：读片段证据 → 聚合 → 写组清单（lessons 零写入断言）。"""
    before = {k: sha16(p) for k, p in lessons_paths.items()}
    evidence = json.load(open(in_json, encoding="utf-8"))
    lessons_items = find_existing_lessons(lessons_paths["work"])
    out = group_evidence(evidence, lessons_items)
    all_groups = out["groups"]
    tally = Counter(g["kind"] for g in all_groups)
    cross = sum(1 for g in all_groups if g["n_sessions"] >= 2)
    aligned = [(g["gid"], g["kind"], g["existing_lesson_idx"])
               for g in all_groups if g["existing_lesson_idx"]]
    doc = {
        "feature": "批量复盘 B1c：跨会话模式聚合与优先级排序",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": os.path.relpath(in_json, WORK),
        "priority_formula": "score = time_s × (1 + log2(n_sessions))；"
                            "n_time_signal_top 单列反复次数信号（repeated_failure "
                            "耗时≈0 但行为意义大）",
        "merge_key_note": "norm_key/fp=产品同源键（跨会话保真）；tool+args 数字"
                          "归一=形态骨架聚类（跨会话任务id/占位符序号归 #）",
        "n_groups": len(all_groups),
        "n_cross_session_groups": cross,
        "kind_tally": dict(tally),
        "existing_lesson_alignment": [
            {"gid": gid, "kind": kind, "lesson_idx": idx} for gid, kind, idx in aligned],
        "attribution_status": "全部 pending，B2 归因回填",
        **out,
        "lessons_before": before,
        "lessons_after": None,
    }
    after = {k: sha16(p) for k, p in lessons_paths.items()}
    doc["lessons_after"] = after
    if after != before:
        sys.stderr.write("FATAL: lessons hash changed %r -> %r\n" % (before, after))
        return 2
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    print("groups=%d cross_session=%d aligned=%d elapsed=n/a" % (
        len(all_groups), cross, len(aligned)), file=sys.stderr)
    print("OUT " + out_json)
    return 0


# ---------------------------------------------------------------- context (B2b)
# 目标上下文（round4 交代、B2b 落实）：当时目标从会话自身的三类事件提取——
# session/title（data.title）、goal/change（data.goal.objective，最后一次
# create/update 生效）、user/message 中 source.kind=="user" 的真实用户消息
# （schema 实证：b1b_schema_probe + 轮次7 复核，'user-approval'/'time-context'
# 等系统伪装的 user 角色消息全部排除）。全部过 Sanitizer 后才进入 prompt。

CTX_GOAL_CHARS = 240        # goal.objective 截断
CTX_USER_CHARS = 160        # 单条用户消息截断
CTX_USER_MAX = 3            # 最多取前 N 条真实用户消息（用户中途的方向调整
                            # 对 turning_point 归因有证据价值）


def session_context(opt, path, san=None):
    """单会话目标上下文（只读）。返回 None=会话无任何目标类事件。"""
    if san is None:
        san = Sanitizer()
    title = None
    goal = None
    user_msgs = []
    try:
        evs = opt.read_events(path)
    except Exception:
        return None
    for e in evs:
        t = e.get("type")
        d = e.get("data") if isinstance(e.get("data"), dict) else {}
        if t == "session/title" and title is None and d.get("title"):
            title = str(d["title"])
        elif t == "goal/change" and isinstance(d.get("goal"), dict):
            obj = d["goal"].get("objective")
            if obj and str(obj).strip():
                goal = str(obj)          # 后写覆盖：最后一次 goal/change 生效
        elif t == "user/message":
            if (d.get("source") or {}).get("kind") != "user":
                continue
            txt = "".join(c.get("text", "") for c in d.get("content") or []
                          if isinstance(c, dict) and c.get("type") == "text").strip()
            if txt and len(user_msgs) < CTX_USER_MAX:
                user_msgs.append(txt)
    if title is None and goal is None and not user_msgs:
        return None
    return {
        "title": san.text(title[:120]) if title else None,
        "goal": san.text(goal[:CTX_GOAL_CHARS]) if goal else None,
        "user_msgs": [san.text(m[:CTX_USER_CHARS]) for m in user_msgs],
    }


def _ctx_brief(ctx):
    """组 context 渲染用精简条目（prompt 体积可控：6 会话组 × ~400 字）。"""
    d = {}
    for k in ("title", "goal"):
        if ctx.get(k):
            d[k] = ctx[k]
    um = ctx.get("user_msgs") or []
    if um:
        d["user_msgs"] = um[:2]
    return d or {"note": "no_goal_events"}


def collect_contexts(opt, selected, lessons_paths):
    """对选中的 20 个会话逐一提取上下文（B1a 同一选择清单），零写入断言。"""
    before = {k: sha16(p) for k, p in lessons_paths.items()}
    out = {}
    for it in selected:
        sid, ws = it["sid"], it["ws"]
        hits = [p for p in opt.session_files() if sid in p]
        if not hits:
            out[sid] = {"ws": ws, "context": None, "error": "not found"}
            continue
        san = Sanitizer(usernames=(os.environ.get("USERNAME") or "",
                                   os.path.expanduser("~").replace("\\", "/").split("/")[-1]))
        out[sid] = {"ws": ws, "context": session_context(opt, hits[0], san)}
    after = {k: sha16(p) for k, p in lessons_paths.items()}
    if after != before:
        sys.stderr.write("FATAL: lessons hash changed %r -> %r\n" % (before, after))
        return None, 2
    return out, 0


CTX_OUT_JSON = os.path.join(WORK, "eval", "batch_session_context.json")


def run_context(out_json, lessons_paths):
    """CLI --context：20 会话上下文预提取 → eval/batch_session_context.json。"""
    sel = json.load(open(SELECT_JSON, encoding="utf-8"))
    ctx, rc = collect_contexts(opt_mod, sel["selected_20"], lessons_paths)
    if rc:
        return rc
    n_ok = sum(1 for v in ctx.values() if v.get("context"))
    doc = {
        "feature": "批量复盘 B2b：20 会话目标上下文提取（title/goal/真实 user 消息，脱敏）",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "user_filter": "user/message 仅取 source.kind=='user'（schema 实证："
                       "user-approval/time-context/tool-jobs 等系统消息排除）",
        "limits": {"goal_chars": CTX_GOAL_CHARS, "user_chars": CTX_USER_CHARS,
                   "user_max": CTX_USER_MAX},
        "n_sessions": len(ctx), "n_with_context": n_ok,
        "sessions": ctx,
    }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    print("context sessions=%d with_context=%d" % (len(ctx), n_ok), file=sys.stderr)
    print("OUT " + out_json)
    return 0


def attach_context(groups_doc, ctx_doc, max_sessions=8):
    """把会话上下文挂到组上（group["context"]，prompt 渲染入口已留）。

    组成员会话数 > max_sessions 时取组内前 max_sessions 个（ptrs 同序），
    组级标注 truncated=true——prompt 体积守恒，模型可如实说覆盖不全。"""
    cmap = ctx_doc.get("sessions", {})
    for g in groups_doc.get("groups", []):
        items, truncated = [], False
        for sid in (g.get("sessions") or [])[:max_sessions]:
            v = cmap.get(sid)
            if v and v.get("context"):
                items.append({"session": sid[-12:], **_ctx_brief(v["context"])})
            else:
                items.append({"session": sid[-12:], "note": "no_goal_events"})
        if len(g.get("sessions") or []) > max_sessions:
            truncated = True
        g["context"] = {"sessions": items, "truncated": truncated}
    return groups_doc


# ---------------------------------------------------------------- attribution（B2a/B2b）
# 约定输出 schema（B2a 与 headless 真实调用对齐；B2b 沿用同一契约做解析回归）

ATTRIB_CLASSES = ("necessary", "avoidable", "insufficient_evidence")
ATTRIB_CONFIDENCE = ("high", "medium", "low")
# B3a 增补 next_action/effectiveness_check：候选经验五要素中的「下次具体
# 动作」「有效性判断标准」直接取自模型归因；模型没给时写库层按类型兜底
# （build_lesson_candidate），故这两键缺键宽容（validate 不算问题）。
ATTRIB_SCHEMA_KEYS = ("goal", "attempt", "result", "turning_point",
                      "classification", "likely_causes", "confidence",
                      "next_action", "effectiveness_check")


def parse_model_json(text):
    """从模型 stdout 提取约定 JSON，容错三条路径。

    1) direct      —— 整段就是一个 JSON 对象
    2) fenced      —— ```json … ``` 围栏包裹
    3) brace_scan  —— 前后有噪声文字，从首个 { 起括号配平（字符串感知）

    返回 (obj, note)；失败返回 (None, note)。note 记录提取路径，
    B2b 依此做『输出不合规 → 归入证据不足』降级判断。"""
    if not text or not text.strip():
        return None, "empty"
    s = text.strip()
    try:
        return json.loads(s), "direct"
    except ValueError:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", s, re.S)
    if m:
        try:
            return json.loads(m.group(1)), "fenced"
        except ValueError:
            pass
    start = s.find("{")
    if start >= 0:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(s)):
            ch = s[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(s[start:i + 1]), "brace_scan"
                    except ValueError:
                        break
    return None, "unparseable"


def validate_attribution(obj):
    """约定 schema 机械校验；返回问题列表（空=合格）。

    goal/attempt/result/turning_point 为字符串或 null（prompt 契约允许
    证据不足时如实写 null）；classification/confidence 属枚举；
    likely_causes 为列表且每项 cause/basis 非空、uncertainty 为字符串
    （可为 ""）。内容质量（如四字段全 null 却判 avoidable）由 B2b
    下游判定，此处只管 schema 形状。"""
    if not isinstance(obj, dict):
        return ["not a dict"]
    problems = []
    for k in ("goal", "attempt", "result", "turning_point"):
        if k not in obj:
            problems.append("%s missing" % k)  # 缺键≠null：模板要求全键，缺=不合规输出
        elif obj[k] is not None and not isinstance(obj[k], str):
            problems.append("%s not str/null" % k)
    if obj.get("classification") not in ATTRIB_CLASSES:
        problems.append("classification invalid: %r" % (obj.get("classification"),))
    if obj.get("confidence") not in ATTRIB_CONFIDENCE:
        problems.append("confidence invalid: %r" % (obj.get("confidence"),))
    lc = obj.get("likely_causes")
    if not isinstance(lc, list):
        problems.append("likely_causes not list")
    else:
        for i, c in enumerate(lc):
            if not isinstance(c, dict):
                problems.append("likely_causes[%d] not dict" % i)
                continue
            for k in ("cause", "basis"):
                if not (isinstance(c.get(k), str) and c.get(k)):
                    problems.append("likely_causes[%d].%s missing/empty" % (i, k))
            if not isinstance(c.get("uncertainty"), str):
                problems.append("likely_causes[%d].uncertainty not str" % i)
    tp = obj.get("turning_point")
    if tp is not None and not isinstance(tp, str):
        problems.append("turning_point not str/null")
    # B3a 五要素增补键：缺键宽容（老替身/旧产物兼容），给了就必须是 str/null
    for k in ("next_action", "effectiveness_check"):
        v = obj.get(k)
        if k in obj and v is not None and not isinstance(v, str):
            problems.append("%s not str/null" % k)
    return problems


# 增量归因缓存（P1）：键 = sha16(提示词全文 + 版本 + 模型标签)。提示词由
# 组证据/上下文构造而成——证据任何变化都会改变提示词并使键失效，正确性
# 由构造保证。build_attribution_prompt 措辞、上下文装配或后端模型语义
# 变更时 bump ATTRIB_PROMPT_VERSION / ATTRIB_MODEL_TAG → 全量缓存失效。
ATTRIB_PROMPT_VERSION = "1"
ATTRIB_MODEL_TAG = "headless"


def _attrib_cache_key(prompt):
    basis = "%s\0%s\0%s" % (prompt, ATTRIB_PROMPT_VERSION, ATTRIB_MODEL_TAG)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def build_attribution_prompt(group):
    """归因 prompt（固定文本写死于此，便于回归）。

    输入是 batch_evidence_groups.json 的一个组（B1b 已脱敏）。B2b 将在
    证据块补目标上下文（round4 交代：user/message source.kind==user +
    goal/change data.goal + session/title，schema 见 eval/b1b_schema_probe.py）
    ——届时走 group["context"] 渲染，不改正文措辞。"""
    lines = []
    lines.append("你是批量复盘归因助手。下面是一组从多个已结束 DSH 会话中提取的"
                 "脱敏证据（同一模式跨会话重复出现）。请只依据证据分析，"
                 "并严格按文末约定输出 JSON。")
    lines.append("")
    lines.append("## 证据组")
    if group.get("gid"):
        lines.append("GID: %s" % group["gid"])     # 组编号（日志对应/测试替身路由）
    lines.append("- 模式类型: %s" % group.get("kind", "unknown"))
    if group.get("merge_key"):
        lines.append("- 归一化形态: %s" % group["merge_key"])
    lines.append("- 出现会话数: %s" % group.get("n_sessions", "?"))
    lines.append("- 总出现次数: %s" % group.get("n_occurrences", "?"))
    lines.append("- 合计耗时: %ss（区间并集口径，并行重叠不重复计）"
                 % group.get("time_s", "?"))
    for smp in group.get("samples", []):
        steps = ",".join(smp.get("steps") or [])
        lines.append("- %s: %s（%s 次）"
                     % (smp.get("session", "?"), steps or "（无步骤号）", smp.get("n", "?")))
    ctx = group.get("context")
    if ctx:
        lines.append("- 目标上下文: %s" % json.dumps(ctx, ensure_ascii=False))
    else:
        lines.append("- 目标上下文: 证据中暂无（当时目标未知；若无法判定请如实用 "
                     "insufficient_evidence，不要编造目标）")
    lines.append("")
    lines.append("## 你的任务")
    lines.append("1. classification 三选一：necessary（必要耗时）/ avoidable（可避免的低效）"
                 "/ insufficient_evidence（证据不足）。")
    lines.append("2. likely_causes 给可能原因：每条 cause 附 basis（依据，引用证据中的"
                 "具体信息）与 uncertainty（不确定性）。")
    lines.append("3. goal/attempt/result 按证据可推断范围填写；证据不足时写 null，"
                 "不要编造。turning_point=后来哪一步改变了局面，证据内未见则 null。")
    lines.append("4. next_action=下次遇到同一模式时的具体动作（可操作的步骤，"
                 "不是泛泛原则）；effectiveness_check=怎么判断该动作有效"
                 "（可核对的标准，如某指标下降到多少）。证据不足以给出时写 null。")
    lines.append("5. confidence 三选一：high / medium / low。")
    lines.append("")
    lines.append("## 输出格式（必须且只能是如下 JSON 对象；不要 markdown 围栏、"
                 "不要任何额外文字）")
    lines.append('{"goal": null, "attempt": "...", "result": "...", "turning_point": null,'
                 ' "classification": "necessary|avoidable|insufficient_evidence",'
                 ' "likely_causes": [{"cause": "...", "basis": "...", "uncertainty": "..."}],'
                 ' "next_action": null, "effectiveness_check": null,'
                 ' "confidence": "high|medium|low"}')
    return "\n".join(lines) + "\n"


def content_gate(obj):
    """内容质量门（B2b）：schema 形状之外，判定结论是否被证据内容支撑。

    规则：classification 非 insufficient_evidence，但 goal/attempt/result
    三字段全为 null/空 → 判定没有证据支撑（模型只下了结论没给过程），返回
    问题列表；否则空列表。turning_point 本就允许 null，不参与。
    （validate_attribution 注释预告的『四字段全 null 却判 avoidable』下游判定）"""
    if not isinstance(obj, dict) or obj.get("classification") == "insufficient_evidence":
        return []
    empt = [k for k in ("goal", "attempt", "result")
            if not (isinstance(obj.get(k), str) and obj[k].strip())]
    if len(empt) == 3:
        return ["content gate: classification=%s but goal/attempt/result all null/empty"
                % obj.get("classification")]
    return []


def normalize_attribution(obj, note, problems):
    """B2b 降级归一：解析失败 / schema 不合规 / 内容不支撑 → 一律归入
    insufficient_evidence（用户规格：模型输出不合规时归入证据不足），
    保留 degraded 原因供审计。合规输出原样通过。"""
    if obj is None:
        return {"classification": "insufficient_evidence", "confidence": "low",
                "goal": None, "attempt": None, "result": None, "turning_point": None,
                "next_action": None, "effectiveness_check": None,
                "likely_causes": [], "degraded": True,
                "degraded_reason": "parse failed: %s" % note}
    problems = list(problems or []) + content_gate(obj)
    if problems:
        return {
            "classification": "insufficient_evidence", "confidence": "low",
            "goal": obj.get("goal") if isinstance(obj.get("goal"), str) else None,
            "attempt": obj.get("attempt") if isinstance(obj.get("attempt"), str) else None,
            "result": obj.get("result") if isinstance(obj.get("result"), str) else None,
            "turning_point": obj.get("turning_point")
                             if isinstance(obj.get("turning_point"), str) else None,
            "next_action": obj.get("next_action")
                           if isinstance(obj.get("next_action"), str) else None,
            "effectiveness_check": obj.get("effectiveness_check")
                                   if isinstance(obj.get("effectiveness_check"), str) else None,
            "likely_causes": obj.get("likely_causes")
                             if isinstance(obj.get("likely_causes"), list) else [],
            "degraded": True, "degraded_reason": "; ".join(problems)[:500],
        }
    out = {k: obj.get(k) for k in ATTRIB_SCHEMA_KEYS}
    out["degraded"] = False
    return out


class HeadlessModel(object):
    """dsh --profile headless 调用后端（B2a 实证姿势：stdin=prompt，
    stdout=答案；AUTH 已由 cordis.patch.yml→deepseek-account 修复）。"""

    def __init__(self, timeout_s=420):
        self.timeout_s = timeout_s

    def complete(self, prompt):
        import shutil
        import subprocess
        exe = shutil.which("dsh")
        if not exe:
            return {"returncode": -1, "stdout": "", "stderr_tail": "dsh not on PATH",
                    "latency_s": 0.0, "error": "dsh not on PATH"}
        t0 = time.time()
        try:
            proc = subprocess.run([exe, "--profile", "headless", "-"],
                                  input=prompt.encode("utf-8"),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=self.timeout_s)
            return {"returncode": proc.returncode,
                    "stdout": proc.stdout.decode("utf-8", "replace"),
                    "stderr_tail": proc.stderr.decode("utf-8", "replace")[-1000:],
                    "latency_s": round(time.time() - t0, 1), "error": None}
        except Exception as e:
            return {"returncode": -1, "stdout": "", "stderr_tail": "",
                    "latency_s": round(time.time() - t0, 1),
                    "error": "%s: %s" % (type(e).__name__, e)}


ATTRIB_OUT_JSON = os.path.join(WORK, "eval", "batch_attribution.json")


def _rel(path):
    """产物元数据用相对路径；跨盘等 relpath 失败时回退原路径。"""
    try:
        return os.path.relpath(path, WORK)
    except ValueError:
        return path


def run_attribution(groups_json, out_json, lessons_paths, model,
                    gids=None, ctx_json=None, max_ctx_sessions=8):
    """B2b 归因主流程（model 可注入：pytest 传测试替身，CLI 传 HeadlessModel）。

    每组：attach context → build prompt → model → parse → validate →
    content gate → normalize（不合规降级 insufficient_evidence）→ 回填。
    输出 eval/batch_attribution.json；lessons 零写入断言。
    gids=None 处理全部组；给定列表则只处理指定组（分批预算）。

    增量复用（P1）：缓存键 = sha16(提示词全文 + ATTRIB_PROMPT_VERSION +
    ATTRIB_MODEL_TAG)。提示词由组证据/上下文构造而成——证据或上下文任何
    变化都会改变提示词并使键失效，正确性由构造保证。仅复用干净结果
    （非 degraded、三分类合法）；模型失败/解析降级的条目下次照常重试。
    旧产物（无 cache_key 字段）一律重归因，一次性过渡成本。"""
    before = {k: sha16(p) for k, p in lessons_paths.items()}
    groups_doc = json.load(open(groups_json, encoding="utf-8"))
    if ctx_json:
        groups_doc = attach_context(groups_doc,
                                    json.load(open(ctx_json, encoding="utf-8")),
                                    max_ctx_sessions)
    prev = {}
    if os.path.isfile(out_json):
        try:
            with open(out_json, encoding="utf-8") as f:
                prev_doc = json.load(f)
            for entry in prev_doc.get("groups", []):
                a = entry.get("attribution")
                if (isinstance(a, dict) and isinstance(a.get("cache_key"), str)
                        and not a.get("degraded")
                        and a.get("classification") in ATTRIB_CLASSES):
                    prev[entry.get("gid")] = (a["cache_key"], entry.get("attribution_status"), a)
        except (OSError, ValueError):
            prev = {}
    targets = [g for g in groups_doc["groups"]
               if gids is None or g["gid"] in set(gids)]
    missing = sorted(set(gids or []) - {g["gid"] for g in targets})
    results = []
    n_reused = 0
    for g in targets:
        prompt = build_attribution_prompt(g)
        cache_key = _attrib_cache_key(prompt)
        p = prev.get(g["gid"])
        if p is not None and p[0] == cache_key:
            attrib = dict(p[2])
            attrib.update({"gid": g["gid"], "reused": True})
            g["attribution_status"] = p[1]
            g["attribution"] = attrib
            results.append(attrib)
            n_reused += 1
            continue
        resp = model.complete(prompt)
        if resp.get("error") or resp.get("returncode") not in (0, None):
            obj, note = None, "model error: rc=%s %s" % (
                resp.get("returncode"), (resp.get("stderr_tail") or resp.get("error"))[-300:])
            problems = ["model call failed"]
            raw = ""
        else:
            raw = resp.get("stdout") or ""
            obj, note = parse_model_json(raw)
            problems = validate_attribution(obj) if obj is not None else []
        attrib = normalize_attribution(obj, note, problems)
        attrib.update({
            "gid": g["gid"], "kind": g["kind"], "merge_key": g["merge_key"][:120],
            "n_sessions": g["n_sessions"], "time_s": g["time_s"],
            "parse_note": note, "latency_s": resp.get("latency_s"),
            "prompt_chars": len(prompt), "stdout_chars": len(raw),
            "cache_key": cache_key, "reused": False,
            "prompt_ver": ATTRIB_PROMPT_VERSION,
        })
        g["attribution_status"] = ("insufficient_evidence" if attrib.get("degraded")
                                   else attrib["classification"])
        g["attribution"] = attrib
        results.append(attrib)
    tally = Counter(a["classification"] for a in results)
    degraded = sum(1 for a in results if a.get("degraded"))
    doc = {
        "feature": "批量复盘 B2b：模型自主归因（三分类 + 不合规降级 + 增量复用）",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_groups": _rel(groups_json),
        "context_source": _rel(ctx_json) if ctx_json else None,
        "gids_requested": gids, "gids_missing": missing,
        "model": type(model).__name__,
        "n_attributed": len(results),
        "n_reused": n_reused,
        "prompt_ver": ATTRIB_PROMPT_VERSION,
        "classification_tally": dict(tally),
        "n_degraded": degraded,
        "attribution_note": "模型结论只作为候选经验的『可能原因』字段（B3 写库时），"
                            "不宣称因果；degraded 条目一律 insufficient_evidence 不写库。"
                            "reused=True 的条目来自同缓存键的既有结果（证据/提示词/模型版本均未变），未产生新模型调用",
        "groups": [{"gid": g["gid"], "kind": g["kind"],
                    "attribution_status": g["attribution_status"],
                    "attribution": g.get("attribution"),
                    "context": g.get("context")} for g in targets],
        "lessons_before": before, "lessons_after": None,
    }
    after = {k: sha16(p) for k, p in lessons_paths.items()}
    doc["lessons_after"] = after
    if after != before:
        sys.stderr.write("FATAL: lessons hash changed %r -> %r\n" % (before, after))
        return 2
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    print("attributed=%d reused=%d tally=%s degraded=%d missing=%s" % (
        len(results) - n_reused, n_reused, dict(tally), degraded, missing or "-"),
        file=sys.stderr)
    print("OUT " + out_json)
    return 0


# ---------------------------------------------------------------- lessons write (B3a)
# 候选经验写入知识库。过滤规则（B2b 语义校准结论）：只写 classification==
# avoidable 且非 degraded 的组——模型对 necessary/avoidable 边界偏保守
# （G003 unknown-bash 实证：瞬时失败被判必要性论据），宁可漏写候选也不把
# 必要耗时写成低效；insufficient_evidence 一律不写（宁缺毋滥）。
#
# 与产品 _record_lesson 的关系：合并语义对齐（相同 kind+fix 只增 hits、
# evidence 去重追加、match 并集、合并即 pop demo），但 load_lessons/
# save_lessons/LessonLock 写死 blackhole.py 同目录正本——批量复盘需要
# --lessons-path 指向临时库（测试/演示用），故此处参数化路径，锁与原子写
# 语义照抄产品（O_CREAT|O_EXCL、60s 陈旧恢复、tmp+fsync+os.replace）。
#
# 防重双路径（B3b 验收依赖）：
#   1) (kind, fix) 精确命中 → 合并（对齐 _record_lesson）
#   2) (kind, pattern_key) 锚命中 → 合并（fix 措辞随归因漂移时仍不新增；
#      pattern_key=merge_key 是确定性归一形态，不随模型输出漂移）
# 另：B1c 已把组对齐到既有条目（existing_lesson_idx，22 处）——命中时直接
# 合并进该条目（保留既有 fix，id 稳定），绝不新增。

ATTRIB_KIND_MAP = {
    "wait": "任务轮询",
    "repeated_failure": "失败循环",
    "repeated_check": "重复调用",
    "repeated_edit": "反复编辑同处",
    "long_compute": "无产出长段",
    "no_output_span": "无产出长段",
}

# 模型未给 next_action 时的类型兜底。确定性模板 + 模式键拼接（不用 str.format
# ——merge_key 可能含花括号），保证同模式 → 同 fix → 同 id，防重合并稳定。
KIND_FALLBACK_FIX = {
    "任务轮询": "后台任务只 wait=false 取一次结果，未完成就先做不依赖它的步骤；同一 job 连续 3 次结果无变化即停止轮询",
    "失败循环": "同一错误出现第 2 次就停手读错误文本，换工具或改参数，不重试同一形态",
    "重复调用": "结果不变的操作最多做 2 次：第 1 次取信息、第 2 次确认变化，之后记录结论不再调用",
    "无产出长段": "长计算先拆可独立验证的子集（-k / 单文件），前台单步控制在分钟级；确需长跑转后台 wait=false，期间推进不依赖步骤",
    "反复编辑同处": "改前先列出这次改动应满足的全部条件，一次改对；连续 3 次编辑同一处即停下重读需求",
}

KIND_FALLBACK_CHECK = {   # 有效性判断标准兜底（boundary）
    "任务轮询": "下次同场景该工具调用次数≤1 且该段等待总时长显著下降；job 结果仍按时取回",
    "失败循环": "同一归一化错误形态连续出现次数降为 1；任务仍按期完成",
    "重复调用": "同参数调用次数≤2 且结论有记录；不因少调用漏掉信息",
    "无产出长段": "前台单步时长降到分钟级且每步有结论产出；任务总时长不上升",
    "反复编辑同处": "同一文件同一区域的编辑次数≤2 且最终改动通过验证",
}


def _ensure_opt():
    global opt_mod
    if opt_mod is None:
        opt_mod = load_module("bh_batch", OPT_MOD)


def build_lesson_candidate(gid, group, attrib, now=None):
    """归因结果 → lessons.jsonl 候选条目（五要素）。返回 (cand, None) 或
    (None, skip_reason)。

    五要素 → 字段映射：
      触发条件     → match（tool 名 + 失败组错误模板前缀；match_lessons 按
                     「关键词全部子串命中 hole.ctx+tools」带出，宁窄勿误）
      可能原因     → causes（likely_causes 原样保留 basis/uncertainty）
      会话步骤证据 → evidence（session T.turn.S.step tool≈dur 指针串，可回查）
      下次具体动作 → fix（模型 next_action；缺则类型兜底模板，source 注明）
      有效性标准   → boundary（模型 effectiveness_check；缺则类型兜底；
                     confidence=low 追加人工复核提示）
    """
    if attrib.get("degraded"):
        return None, "degraded: %s" % (attrib.get("degraded_reason") or "")[:120]
    if attrib.get("classification") != "avoidable":
        return None, "classification=%s（只写 avoidable）" % attrib.get("classification")
    kind = ATTRIB_KIND_MAP.get(group.get("kind"))
    if not kind:
        return None, "kind %r 不在写库映射表" % group.get("kind")
    causes = [c for c in (attrib.get("likely_causes") or [])
              if isinstance(c, dict) and c.get("cause")]
    if not causes:
        return None, "无可用可能原因"
    key = group.get("merge_key") or ""
    now = int(time.time()) if now is None else now

    fix, fix_src = attrib.get("next_action"), "model"
    if not (isinstance(fix, str) and fix.strip()):
        fix = KIND_FALLBACK_FIX[kind] + "（模式：%s）" % key[:80]
        fix_src = "fallback"
    eff, eff_src = attrib.get("effectiveness_check"), "model"
    if not (isinstance(eff, str) and eff.strip()):
        eff, eff_src = KIND_FALLBACK_CHECK[kind], "fallback"
    if attrib.get("confidence") == "low":
        eff += "（置信度 low：人工复核后再作为主要依据）"

    match = []
    tool = next((p.get("tool") for p in group.get("evidence_ptrs", [])
                 if p.get("tool")), None)
    if tool:
        match.append(str(tool).lower())
    # 失败组的 norm_key 是归一化错误模板（小写、路径折叠），其前缀在同类
    # hole 的 ctx 里有子串命中机会；fp 纯哈希 / 组合键无匹配意义，不放
    if group.get("kind") == "repeated_failure" and key and key != "?":
        frag = key[:40].strip()
        if frag and frag not in match:
            match.append(frag)
    if not match:
        return None, "无法构造触发条件（无 tool 无可用 merge_key）"
    # 证据指针必须可回查：ptr 带 turn/step 用精确形态；repeated_failure 组
    # 的 ptr 是组级占位（turn/step/tool 为 null），用 samples 兜底——
    # steps 列表就是会话内出错步骤号（对齐既有条目「sid tool×n（…）」姿势）
    smp_by_sid = {s.get("session"): s for s in group.get("samples", [])}
    evidence = []
    for p in group.get("evidence_ptrs", []):
        if p.get("turn") is not None or p.get("step") is not None:
            evidence.append("%s T%s.S%s %s≈%ss" % (
                p.get("session", "?"), p.get("turn", "?"), p.get("step", "?"),
                p.get("tool") or "tool?", p.get("time_s", "?")))
            continue
        s = smp_by_sid.get(p.get("session")) or {}
        steps = s.get("steps") or []
        tools = s.get("tools") or []
        ev_tool = tools[0] if tools else (p.get("tool") or "tool?")
        n = s.get("n") or "?"
        evidence.append("%s %s×%s（步骤 %s）" % (
            p.get("session", "?"), ev_tool, n,
            ",".join(str(x) for x in steps[:8]) or "无步骤号"))
    if not evidence:
        return None, "无证据指针（evidence_ptrs 为空）"

    cand = {
        "kind": kind,
        "fix": fix.strip(),
        "hits": 1,
        "created": now, "last_used": now,
        "evidence": evidence,
        "match": match,
        "scope": "contextual",
        "feedback": [],
        "causes": causes,
        "boundary": "%s（有效性标准来源=%s；可能原因来自批量复盘归因，不宣称因果）"
                    % (eff, eff_src),
        "pattern_key": key[:200],
        "source": {"feature": "batch-review", "gid": gid,
                   "confidence": attrib.get("confidence"),
                   "fix_source": fix_src},
    }
    _ensure_opt()
    cand["id"] = opt_mod.lesson_id({"kind": kind, "fix": cand["fix"]})
    return cand, None


def _merge_fields(it, cand, keep_fix=False):
    """把候选合并进既有条目（就地）。对齐 _record_lesson：hits+1、evidence
    去重追加、match 并集、合并即转正式（pop demo）。boundary 用新归因的
    （更新鲜）；causes 按 cause 文本去重合并。keep_fix=True（pattern 锚/
    existing_lesson 对齐路径）时保留既有 fix——id 依赖 kind+fix 必须稳定，
    候选动作文本并入 boundary 备查。"""
    it["hits"] = it.get("hits", 0) + 1
    it["last_used"] = cand["last_used"]
    ev = it.setdefault("evidence", [])
    for e in cand["evidence"]:
        if e not in ev:
            ev.append(e)
    it["match"] = sorted(set(it.get("match") or []) | set(cand.get("match") or []))
    it["boundary"] = cand["boundary"]
    if keep_fix and cand["fix"] != it.get("fix"):
        it["boundary"] += "；另一次归因建议动作：%s" % cand["fix"][:120]
    else:
        it.setdefault("fix", cand["fix"])
    cs = it.setdefault("causes", [])
    known = {c.get("cause") for c in cs if isinstance(c, dict)}
    for c in cand.get("causes", []):
        if c.get("cause") not in known:
            cs.append(c)
    it.setdefault("pattern_key", cand.get("pattern_key"))
    src = it.setdefault("source", {})
    if isinstance(src, dict):
        g = src.setdefault("gids", [])
        # 既有条目创建时的单值 gid 也要进历史（B3b 修复：跨批合并时
        # 批1 的 gid 原来只留在 src["gid"]，gids 历史从批2 才开始）
        first = src.get("gid")
        if first and first not in g:
            g.insert(0, first)
        gid = (cand.get("source") or {}).get("gid")
        if gid and gid not in g:
            g.append(gid)
    it.pop("demo", None)


def merge_candidate_into(items, cand):
    """防重双路径合并（见本节头注）。返回 (action, item)，
    action ∈ created / merged_exact / merged_pattern。"""
    for it in items:
        if it.get("kind") == cand["kind"] and it.get("fix") == cand["fix"]:
            _merge_fields(it, cand)
            return "merged_exact", it
    if cand.get("pattern_key"):
        for it in items:
            if it.get("kind") == cand["kind"] and it.get("pattern_key") == cand["pattern_key"]:
                _merge_fields(it, cand, keep_fix=True)
                return "merged_pattern", it
    items.append(cand)
    return "created", cand


class _PathLock(object):
    """参数化路径锁，语义照抄 blackhole.LessonLock（O_CREAT|O_EXCL、
    60s 陈旧恢复、5s 等待上限）。"""

    STALE_SEC = 60
    DEADLINE_SEC = 5

    def __init__(self, path):
        self.path = path + ".lock"
        self.fd = None

    def __enter__(self):
        deadline = time.monotonic() + self.DEADLINE_SEC
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, str(os.getpid()).encode())
                return self
            except FileExistsError:
                try:
                    stale = time.time() - os.path.getmtime(self.path) > self.STALE_SEC
                except OSError:
                    stale = False
                if stale:
                    try:
                        os.remove(self.path)
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise RuntimeError("经验库 %s 正在写入或存在遗留 .lock；"
                                       "确认写入进程结束后重试" % self.path)
                time.sleep(0.05)

    def __exit__(self, *_args):
        os.close(self.fd)
        try:
            os.remove(self.path)
        except OSError:
            pass


def _load_items(path):
    """参数化读取经验库（校验口径对齐 load_lessons：kind∈KNOWN_KINDS、
    fix 为字符串）；文件不存在返回空表。附 _lid=派生 lesson_id（写盘前剥除）。"""
    items = []
    if not os.path.exists(path):
        return items
    with open(path, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                it = json.loads(line)
                if not isinstance(it, dict) or not isinstance(it.get("fix"), str) \
                        or it.get("kind") not in opt_mod.KNOWN_KINDS:
                    raise ValueError("invalid lesson")
            except (ValueError, TypeError) as exc:
                raise ValueError("经验库 %s 第 %d 行无效；保留原文件，请核对后再写入"
                                 % (path, number)) from exc
            it["_lid"] = it.get("id") or opt_mod.lesson_id(it)
            items.append(it)
    return items


def _save_items(path, items):
    """参数化原子写（语义对齐 save_lessons：tmp+fsync+os.replace）。"""
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix="lessons-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for it in items:
                it.pop("_lid", None)
                f.write(json.dumps(it, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _apply_candidates(items, targets, gmap, amap):
    """把候选写入 items（就地），返回动作列表。锁内调用（决策与写一致）。"""
    actions = []
    for gid in targets:
        group, attrib = gmap[gid], amap[gid]
        cand, skip = build_lesson_candidate(gid, group, attrib)
        if cand is None:
            actions.append({"gid": gid, "action": "skipped", "reason": skip})
            continue
        # B1c 已对齐的既有条目优先：existing_lesson_idx 命中 → 合并不新增
        ex_item = None
        for idx in (group.get("existing_lesson_idx") or []):
            ex_item = next((it for it in items if it.get("_lid") == idx), None)
            if ex_item is not None:
                break
        if ex_item is not None:
            _merge_fields(ex_item, cand, keep_fix=True)
            actions.append({"gid": gid, "action": "merged_existing",
                            "lesson_id": ex_item.get("_lid"),
                            "fix": ex_item["fix"][:80]})
            continue
        action, item = merge_candidate_into(items, cand)
        actions.append({"gid": gid, "action": action,
                        "lesson_id": item.get("id") or item.get("_lid"),
                        "fix": item["fix"][:80]})
    return actions


LESSONS_WRITE_OUT_JSON = os.path.join(WORK, "eval", "batch_lessons_write.json")
GROUPS_OUT_JSON = os.path.join(WORK, "eval", "batch_evidence_groups.json")


def _backup_lessons(path):
    """写库前的自动备份：<库文件>.bak-batchreview-<UTC时间戳>（同秒冲突
    递增 .N）。返回备份路径；源文件不存在返回 None。USAGE 承诺
    「写正本前自动备份」，由此兑现——任何真实写入（正本/部署位/override）
    都先备份。"""
    if not os.path.isfile(path):
        return None
    base = path + ".bak-batchreview-" + time.strftime("%Y%m%d-%H%M%S")
    cand, k = base, 0
    while os.path.exists(cand):
        k += 1
        cand = "%s.%d" % (base, k)
    shutil.copyfile(path, cand)
    return cand


def run_write_lessons(groups_json, attrib_json, out_json, lessons_paths,
                      gids=None, dry_run=False, lessons_override=None):
    """B3a CLI 主流程：归因产物 → 候选经验 → 写入知识库。

    写入目标 = lessons_override（临时库/演示）或 work 正本；official 侧
    只做零写入断言，例外是写库目标本身就是 official（部署位 WORK=脚本
    目录=official 目录，main() 构造的 work/official 路径坍缩为同一文件，
    此时写入合法且哈希断言豁免）。写正本时调用方先备份
    （lessons.jsonl.bak-*）。before/after 双侧哈希全程留痕进产物。"""
    _ensure_opt()
    before = {k: sha16(p) for k, p in lessons_paths.items()}
    groups_doc = json.load(open(groups_json, encoding="utf-8"))
    gmap = {g["gid"]: g for g in groups_doc.get("groups", [])}
    adoc = json.load(open(attrib_json, encoding="utf-8"))
    amap = {g["gid"]: (g.get("attribution") or {}) for g in adoc.get("groups", [])}
    requested = list(gids) if gids is not None else sorted(amap)
    targets = [gid for gid in requested if gid in gmap and gid in amap]
    missing = sorted(set(requested) - set(targets))

    target_path = lessons_override or lessons_paths["work"]
    lessons_backup = None
    if dry_run:
        items = _load_items(target_path)
        actions = _apply_candidates(items, targets, gmap, amap)
    else:
        with _PathLock(target_path):
            items = _load_items(target_path)
            actions = _apply_candidates(items, targets, gmap, amap)
            if any(a["action"] != "skipped" for a in actions):
                lessons_backup = _backup_lessons(target_path)
                _save_items(target_path, items)

    n_created = sum(1 for a in actions if a["action"] == "created")
    n_merged = sum(1 for a in actions
                   if str(a["action"]).startswith("merged"))
    n_skipped = sum(1 for a in actions if a["action"] == "skipped")

    doc = {
        "feature": "批量复盘 B3a：候选经验写入知识库（五要素 + 合并语义）",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_groups": _rel(groups_json), "source_attrib": _rel(attrib_json),
        "gids_requested": gids, "gids_missing": missing,
        "lessons_path": target_path, "dry_run": dry_run,
        "lessons_backup": lessons_backup,
        "write_rule": "只写 classification==avoidable 且非 degraded 的组；"
                      "B1c existing_lesson_idx 命中 → 合并进既有条目；"
                      "(kind,fix) 精确 / (kind,pattern_key) 锚双路径防重",
        "n_candidates": len(targets),
        "n_created": n_created, "n_merged": n_merged, "n_skipped": n_skipped,
        "actions": actions,
        "lessons_before": before, "lessons_after": None,
    }
    after = {k: sha16(p) for k, p in lessons_paths.items()}
    doc["lessons_after"] = after
    # 哈希断言：official 永远零写入——除非写库目标就是 official 本身
    # （部署位 WORK=脚本目录=official 目录，work/official 路径坍缩为同一
    # 文件；豁免否则会把部署位合法写库误报 FATAL：写入已落盘但报错、
    # 产物不落盘）。写正本时变化必须与动作一致；
    # 临时库/演示模式下正本双侧都不许动
    writing_official = os.path.abspath(target_path) == \
        os.path.abspath(lessons_paths["official"])
    if not writing_official and after["official"] != before["official"]:
        sys.stderr.write("FATAL: official lessons hash changed %r -> %r\n"
                         % (before["official"], after["official"]))
        return 2
    if lessons_override and os.path.abspath(lessons_override) != \
            os.path.abspath(lessons_paths["work"]):
        if after["work"] != before["work"]:
            sys.stderr.write("FATAL: 临时库模式动了正本 lessons\n")
            return 2
    else:
        # dry_run 不落盘：created/merged 只出现在预览里，哈希不变是预期
        if not dry_run and (n_created or n_merged) and after["work"] == before["work"]:
            sys.stderr.write("FATAL: 声称写入但正本哈希未变\n")
            return 2
        if not (n_created or n_merged) and after["work"] != before["work"]:
            sys.stderr.write("FATAL: 未写入但正本哈希变了\n")
            return 2
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    print("candidates=%d created=%d merged=%d skipped=%d dry_run=%s" % (
        len(targets), n_created, n_merged, n_skipped, dry_run), file=sys.stderr)
    print("OUT " + out_json)
    return 0


# ---------------------------------------------------------------- main

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


def main(argv=None):
    _out()
    global opt_mod
    lessons_paths = {
        "work": os.path.join(WORK, "lessons.jsonl"),
        "official": os.path.join(os.path.expanduser("~"),
                                 ".dsh", "skills", "time-blackhole-audit", "lessons.jsonl"),
    }
    # B1c 路径：--groups [IN [OUT]]——聚合既有片段证据，不重新提取
    argv = sys.argv[1:] if argv is None else argv
    if "--groups" in argv:
        i = argv.index("--groups")
        rest = argv[i + 1:]
        in_json = rest[0] if rest else OUT_JSON
        out_json = rest[1] if len(rest) > 1 else os.path.join(WORK, "eval", "batch_evidence_groups.json")
        opt_mod = load_module("bh_batch", OPT_MOD)
        return run_groups(in_json, out_json, lessons_paths)

    # B2b 路径 1：--context [OUT]——20 会话目标上下文预提取
    if "--context" in argv:
        i = argv.index("--context")
        rest = argv[i + 1:]
        out_json = rest[0] if rest else CTX_OUT_JSON
        opt_mod = load_module("bh_batch", OPT_MOD)
        return run_context(out_json, lessons_paths)

    # B2b 路径 2：--attribute [--gids G001,G003,...] [--ctx FILE] [IN [OUT]]
    # ——组归因（默认 headless 真实调用；--gids 分批控制调用预算）
    if "--attribute" in argv:
        i = argv.index("--attribute")
        rest = argv[i + 1:]
        gids = None
        ctx_json = CTX_OUT_JSON if os.path.isfile(CTX_OUT_JSON) else None
        positional = []
        j = 0
        while j < len(rest):
            if rest[j] == "--gids" and j + 1 < len(rest):
                gids = [x.strip() for x in rest[j + 1].split(",") if x.strip()]
                j += 2
            elif rest[j] == "--ctx" and j + 1 < len(rest):
                ctx_json = rest[j + 1] if rest[j + 1] != "-" else None
                j += 2
            else:
                positional.append(rest[j])
                j += 1
        in_json = positional[0] if positional else os.path.join(WORK, "eval", "batch_evidence_groups.json")
        out_json = positional[1] if len(positional) > 1 else ATTRIB_OUT_JSON
        opt_mod = load_module("bh_batch", OPT_MOD)
        return run_attribution(in_json, out_json, lessons_paths,
                               HeadlessModel(), gids=gids, ctx_json=ctx_json)

    # B3a 路径：--write-lessons [--gids G001,...] [--attrib FILE]
    #           [--lessons-path FILE] [--dry-run] [GROUPS_JSON [OUT_JSON]]
    # ——候选经验写入知识库。默认写 work 正本（写前先备份）；--lessons-path
    # 指向临时库用于测试/演示；--dry-run 只出预览不落盘
    if "--write-lessons" in argv:
        i = argv.index("--write-lessons")
        rest = argv[i + 1:]
        gids, attrib_json, override, dry = None, ATTRIB_OUT_JSON, None, False
        positional = []
        j = 0
        while j < len(rest):
            if rest[j] == "--gids" and j + 1 < len(rest):
                gids = [x.strip() for x in rest[j + 1].split(",") if x.strip()]
                j += 2
            elif rest[j] == "--attrib" and j + 1 < len(rest):
                attrib_json = rest[j + 1]
                j += 2
            elif rest[j] == "--lessons-path" and j + 1 < len(rest):
                override = rest[j + 1]
                j += 2
            elif rest[j] == "--dry-run":
                dry = True
                j += 1
            else:
                positional.append(rest[j])
                j += 1
        groups_json = positional[0] if positional else GROUPS_OUT_JSON
        out_json = positional[1] if len(positional) > 1 else LESSONS_WRITE_OUT_JSON
        opt_mod = load_module("bh_batch", OPT_MOD)
        return run_write_lessons(groups_json, attrib_json, out_json, lessons_paths,
                                 gids=gids, dry_run=dry, lessons_override=override)

    lessons_paths = {
        "work": os.path.join(WORK, "lessons.jsonl"),
        "official": os.path.join(os.path.expanduser("~"),
                                 ".dsh", "skills", "time-blackhole-audit", "lessons.jsonl"),
    }
    before = {k: sha16(p) for k, p in lessons_paths.items()}

    opt_mod = load_module("bh_batch", OPT_MOD)
    sel = json.load(open(SELECT_JSON, encoding="utf-8"))
    selected = sel["selected_20"]

    sessions = []
    t0 = time.time()
    smoke_zero_groups = []
    for it in selected:
        ws, sid = it["ws"], it["sid"]
        hits = [p for p in opt_mod.session_files() if sid in p]
        if not hits:
            sessions.append({"session": sid, "error": "session file not found"})
            continue
        groups, summary = extract_session(opt_mod, hits[0], sid)
        summary["ws"] = ws
        summary["end_class"] = it.get("end_class")
        summary["substantive"] = it.get("substantive")
        sessions.append(summary)
        if not it.get("substantive") and groups:
            smoke_zero_groups.append(sid)
        print("%-70s %-6s total=%7.1fs groups=%d %s" % (
            sid[:70], summary["status"], summary["total_s"], len(groups),
            summary["type_counts"]), file=sys.stderr)

    # 防误伤断言：非实质（冒烟/短）会话必须零证据片段
    if smoke_zero_groups:
        sys.stderr.write("FATAL: non-substantive sessions produced evidence groups: %r\n"
                         % smoke_zero_groups)
        return 2

    all_groups = [(s["session"], g) for s in sessions for g in s.get("groups", [])]
    tally = Counter(g["type"] for _s, g in all_groups)
    top = sorted(all_groups, key=lambda x: -(x[1].get("union_s") or x[1].get("tool_s")
                                             or x[1].get("span_s") or x[1].get("poll_total_s") or 0))[:10]
    out = {
        "feature": "批量复盘 B1b：四类耗时集中片段证据提取（脱敏）",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "selected_source": os.path.relpath(SELECT_JSON, WORK),
        "thresholds": {
            "long_call_s": LONG_CALL_S, "timeout_call_s": TIMEOUT_CALL_S,
            "err_group_min": ERR_GROUP_MIN,
            "wait_total_s": WAIT_TOTAL_S, "wait_min_n": WAIT_MIN_N,
            "noprod_min_steps": NOPROD_MIN_STEPS, "noprod_min_s": NOPROD_MIN_S,
            "edit_hot_min": EDIT_HOT_MIN,
        },
        "sanitization": "显示文本=会话内稳定编号占位符(PATH/URL/HEX/MAIL/USER+序号；"
                        "斜杠 token 仅路径形态才脱敏，3/10、and/or 保留)；"
                        "合并键 norm_key 只做 ≥16 位十六进制→HEX 确定性折叠；fp 本为 sha256",
        "n_sessions": len(sessions),
        "type_tally": dict(tally),
        "top_fragments_preview": [
            {"session": s, "type": g["type"],
             "time_s": (g.get("union_s") or g.get("tool_s") or g.get("span_s")
                        or g.get("poll_total_s")),
             "tool": g.get("tool"), "args": (g.get("args") or "")[:120],
             "timeout": g.get("timeout")} for s, g in top],
        "sessions": sessions,
        "elapsed_s": None,
        "lessons_before": before,
        "lessons_after": None,
    }
    after = {k: sha16(p) for k, p in lessons_paths.items()}
    out["lessons_after"] = after
    if after != before:
        sys.stderr.write("FATAL: lessons hash changed %r -> %r\n" % (before, after))
        return 2
    out["elapsed_s"] = round(time.time() - t0, 1)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    print("sessions=%d groups=%d tally=%s elapsed=%.1fs" % (
        len(sessions), len(all_groups), dict(tally), out["elapsed_s"]), file=sys.stderr)
    print("OUT " + OUT_JSON)
    return 0


if __name__ == "__main__":
    sys.exit(main())
