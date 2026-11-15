# -*- coding: utf-8 -*-
"""B7 一键复盘与行动清单（quick review）。

把批量复盘的手动串联（选取 → 提取 → 聚合 → 上下文 → 归因 → 写入）收成
**一次调用**：默认看最近最多 20 个已结束任务，产出最多 3 个有证据、值得
下一次优先处理的卡点（行动清单预览）。设计边界（任务书 B7）：

- **原接口零改动**：本模块只 import 复用 batch_review.py 的五步函数
  （extract_session / group_evidence / collect_contexts / run_attribution），
  不修改原脚本一行；原 CLI 与插件接口行为不变。
- **预览不写库**：全程零写入断言（work+official lessons 哈希前后一致，
  任一变化立即 FATAL rc=2）；行动清单只附「经确认写入」所需的精确命令
  （显式 --gids + --attrib + quick 自己的 groups 文件，避免默认路径撞名——
  USAGE 已知坑：漏传 --attrib 会静默读旧接口默认归因路径）。
- **增量复用**：归因缓存沿用 run_attribution（缓存键=提示词全文 sha16+
  版本+模型标签）：同批重跑零新增模型调用；追加证据只改变受影响组的
  提示词 → 只重算受影响组；模型失败（degraded）不入缓存 → 重试只算
  失败组。缓存落在 out_dir/quick_attribution.json。
- **候选上限 3**：候选打分 = 先验可避免性(kind) × (1 + 观测耗时 + 跨会话
  复现 + 证据完整度)。已对齐既有经验条目（existing_lesson_idx 非空）的组
  不进候选——它们已被经验库覆盖；全部候选都被覆盖时给 no_new_evidence
  短结果。先验只影响预算分配（3 组归因花在谁身上），不替代归因结论；
  未入候选的高耗时组在报告 not_listed 里如实列出并给补归因命令。
- **诚实口径**：observed_time_s=观测耗时（区间并集口径，机械事实）；
  saveable_time_s 只在确有复跑数据时给数字（默认 null+明注），不拿观测
  耗时冒充可节省耗时。

短结果五态（用户规格：空输入/没新证据/只剩必要耗时/证据不足都要明确短结果）：
  empty_input          选中 0 个已结束任务
  no_evidence          有任务但零证据片段（全部低于阈值——健康信号）
  no_new_evidence      有片段但候选全被既有经验覆盖
  all_necessary        归因后全部必要耗时（无可避免卡点）
  insufficient_evidence 归因后全部证据不足/降级（如实短结果+缺口说明）

产物（默认 eval/quick/，不触碰旧接口共享产物）：
  quick_select.json / quick_evidence.json / quick_groups.json /
  quick_context.json / quick_attribution.json / quick_report.json

CLI：
  python quick_review.py [--select-json FILE] [--max-groups 3]
                         [--model headless|scripted] [--gids G001,G002]
                         [--out-dir DIR] [--lessons-path FILE]
stdout 只有 `OUT <report.json>` 一行（脚本化消费惯例与 batch_review 一致），
汇总与短结果走 stderr。
"""
import hashlib
import importlib.util
import io
import contextlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT_DIR = os.path.join(HERE, "eval", "quick")
SELECTOR_PATH = os.path.join(HERE, "eval", "batch_scan_select.py")
MAX_SESSIONS = 20          # 用户规格：默认只看最近最多 20 个已结束任务
MAX_GROUPS_DEFAULT = 3     # 用户规格：候选归因上限 3 组

# 先验可避免性（B2b/B3a 语义校准定稿：失败循环最典型——B3a 写入正本的
# 3 条全是 repeated_failure；等待/长计算多为必要（G003 教训：necessary↔
# avoidable 边界偏保守，先验低了顶多不进 3 组预算，不会把必要写成低效）。
KIND_PRIOR = {
    "repeated_failure": 1.0,
    "repeated_edit": 0.8,
    "repeated_check": 0.7,
    "no_output_span": 0.5,
    "long_compute": 0.3,
    "wait": 0.2,
}


def load_br():
    """加载 batch_review.py（同目录）并接好 blackhole.py 依赖。

    find_existing_lessons 依赖 batch_review 的模块级 opt_mod（lesson_id
    派生用），必须在调用前接好——与 batch_review.main 的 global opt_mod
    装配方式一致。"""
    spec = importlib.util.spec_from_file_location(
        "bh_quick_br", os.path.join(HERE, "batch_review.py"))
    br = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(br)
    br.opt_mod = br.load_module("bh_quick_bh", os.path.join(HERE, "blackhole.py"))
    return br


def sha16(path):
    if not os.path.exists(path):
        return "no-file"
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


def _rel_safe(path, start=HERE):
    """相对路径元数据；跨盘等 relpath 失败时回退原路径（同 batch_review._rel）。"""
    try:
        return os.path.relpath(path, start)
    except ValueError:
        return path


def _check_same_drive(path, what):
    """out_dir 必须与脚本同盘：batch_review.run_groups 内部用裸 relpath
    （跨盘抛 ValueError），本入口不动原脚本，改为入口处明确拒绝。"""
    if path and os.path.splitdrive(os.path.abspath(path))[0] != \
            os.path.splitdrive(HERE)[0]:
        sys.stderr.write("FATAL: %s 必须与 quick_review.py 同盘（%s 与 %s 跨盘，"
                         "底层 batch_review 的产物路径口径不支持）\n"
                         % (what, os.path.abspath(path), HERE))
        return False
    return True


# ---------------------------------------------------------------- 候选打分

def candidate_score(g):
    """归因预算打分（先验可避免性 × 证据规模，各因子封顶防单一因子垄断）。

    - prior：kind 先验（KIND_PRIOR）
    - time_part：观测耗时封顶 1h → 0..2
    - rec_part：跨会话数封顶 10 → 0..2
    - ev_part：出现次数封顶 20 → 0..1；无步骤指针（不可回查）再减半
    """
    prior = KIND_PRIOR.get(g.get("kind"), 0.4)
    t = g.get("time_s") or 0.0
    time_part = min(t, 3600.0) / 3600.0 * 2.0
    rec_part = min(g.get("n_sessions") or 1, 10) / 10.0 * 2.0
    samples = g.get("samples") or []
    n_occ = sum(s.get("n") or 0 for s in samples)
    ev_part = min(n_occ, 20) / 20.0
    if not any(s.get("steps") for s in samples):
        ev_part *= 0.5
    return round(prior * (1.0 + time_part + rec_part + ev_part), 3)


def rank_candidates(groups):
    """归因候选排序。排除已对齐既有经验的组（经验库已覆盖，非新证据）。

    H1（B7 副本验证，eval/quick/_b7_hypo/h1_replay.json）：repeated_check
    指纹组的会话集合被某 repeated_failure 组完全覆盖时降权 ×0.6——同一批
    调用双计信号（同 4 次盲试同时产出失败模板与重复检查两类片段），指纹组
    不新增信息却争抢 3 组归因预算；重放实证 fixture 换入新模板组（信息增益）、
    真实语料 top3 不变（无回归）。

    返回 (candidates, skipped_aligned)：candidates 按 score 降序（同分按
    gid 稳定序）；skipped_aligned=被排除组摘要（报告如实披露）。"""
    cands, skipped = [], []
    rf_sessions = [set(g.get("sessions") or []) for g in groups
                   if g.get("kind") == "repeated_failure"]
    for g in groups:
        if g.get("existing_lesson_idx"):
            skipped.append({"gid": g["gid"], "kind": g["kind"],
                            "reason": "aligned_existing_lesson",
                            "lesson_idx": g["existing_lesson_idx"],
                            "time_s": g.get("time_s"),
                            "n_sessions": g.get("n_sessions")})
            continue
        score = candidate_score(g)
        if g.get("kind") == "repeated_check" and rf_sessions:
            ss = set(g.get("sessions") or [])
            if any(ss <= r for r in rf_sessions):
                score = round(score * 0.6, 3)
        cands.append({"gid": g["gid"], "score": score})
    cands.sort(key=lambda c: (-c["score"], c["gid"]))
    return cands, skipped


# ---------------------------------------------------------------- 流程

def resolve_selection(br, opt, select_json, out_dir):
    """确定复盘范围。返回 (selected, select_meta, rc)。

    - select_json=None：跑正式选取器（eval/batch_scan_select.py，patch 其
      OUT_JSON 到 out_dir/quick_select.json——共享产物 eval/batch_scan_select.json
      不被本入口触碰），selection_rule=substantive_first_fill_trivial 继承。
    - select_json=FILE：固定样本。兼容两种形状：选取器产物
      {"selected_20": [...]} 与显式路径 {"selected": [{ws,sid,path}]}
      （fixture/测试用；path 缺省时用 session_files() 按 sid 解析）。"""
    os.makedirs(out_dir, exist_ok=True)
    sel_path = os.path.join(out_dir, "quick_select.json")
    if select_json:
        doc = json.load(open(select_json, encoding="utf-8"))
        items = doc.get("selected_20") or doc.get("selected") or []
        sel_dir = os.path.dirname(os.path.abspath(select_json))
        fixed = []
        for it in items[:MAX_SESSIONS]:
            it = {k: it[k] for k in ("ws", "sid", "path", "substantive") if k in it}
            # 相对 path 按样本文件所在目录解析（样本与 fixture 同源携带即可
            # 移植），其次 cwd——绝对路径原样。
            p = it.get("path")
            if p and not os.path.isabs(p):
                cand = os.path.join(sel_dir, p)
                it["path"] = cand if os.path.exists(cand) else os.path.abspath(p)
            fixed.append(it)
        selected = fixed
        meta = {"source": _rel_safe(select_json),
                "rule": doc.get("summary", {}).get("counts", {}).get(
                    "selection_rule", "fixed_sample"),
                "n_selected": len(selected)}
        return selected, meta, 0
    if not os.path.isfile(SELECTOR_PATH):
        sys.stderr.write("FATAL: 选取器缺失 %s（默认选取需要；或用 --select-json 指定固定样本）\n"
                         % SELECTOR_PATH)
        return None, None, 2
    spec = importlib.util.spec_from_file_location("bh_quick_selector", SELECTOR_PATH)
    sel_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sel_mod)
    sel_mod.OUT_JSON = sel_path            # 只改产物落点，不改共享文件
    sel_mod.main()
    doc = json.load(open(sel_path, encoding="utf-8"))
    selected = [{k: it[k] for k in ("ws", "sid", "substantive") if k in it}
                for it in doc.get("selected_20", [])[:MAX_SESSIONS]]
    meta = {"source": _rel_safe(SELECTOR_PATH),
            "rule": doc.get("summary", {}).get("counts", {}).get(
                "selection_rule", "substantive_first_fill_trivial"),
            "n_sessions_scanned": doc.get("summary", {}).get("n_sessions"),
            "n_selected": len(selected)}
    return selected, meta, 0


def phase_extract(br, opt, selected, out_dir):
    """提取耗时集中片段（复用 batch_review.extract_session；lessons 零写入）。

    非实质会话零片段守卫沿用主入口口径（substantive=False 且出片段=FATAL）。"""
    evidence = {"feature": "B7 quick：耗时集中片段证据提取（复用 batch_review 五步）",
                "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sessions": []}
    smoke_zero = []
    for it in selected:
        sid = it["sid"]
        path = it.get("path")
        if not path:
            hits = [p for p in opt.session_files() if sid in p]
            path = hits[0] if hits else None
        if not path:
            evidence["sessions"].append({"session": sid, "error": "session file not found"})
            continue
        groups, summary = br.extract_session(opt, path, sid)
        summary["ws"] = it.get("ws", "unknown")
        evidence["sessions"].append({"session": sid, "groups": groups, **summary})
        if it.get("substantive") is False and groups:
            smoke_zero.append(sid)
    if smoke_zero:
        sys.stderr.write("FATAL: 非实质会话出现证据片段（防误伤断言）: %r\n" % smoke_zero)
        return None, 2
    path = os.path.join(out_dir, "quick_evidence.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=1)
    return evidence, 0


def phase_context(br, opt, selected, out_dir, lessons_paths):
    """目标上下文（复用 collect_contexts；ctx=None 合法=无目标类事件）。"""
    ctx, rc = br.collect_contexts(opt, selected, lessons_paths)
    if rc:
        return None, rc
    doc = {"feature": "B7 quick：会话目标上下文（title/goal/真实 user 消息，脱敏）",
           "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "limits": {"goal_chars": br.CTX_GOAL_CHARS, "user_chars": br.CTX_USER_CHARS,
                      "user_max": br.CTX_USER_MAX},
           "n_sessions": len(ctx), "sessions": ctx}
    path = os.path.join(out_dir, "quick_context.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    return doc, 0


def _write_cmd(gids, out_dir, dry_run=True):
    """确认写入命令（显式四锚点：quick 的 groups 文件 + gids + quick 归因
    文件 + 预览产物落点，全部绝对路径——在任意 cwd 可复现，且不触碰旧
    接口共享产物）。默认 --dry-run 只出预览；真写去掉 --dry-run（写前自动
    备份，与五步写库同一机制），演练时再加 --lessons-path 指向临时库。"""
    script = os.path.join(HERE, "batch_review.py")
    cmd = ("python \"%s\" --write-lessons \"%s\" --gids %s --attrib \"%s\" \"%s\""
           % (script, os.path.abspath(os.path.join(out_dir, "quick_groups.json")),
              ",".join(gids),
              os.path.abspath(os.path.join(out_dir, "quick_attribution.json")),
              os.path.abspath(os.path.join(out_dir, "quick_write_preview.json"))))
    if dry_run:
        cmd += " --dry-run"
    return cmd


def _fallback(kind, field):
    """模型未给 next_action/effectiveness_check 时的类型兜底文案
    （与 build_lesson_candidate 写库层兜底同语义，保持清单与库一致）。"""
    if field == "next_action":
        return {"repeated_failure": "同一报错第二次出现时立即改用替代方法，不原样重试",
                "repeated_check": "重复检查前先确认结果落盘位置，避免无效重读",
                "repeated_edit": "编辑前重读文件最新内容，合并为一次改动",
                "no_output_span": "长探索段先写下当前假设与验证标准，再继续",
                "long_compute": "长调用前预估时长，超预期即转后台并轮询",
                "wait": "确认等待对象与轮询间隔，避免密集空轮询"}.get(
            kind, "下次遇到同一模式先记录上下文再行动")
    return "按「下次第一步」执行后，比对该模式重现次数是否下降（以本卡点的会话步骤为回查基准）"


def build_blocker(g, attrib, out_dir):
    """行动清单条目：可回查会话与步骤、重复次数、观测耗时、可能原因与
    不确定性、下次第一步与验证方法。观测/可节省口径分开。"""
    samples = g.get("samples") or []
    sessions_steps = [{"session": s.get("session"),
                       "steps": s.get("steps") or [],
                       "n": s.get("n")}
                      for s in samples]
    causes = []
    for c in (attrib.get("likely_causes") or [])[:4]:
        if isinstance(c, dict) and c.get("cause"):
            causes.append({"cause": c.get("cause"), "basis": c.get("basis"),
                           "uncertainty": c.get("uncertainty")})
    gids = [g["gid"]]
    return {
        "gid": g["gid"],
        "kind": g["kind"],
        "pattern": (g.get("merge_key") or "")[:120],
        "n_sessions": g.get("n_sessions"),
        "n_occurrences": g.get("n_occurrences"),
        "observed_time_s": g.get("time_s"),
        "time_note": "观测耗时（区间并集口径，机械事实）；"
                     "可节省耗时未验证——本批无复跑数据，不宣称节省",
        "saveable_time_s": None,
        "classification": attrib.get("classification"),
        "confidence": attrib.get("confidence"),
        "possible_causes": causes,
        "goal_context": attrib.get("goal"),
        "attempt": attrib.get("attempt"),
        "result": attrib.get("result"),
        "next_first_step": attrib.get("next_action") or _fallback(g["kind"], "next_action"),
        "verification": attrib.get("effectiveness_check") or _fallback(g["kind"], "check"),
        "sessions_steps": sessions_steps,
        "evidence_file": _rel_safe(
            os.path.join(out_dir, "quick_groups.json")).replace("\\", "/"),
        "attribution_file": _rel_safe(
            os.path.join(out_dir, "quick_attribution.json")).replace("\\", "/"),
        "write_cmd": _write_cmd(gids, out_dir, dry_run=True),
        "write_cmd_confirm": _write_cmd(gids, out_dir, dry_run=False),
    }


def build_report(selected, select_meta, evidence, groups_doc, ctx_doc,
                 attrib_doc, candidates, skipped, out_dir,
                 phase_s, lessons_before, lessons_after,
                 max_groups=MAX_GROUPS_DEFAULT):
    """汇总报告 + 短结果判定。result 五态见模块 docstring。"""
    groups = (groups_doc or {}).get("groups", [])
    n_groups = len(groups)
    targets = (attrib_doc or {}).get("groups", [])
    model_calls = (attrib_doc or {}).get("n_attributed", 0)
    model_reused = (attrib_doc or {}).get("n_reused", 0)
    n_err_sessions = sum(1 for s in (evidence or {}).get("sessions", [])
                         if s.get("error"))

    blockers, not_listed = [], []
    if targets:
        by_gid = {g["gid"]: g for g in groups}
        for tg in targets:
            g = by_gid.get(tg["gid"], tg)
            st = tg.get("attribution_status")
            a = tg.get("attribution") or {}
            if st == "avoidable" and not a.get("degraded"):
                blockers.append(build_blocker(g, a, out_dir))
            else:
                not_listed.append({
                    "gid": tg["gid"], "kind": g.get("kind", tg.get("kind")),
                    "status": st, "reason": ("degraded" if a.get("degraded")
                                             else st),
                    "degraded_reason": a.get("degraded_reason"),
                    "time_s": g.get("time_s", tg.get("time_s")),
                    "n_sessions": g.get("n_sessions", tg.get("n_sessions"))})
    # 未入候选的组如实列出（先验/上限之外的透明度 + 补归因出口）
    cand_gids = {c["gid"] for c in candidates}
    for g in groups:
        if g["gid"] in cand_gids:
            continue
        if any(n["gid"] == g["gid"] for n in not_listed):
            continue
        if g.get("existing_lesson_idx"):
            continue
        not_listed.append({"gid": g["gid"], "kind": g["kind"],
                           "status": "pending", "reason": "rank_below_cap",
                           "time_s": g.get("time_s"),
                           "n_sessions": g.get("n_sessions")})

    if not selected:
        result = "empty_input"
    elif n_groups == 0:
        # 全部会话读取失败时不是健康信号，如实说
        result = "empty_input" if n_err_sessions == len(selected) else "no_evidence"
    elif not candidates and not blockers:
        result = "no_new_evidence"
    elif targets and not blockers and all(
            (t.get("attribution") or {}).get("classification") == "necessary"
            for t in targets):
        result = "all_necessary"
    elif targets and not blockers:
        result = "insufficient_evidence"
    else:
        result = "ok"

    rep = {
        "feature": "B7 一键复盘与行动清单（预览，不写正式经验库）",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "result": result,
        "result_text": {
            "empty_input": ("没有可复盘的已结束任务（选中 0 个）" if not selected
                            else "选中 %d 个任务但全部读取失败，无可用证据" % n_err_sessions),
            "no_evidence": "最近 %d 个任务没有耗时集中片段（全部低于阈值，健康信号）"
                           % max(0, len(selected) - n_err_sessions),
            "no_new_evidence": "候选证据组均已被既有经验覆盖，无新增证据",
            "all_necessary": "只观测到必要耗时，无可避免卡点",
            "insufficient_evidence": "证据不足，无法给出有依据的卡点（见 not_listed 缺口）",
            "ok": "%d 个卡点（候选上限 %d，模型调用 %d 次、复用 %d 次）"
                  % (len(blockers), max_groups, model_calls - model_reused,
                     model_reused),
        }[result],
        "scope": {**(select_meta or {}), "n_sessions": len(selected),
                  "max_sessions": MAX_SESSIONS},
        "pipeline": {
            "n_groups": n_groups,
            "n_candidates": len(candidates),
            "candidate_cap": MAX_GROUPS_DEFAULT,
            "candidates": candidates,
            "skipped_aligned": skipped,
            "model_calls": model_calls, "model_reused": model_reused,
            "model_backend": (attrib_doc or {}).get("model"),
            "phase_seconds": {k: round(v, 1) for k, v in phase_s.items()},
            "elapsed_s": round(sum(phase_s.values()), 1),
        },
        "blockers": blockers,
        "not_listed": not_listed,
        "zero_write": {"lessons_before": lessons_before,
                       "lessons_after": lessons_after,
                       "note": "预览不写任何经验库；写入须按 blockers[].write_cmd "
                               "（显式 --gids + --attrib + --dry-run 预览）或插件 "
                               "write 动作（attrib_path/groups_path 指向 quick 产物）"},
        "summary_lines": [],
    }
    lines = ["QUICK %s | %s" % (result, rep["result_text"])]
    for i, b in enumerate(blockers, 1):
        lines.append("[%d/%d] %s %s %s会话 %s次 观测%ss conf=%s"
                     % (i, len(blockers), b["gid"], b["kind"], b["n_sessions"],
                        b["n_occurrences"], b["observed_time_s"], b["confidence"]))
        for c in b["possible_causes"][:2]:
            u = ("；不确定: %s" % c["uncertainty"]) if c.get("uncertainty") else ""
            lines.append("  原因: %s（依据: %s%s）" % (c["cause"],
                                                     (c.get("basis") or "-")[:120], u))
        lines.append("  下次第一步: %s" % b["next_first_step"])
        lines.append("  验证方法: %s" % b["verification"])
        trace = "; ".join("%s:%s" % (s["session"],
                                     ",".join(map(str, s["steps"][:4])) or "无步骤号")
                          for s in b["sessions_steps"][:3])
        lines.append("  证据回查: %s → %s" % (b["evidence_file"], trace))
        lines.append("  确认写入: %s" % b["write_cmd"])
    for n in not_listed[:6]:
        lines.append("未列出 %s %s %s（%s）"
                     % (n["gid"], n["kind"], n.get("status"),
                        n.get("reason") or n.get("degraded_reason") or ""))
    rep["summary_lines"] = lines
    return rep


def run_quick(selected, lessons_paths, model, out_dir=DEFAULT_OUT_DIR,
              max_groups=MAX_GROUPS_DEFAULT, select_meta=None,
              gids_override=None, br=None, opt=None):
    """一键复盘主流程。返回 (report, rc)。rc=0 含全部短结果情形；
    rc=2 仅零写入被破坏等 FATAL。"""
    if br is None:
        br = load_br()
    if opt is None:
        opt = br.opt_mod
    if not _check_same_drive(out_dir, "out_dir"):
        return 2
    os.makedirs(out_dir, exist_ok=True)
    phase_s = {}
    lessons_before = {k: sha16(p) for k, p in lessons_paths.items()}

    # 1) 提取（含选取产物已在 resolve_selection 落盘；这里只计时提取）
    t0 = time.time()
    evidence, rc = phase_extract(br, opt, selected, out_dir)
    phase_s["extract_s"] = time.time() - t0
    if rc:
        return None, rc

    # 2) 聚合（复用 run_groups：自带 lessons 零写入断言与 existing 对齐；
    # 子步骤 stdout 重定向——stdout 只保留本入口最终的 OUT 一行，脚本化
    # 消费口径与 batch_review 单步一致；stderr 汇总照常透出）
    t0 = time.time()
    groups_path = os.path.join(out_dir, "quick_groups.json")
    with contextlib.redirect_stdout(io.StringIO()):
        rc = br.run_groups(os.path.join(out_dir, "quick_evidence.json"),
                           groups_path, lessons_paths)
    phase_s["groups_s"] = time.time() - t0
    if rc:
        return None, rc
    groups_doc = json.load(open(groups_path, encoding="utf-8"))

    # 3) 上下文
    t0 = time.time()
    ctx_doc, rc = phase_context(br, opt, selected, out_dir, lessons_paths)
    phase_s["context_s"] = time.time() - t0
    if rc:
        return None, rc

    # 4) 候选与归因（上限 max_groups；--gids 覆盖自动选取）。
    # 缓存按模型身份隔离（B7f 实测教训：缓存键若不含模型，替身结果会被
    # 真实调用复用——latency=0 假复用）。ATTRIB_MODEL_TAG 正是为此预留的
    # 版本位；每个 run_quick 实例加载独立的 br 模块，就地设置安全。
    t0 = time.time()
    br.ATTRIB_MODEL_TAG = type(model).__name__
    candidates, skipped = rank_candidates(groups_doc.get("groups", []))
    use_gids = gids_override or [c["gid"] for c in candidates[:max_groups]]
    attrib_doc = None
    if use_gids:
        attrib_path = os.path.join(out_dir, "quick_attribution.json")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = br.run_attribution(groups_path, attrib_path, lessons_paths, model,
                                    gids=use_gids,
                                    ctx_json=os.path.join(out_dir, "quick_context.json"))
        if rc:
            return None, rc
        attrib_doc = json.load(open(attrib_path, encoding="utf-8"))
    phase_s["attribute_s"] = time.time() - t0

    # 5) 报告（短结果判定 + 行动清单）
    t0 = time.time()
    lessons_after = {k: sha16(p) for k, p in lessons_paths.items()}
    if lessons_after != lessons_before:
        sys.stderr.write("FATAL: lessons hash changed %r -> %r\n"
                         % (lessons_before, lessons_after))
        return None, 2
    rep = build_report(selected, select_meta, evidence, groups_doc, ctx_doc,
                       attrib_doc, candidates, skipped, out_dir,
                       phase_s, lessons_before, lessons_after,
                       max_groups=max_groups)
    report_path = os.path.join(out_dir, "quick_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)
    phase_s["report_s"] = time.time() - t0
    rep["pipeline"]["phase_seconds"] = {k: round(v, 1) for k, v in phase_s.items()}
    rep["pipeline"]["elapsed_s"] = round(sum(phase_s.values()), 1)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)
    return rep, 0


# ---------------------------------------------------------------- CLI

class ScriptedModel(object):
    """确定性测试替身（CLI --model scripted；按 merge_key 关键词路由，
    与 B4 ScriptedModel 同语义）。仅用于免费快跑/演示，输出如实标注
    model=ScriptedModel，不作正式验收依据——正式验收用 HeadlessModel。"""

    def complete(self, prompt):
        low = prompt.lower()
        if "file has been modified" in low:
            cls, fix = "avoidable", "失败后立即重读文件再构造新 old_string，禁止凭记忆盲试"
        elif "aborted" in low:
            cls, fix = "insufficient_evidence", "先补齐中止上下文（发起方/后续动作）再归因"
        else:
            cls, fix = "necessary", "单次成功调用无重试，属必要耗时"
        return {"stdout": json.dumps({
            "goal": "样例目标", "attempt": "样例试过程", "result": "样例结果",
            "turning_point": None, "classification": cls,
            "likely_causes": [{"cause": "样例原因", "basis": "样例依据",
                               "uncertainty": "样例不确定性"}],
            "confidence": "medium", "next_action": fix,
            "effectiveness_check": "该模式重现次数下降为 0"}), "returncode": 0,
            "stderr_tail": "", "latency_s": 0.0, "error": None}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    select_json = out_dir = lessons_override = None
    model_kind = "headless"
    max_groups = MAX_GROUPS_DEFAULT
    gids_override = None
    j = 0
    while j < len(argv):
        a = argv[j]
        if a == "--select-json" and j + 1 < len(argv):
            select_json = argv[j + 1]; j += 2
        elif a == "--out-dir" and j + 1 < len(argv):
            out_dir = argv[j + 1]; j += 2
        elif a == "--lessons-path" and j + 1 < len(argv):
            lessons_override = argv[j + 1]; j += 2
        elif a == "--model" and j + 1 < len(argv):
            model_kind = argv[j + 1]; j += 2
        elif a == "--max-groups" and j + 1 < len(argv):
            max_groups = max(1, int(argv[j + 1])); j += 2
        elif a == "--gids" and j + 1 < len(argv):
            gids_override = [x.strip() for x in argv[j + 1].split(",") if x.strip()]; j += 2
        else:
            sys.stderr.write("未知参数 %r；用法见模块 docstring\n" % a)
            return 2
    out_dir = out_dir or DEFAULT_OUT_DIR
    if not _check_same_drive(out_dir, "--out-dir"):
        return 2

    br = load_br()
    opt = br.opt_mod
    lessons_paths = {
        "work": lessons_override or os.path.join(HERE, "lessons.jsonl"),
        "official": os.path.join(os.path.expanduser("~"), ".dsh", "skills",
                                 "time-blackhole-audit", "lessons.jsonl"),
    }
    if model_kind == "scripted":
        model = ScriptedModel()
    elif model_kind == "headless":
        model = br.HeadlessModel()
    else:
        sys.stderr.write("--model 必须是 headless|scripted\n")
        return 2

    selected, select_meta, rc = resolve_selection(br, opt, select_json, out_dir)
    if rc:
        return rc
    rep, rc = run_quick(selected, lessons_paths, model, out_dir=out_dir,
                        max_groups=max_groups, select_meta=select_meta,
                        gids_override=gids_override, br=br, opt=opt)
    if rc:
        return rc
    for line in rep["summary_lines"]:
        sys.stderr.write(line + "\n")
    sys.stderr.write("OUT_REPORT %s\n"
                     % os.path.join(out_dir, "quick_report.json"))
    print("OUT " + os.path.join(out_dir, "quick_report.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
