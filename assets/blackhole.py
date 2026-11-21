#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""blackhole.py — 会话时间黑洞审计器

读 DSH session 转录，机械算出"哪一步耗时长、产出少"，输出可执行的结论。
时间来自毫秒时间戳；低效是待核实的信号，工具写入不等于任务产出。

用法:
  python blackhole.py                     # 当前会话
  python blackhole.py --session <id|path> # 指定会话
  python blackhole.py --recent 3          # 最近 3 个会话
  python blackhole.py --since 30          # 只看最近 30 分钟的步
  python blackhole.py --json              # 机器可读
  python blackhole.py --brief             # 一句话结论
  python blackhole.py --review            # 结构化复盘材料（Markdown）

2026-11 相对基线的改动（详见 REPORT.md）：
  1. 流式逐行读取（.jsonl 与 .zstd 均不再整份驻留内存）；zstd 截断时恢复可读
     前缀并明确警告，空可读+截断时状态记 partial 而不是 insufficient_data。
  2. 重复调用同时检查"单步内 ≥3 次同参同果"（原来只查跨步）。
  3. 失败循环新增"同文本错误 ≥3 次"聚合触发（同类失败散布不再漏报）。
  4. 事件缺 turn/step 时警告并把状态标为 partial（未知步骤聚合可能失真）。
  5. 修复：edit 调用参数为非 dict JSON（如数组）时的崩溃。
  6. 性能：指纹参数只解析一次、区间只计算一次、段定位改二分、长上下文即拼即截。
  7. 修复：默认示例经验与调用方共享可变列表的隐患（载入一律返回私有副本）。
  8. 新增 --review 复盘导出；--json 增加 window_min 与 holes[].lessons 字段（向后兼容）。
  9. 多帧 zstd 中部帧损坏时跳帧续读（定位下一帧魔数继续，警告注明跳过数）。
 10. 性能：同参数调用复用解析与指纹（重复空转形态的常见路径）。
 11. 修复：损坏时间戳（如 1e18/负值）曾使 --review 单独崩溃（其他模式正常）；
     现降级显示原始毫秒值。
 12. 快路径（帧头声明大小）多帧日志的末帧截断检测：从最后帧魔数重解压
     验证帧边界，截断不再静默当"没有数据"（单帧对账已覆盖，多帧此前漏）。
 13. "同文本错误"/"重复调用输出"聚合把仅首尾空白差异视为同一条（格式
     噪声不构成新信息；时间戳/路径等内容差异仍各自计数）。
 14. --review 增加工具耗时分布；--json 增加 tool_seconds 字段（向后兼容，
     只增不改）。
 15. 新增 --query 报错查经验：--tool+--error（路径归一化）→ 至多一条已验证
     经验（ID/下一步/验证方法）；--query-session 同会话同一错误只提示一次
     （状态存经验库同目录 .query_state/，7 天过期）；--lessons-path 隔离副本。
     审计/报告路径不受影响；经验库本身在 query 中零写入。
"""

import argparse
import bisect
import codecs
import glob
import hashlib
import itertools
import json
import os
import re
import sys
import time
import math
import tempfile
from collections import Counter, defaultdict

# ---------------------------------------------------------------- constants

GAP_MS = 20 * 60 * 1000      # 超过这个间隔视为会话中断/恢复，切分活动段
CROSS_MS = 30 * 60 * 1000    # 单次调用超过这个时长，视为跨段伪影，剔除
# --trend 单次分析上限：实测每个会话约 0.04s（读盘/解压占 86%），
# 100 个约 3.2s、508 个约 18.5s。趋势只需要足够样本，不必全量。
MAX_TREND_SESSIONS = 200
PRODUCTIVE = {"write", "edit", "present"}
# 只读类工具：用于「探索段守卫」判断这段是在读还是空转。
# 实测补充（60 会话工具统计）：OPS 工具族（ops_read_files / ops_inspect_local_file
# / ops_glob / ops_grep / ops_bash）和 read_image / compress 都是读取/检查类。
# 旧集合只有 read/glob/grep/web_*，而本环境主力是 pwsh(3291)+ops_bash(1945)，
# 导致守卫的「读取目标 ≥4」条件几乎永不成立 → 正常调研被误判为空转。
READ_LIKE = {
    "read", "ops_read_files", "glob", "grep", "web_fetch", "web_search",
    "read_image", "compress",
    "ops_inspect_local_file", "ops_glob", "ops_grep",
}
# 命令执行类：既不是明确的「读」（可能写文件），也不是「产出」。
# 用于守卫里区分「在跑命令」和「在空转等待」——连续跑命令通常是在推进。
SHELL_LIKE = {"pwsh", "bash", "ops_bash", "shell", "terminal"}
POLL_LIKE = {"job_output", "job_list"}
# 真能并行的入口。判据同 AGENTS.md：subagent / 并发工具调用 / 后台作业。
DELEGATE_LIKE = {"subagent", "subagent_fork", "spawn_teammate", "workflow"}

# subagent 的结果文本形如 "started subagent <uuid>"，而该 uuid 就是子会话的
# session id —— 能反查到子会话自己的转录，从而取到它的真实活跃时长。
_SUBAGENT_ID_RE = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")

# 一次分析最多读这么多个子会话：--trend 会逐会话复用这段逻辑，
# 不设上限会把一次聚合放大成几百次额外的读盘 + 解压。
MAX_SUBAGENT_LOOKUP = 8

TRUNCATION_WARNING = "压缩日志未完整读出；仅分析已读部分（文件可能仍在写入或被截断）"

# 各信号需要模型/人工核查的问题——脚本不做因果判断，这里把问题问对。
VERIFY_QUESTIONS = {
    "失败循环": "几次失败是否同一根因？完整错误信息指向什么？是继续排查还是换方法？",
    "重复调用": "重复是否拿到了新信息？是否是必要的状态复查？",
    "反复编辑同处": "是局部反复修补还是合理迭代？是否先读全再动手？",
    "无产出长段": "这段产生了哪些可验证的新结论？答不上来就该换方向。",
    "任务轮询": "轮询是否带来新状态？能否降低频率、转后台或并行独立工作？",
    "起后台即阻塞等": "后台任务的唯一价值是等待期间做别的事；起了就等等于同步调用。换成 wait=false 探一次，然后去推进独立工作。",
    "盲等": "这条 sleep 在等什么？如果等的是某个可检查的状态，改成轮询该状态（wait=false 探一次）；如果什么都不等，删掉它。",
    "命令可合并": "这些命令之间有数据依赖吗？没有就合并成一条（cmd1; cmd2）或同一条消息里并发发出——每省一个 LLM 轮次约省 8 秒。",
    "超时转后台": "是正常转后台还是任务范围不当？",
    "串行长调用": "这些同类调用之间是否存在数据依赖？不依赖就该并发；串行是任务必需还是只是写法习惯？",
    "盲改缺验证": "改动之间为什么既没重读也没跑测试？如果这次改动没生效，能否从输出判断卡在哪一步？",
    "串行未并行": "这串调用里是否有互不依赖的项？有就并发（subagent / 后台作业 / 同一条消息多工具），确属依赖链就保持串行。",
    "subagent 串行": "这几个子任务分步起，是不是因为要看上一步的产出？不需要就该在同一条消息里并起——墙钟取 max 而不是 sum。",
    "subagent 闲置": "这段长会话里有没有彼此无数据依赖的独立块？有就下次并起 subagent；确实是单点排查或严格依赖链，不拆是对的。",
}

STATUS_MEANING = {
    "ok": "可分析记录没有触发规则，不代表已经证明高效",
    "review": "存在待核查信号，优先看失败循环，再看其他信号",
    "partial": "数据不完整，现有记录没有触发规则，不能判断整体健康",
    "insufficient_data": "没有可计时的完整步骤，也没有可判读的调用/结果内容",
    "error": "输入或经验库不可读取，审计未完成",
}

_MISSING = object()


class AuditInputError(Exception):
    """输入不可读取，不能把它当作一次健康的审计。"""


class EventBatch(list):
    def __init__(self, events=(), warnings=()):
        super().__init__(events)
        self.warnings = list(warnings)


def _out():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------- utilities

def norm_args(s):
    """完整规范化 JSON；截断仅用于展示，不能参与判重。"""
    if not s:
        return ""
    try:
        o = json.loads(s) if isinstance(s, str) else s
    except Exception:
        return str(s)
    return json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


_ERR_URL_RE = re.compile(r"https?://\S+")
# 路径归一：允许路径内部含空格。
# 旧版用 [^\s'"]* 排除空白，导致 `D:\working area\demo.txt` 被切成
# `D:\working` 和 `area\demo.txt` 两段，归一成 "PATH PATH" ——
# 同一个报错因路径带空格而无法与其它会话聚合（Windows 上极常见：
# 用户主目录就是 D:\working area）。改为「从盘符/斜杠起，向后吞到
# 引号、行尾或明确的分隔符」，内部允许空格。
_ERR_WINPATH_RE = re.compile(r"[A-Za-z]:[\\/][^'\"\r\n,;()\[\]<>|]*")
_ERR_PATH_RE = re.compile(r"[^\s'\"]*[\\/][^'\"\r\n,;()\[\]<>|]*")
_ERR_DIGITS_RE = re.compile(r"\d+")


def norm_err_text(s):
    """失败循环「同文本错误」聚合键：URL/路径 token 归一（数字不归一）。

    口径 = eval/fn_norm2_probe.py 的 n_path(digits=False)。§21 A/B：
    含数字→# 的版本被评估集 4 个冻结边界场景证伪（时间戳/行号/计数器
    递增是内容差异，数字轴 4/4 全 FP）；纯路径轴在 344 真实语料上保留
    全部收益（见 §21 表）。顺序敏感：URL → 盘符路径 → 一般含斜杠 token
    （后者兜住残余斜杠）；strip 由本函数兜底。
    """
    s = _ERR_URL_RE.sub("URL", s)
    s = _ERR_WINPATH_RE.sub("PATH", s)
    s = _ERR_PATH_RE.sub("PATH", s)
    return s.strip()


def _canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash_fp(name, canon):
    return "%s|%s" % (name, hashlib.sha256(canon.encode()).hexdigest())


def fp(name, args):
    """兼容入口：对任意 args 字符串/对象算指纹。内部构建走 build() 的单次解析。"""
    return _hash_fp(name, norm_args(args))


def brief_args(call, n=80):
    """从一次调用里抽出人能看懂的一小段，用于 evidence。
    做匹配时传大 n（命令关键词常在末尾）。"""
    a = call.get("aobj")
    if a is None:
        return (call.get("canon") or "")[:n]   # canon 已是规范化/原文形式，无需再解析
    if isinstance(a, dict):
        for k in ("command", "cmd", "file_path", "path", "url", "job_id", "pattern"):
            v = a.get(k)
            if v:
                v = str(v).replace("\n", " ").strip()
                return v[:n]
    return _canon(a)[:n]


def fmt_dur(sec):
    """人类可读时长。

    单位切换点要注意「显示进位」：旧实现里 3599s 会显示成 "60.0min"——
    数值上没错，但读者会以为该进到小时。现在提前 30 秒切换，让每个
    单位区间内的显示值都不会越界到下一单位的上限。
    """
    sec = float(sec)
    if sec < 59.5:              # 59.5s 起改用分钟，避免 %.0f 进位成 "60s"
        return "%.0fs" % sec
    if sec < 3570:              # 59.5min 起改用小时，避免显示 "60.0min"
        return "%.1fmin" % (sec / 60.0)
    return "%.2fh" % (sec / 3600.0)


def session_files():
    home = os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh"))
    files = []
    for suffix in ("*.jsonl.zstd", "*.jsonl"):
        files.extend(glob.glob(os.path.join(home, "sessions", "*", "*", suffix)))
    # 同一个 session 的格式版本/副本不能算成多个独立会话。
    def _mtime(p):
        try:
            return os.path.getmtime(p)   # glob 与取 mtime 之间文件可能被清理
        except OSError:
            return 0.0
    selected = {}
    for path in sorted(set(files), key=_mtime, reverse=True):
        selected.setdefault(os.path.dirname(path), path)
    return list(selected.values())


def find_session(spec=None):
    if spec and os.path.isfile(spec):
        return spec
    files = session_files()

    if spec:
        # 路径形态必须是文件；传目录要明确报错，不能靠子串瞎匹配。
        # 实测：--session C:\...\.dsh\sessions 会子串命中全部 508 个文件，
        # 然后静默返回第一个（最新会话）——用户以为在审计指定会话，
        # 实际看到的是别处的数据。这种静默错误比报错更危险。
        if os.path.exists(spec) and os.path.isdir(spec):
            raise AuditInputError(
                "--session 需要会话 id 或日志文件路径，不是目录：%s" % spec)
        # 带路径分隔符但文件不存在 → 明确报错，不做子串猜测
        if ("/" in spec or "\\" in spec) and not os.path.isfile(spec):
            raise AuditInputError("日志文件不存在：%s" % spec)
        hits = [f for f in files if spec in f]
        if not hits:
            return None
        if len(hits) > 1:
            # 多个候选时，只有「恰好一个目录名等于该 id」才算无歧义。
            exact = [f for f in hits
                     if os.path.basename(os.path.dirname(f)) == spec
                     or os.path.basename(os.path.dirname(f)) == "session-" + spec]
            if len(exact) == 1:
                return exact[0]
            raise AuditInputError(
                "--session %r 匹配到 %d 个会话，无法确定是哪一个；"
                "请给更完整的会话 id 或日志路径" % (spec, len(hits)))
        return hits[0]

    sid = os.environ.get("DSH_SESSION_ID", "")
    if sid:
        key = sid.replace("session-", "")
        hits = [f for f in files if key in f]
        return hits[0] if hits else None
    return files[0] if files else None


# ---------------------------------------------------------------- reading

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"          # zstd 帧头魔数（LE）
_ZSTD_SKIP_FIX = b"\x2a\x4d\x18"           # skippable frame magic 0x184D2A50..5F 的固定后缀（LE）


def _skippable_chain_ok(buf):
    """eof 后的剩余字节必须是完整的 skippable 帧链，否则视为截断。"""
    i = 0
    while i < len(buf):
        if i + 8 > len(buf) or not (0x50 <= buf[i] <= 0x5F) or buf[i + 1:i + 4] != _ZSTD_SKIP_FIX:
            return False
        i += 8 + int.from_bytes(buf[i + 4:i + 8], "little")
    return True


def _ends_at_frame_boundary(dctx, fh, size):
    """验证文件以完整 zstd 帧结尾（快路径末帧截断检测）。

    stream_reader(read_across_frames=True) 在末帧被截断时静默返回部分输出
    而不报错，且帧头声明大小只是第 1 帧的——无法用总量对账发现。这里从
    最后一个帧魔数起重新解压到 EOF：解压失败或 eof 后残留无法解释的字节
    即为截断。候选取从后向前的最多 8 个魔数（帧载荷内的假魔数会解压失败
    自动跳过；真实帧起点必然在候选内）。仅在多帧+声明大小场景调用，
    代价为重解压最后一帧。
    """
    import zstandard
    if size <= 0:
        return True
    cands = []
    CH = 1 << 20
    end = size
    while end > 0 and len(cands) < 8:
        start = max(0, end - CH - 3)      # 多读3字节，魔数跨块边界也能找全
        fh.seek(start)
        chunk = fh.read(end - start)
        off = len(chunk)
        while off >= 4 and len(cands) < 8:
            off = chunk.rfind(_ZSTD_MAGIC, 0, off)
            if off == -1:
                break
            p = start + off
            if not cands or p < cands[-1]:
                cands.append(p)
        end = start
    for p in cands:
        fh.seek(p)
        dobj = dctx.decompressobj()
        tail = b""
        try:
            while True:
                c = fh.read(CH)
                if not c:
                    break
                if dobj.eof:
                    tail += c
                    continue
                dobj.decompress(c)
        except zstandard.ZstdError:
            continue                      # 假魔数/损坏起点：试更早的候选
        if dobj.eof and _skippable_chain_ok((dobj.unused_data or b"") + tail):
            return True
    return False


def _plain_lines(path):
    """逐行产出文本：分块读盘+增量解码，避免整份文本与行列表同时驻留。"""
    dec = codecs.getincrementaldecoder("utf-8")("replace")
    buf = ""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            buf += dec.decode(chunk)
            if "\n" in buf:
                *lines, buf = buf.split("\n")
                for ln in lines:
                    yield ln
        buf += dec.decode(b"", final=True)
        if buf:
            yield buf


def _zstd_lines(path, warnings):
    """zstd 增量解压逐行产出。截断/正在写入的文件：恢复可读前缀并警告。

    截断判定：帧头声明了内容大小时，用解压总量与之对账（快路径，
    stream_reader 速度）；无声明大小（如流式写入中）用 decompressobj
    的 eof 标志判定（慢约1.7s/10万事件，但可靠）。绝不能把半份日志
    当成"没有数据"。
    """
    try:
        import zstandard
    except ImportError:
        raise AuditInputError("需要 zstandard: pip install zstandard")

    try:
        fh = open(path, "rb")
    except OSError as exc:
        raise AuditInputError("无法读取日志: %s" % exc) from exc
    with fh:
        head = fh.read(18)
        try:
            declared = zstandard.frame_content_size(head)
        except Exception:
            declared = -1
        fh.seek(0)
        dctx = zstandard.ZstdDecompressor()
        dec = codecs.getincrementaldecoder("utf-8")("replace")
        state = {"buf": "", "produced": False, "total_out": 0, "broken": False}

        def emit(text):
            buf = state["buf"] + text
            lines = []
            if "\n" in buf:
                *lines, buf = buf.split("\n")
            state["buf"] = buf
            return lines

        if declared is not None and declared >= 0:
            # 快路径：读完与帧头声明的字节数对账。
            # size 在读取前取样：stream_reader 的 with 退出会关闭 fh
            # （closefd 默认 True），且与"单次读取按快照分析"语义一致。
            fsize = os.fstat(fh.fileno()).st_size
            try:
                with dctx.stream_reader(fh, read_across_frames=True, closefd=False) as r:
                    while True:
                        c = r.read(1 << 20)
                        if not c:
                            break
                        state["produced"] = True
                        state["total_out"] += len(c)
                        for ln in emit(dec.decode(c)):
                            yield ln
            except zstandard.ZstdError:
                if not state["produced"]:
                    raise AuditInputError("无法解压日志: 帧不完整或数据损坏") from None
                state["broken"] = True
            truncated = state["total_out"] < declared
            if not truncated and not state["broken"] and state["total_out"] > declared:
                # 多帧+声明大小：帧头声明只是第1帧的，总量对账发现不了
                # 末帧截断（stream_reader 对部分末帧静默返回不报错）——验证帧边界。
                if not _ends_at_frame_boundary(dctx, fh, fsize):
                    truncated = True
        else:
            # 慢路径：无声明大小（流式写入的帧）。DSH 实际日志是多帧拼接
            # （stream_writer 每次落盘一帧），必须逐帧循环：帧结束（eof）后
            # 用 unused_data 的剩余字节开新解压器继续。文件末尾停在帧中间
            # 即截断（写入中或被切），恢复全部完整帧并警告。
            # 中部帧损坏：定位下一帧魔数（zstd magic 0xFD2FB528 LE）跳帧续读；
            # 魔数落在损坏载荷内属误报，解压会再次失败并继续向后跳，自纠错。
            dobj = dctx.decompressobj()
            pending = b""
            complete = False
            total_in = 0
            skipped = 0
            give_up = False
            recovering = False
            eof = False
            MAGIC = b"\x28\xb5\x2f\xfd"
            MAX_SKIP = 256
            while True:
                if not eof:
                    chunk = fh.read(1 << 20)
                    total_in += len(chunk)
                    if not chunk:
                        eof = True
                    else:
                        pending += chunk
                if eof and not pending:
                    break
                if recovering:
                    k = pending.find(MAGIC, 1)
                    if k == -1:
                        if eof:
                            break           # 尾部无更多帧起点
                        continue            # 等更多数据再找
                    pending = pending[k:]
                    dobj = dctx.decompressobj()
                    dec = codecs.getincrementaldecoder("utf-8")("replace")
                    state["buf"] = ""       # 丢弃损坏帧残留的半行
                    complete = False
                    recovering = False
                while pending:
                    try:
                        c = dobj.decompress(pending)
                    except zstandard.ZstdError as exc:
                        if not state["produced"]:
                            raise AuditInputError("无法解压日志: %s" % exc) from exc
                        state["broken"] = True   # 已有可读帧，保留并警告
                        skipped += 1
                        if skipped > MAX_SKIP:
                            give_up = True
                        else:
                            recovering = True
                        break
                    if c:
                        state["produced"] = True
                        for ln in emit(dec.decode(c)):
                            yield ln
                    if dobj.eof:
                        complete = True
                        pending = dobj.unused_data or b""
                        if pending:
                            dobj = dctx.decompressobj()
                    else:
                        complete = False
                        pending = b""
                if give_up:
                    break
            truncated = total_in > 0 and not complete
            if skipped:
                warnings.append(
                    "压缩日志未完整读出：跳过 %d 个损坏帧，已恢复其余可读部分" % skipped)
        buf = state["buf"] + dec.decode(b"", final=True)
        if buf:
            yield buf
        if truncated or state["broken"]:
            warnings.append(TRUNCATION_WARNING)


def read_events(path):
    """逐行读取 + 解析成事件列表；不把整份文本留在内存里。"""
    warnings = []
    if path.endswith(".jsonl"):
        lines = _plain_lines(path)
    else:
        zwarnings = []
        lines = _zstd_lines(path, zwarnings)

    evs = []
    invalid = 0
    try:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                # DSH 首行是没有事件时间戳的会话头，属于正常元数据。
                if (isinstance(event, dict) and event.get("type") == "session"
                        and isinstance(event.get("id"), str) and isinstance(event.get("version"), int)):
                    continue
                if (not isinstance(event, dict) or isinstance(event.get("time"), bool)
                        or not isinstance(event.get("time"), (int, float))
                        or not math.isfinite(event["time"])
                        or (event.get("data") is not None and not isinstance(event["data"], dict))):
                    invalid += 1
                    continue
                evs.append(event)
            except Exception:
                invalid += 1
                continue
    except AuditInputError:
        raise
    except OSError as exc:
        raise AuditInputError("无法读取日志: %s" % exc) from exc
    if not path.endswith(".jsonl"):
        warnings.extend(zwarnings)
    if invalid:
        warnings.append("跳过 %d 条无效/不完整日志记录" % invalid)
    return EventBatch(evs, warnings)


# ---------------------------------------------------------------- parsing

def build(evs):
    """单遍构建调用/结果/步骤索引。

    arguments 只解析一次：解析成功存 aobj（指纹用其规范化形式现算现弃），
    解析失败存 canon=原文并按原文指纹。返回值含缺 turn/step 的事件数。
    """
    calls = {}     # callId -> dict
    results = {}   # callId -> dict
    steps = {}     # (turn, step) -> dict
    missing_keys = 0
    fp_memo = {}   # (name, arguments原文) -> (aobj, canon, fp)；仅本次 analyze 内有效

    for e in evs:
        t = e.get("type")
        d = e.get("data") or {}
        ts = e.get("time")

        if t == "step/start":
            turn, no = d.get("turn"), d.get("step")
            if turn is None or no is None:
                missing_keys += 1
            k = (turn, no)
            s = steps.setdefault(k, {"calls": []})
            s["start"] = ts
            s["turn"] = turn
        elif t == "step/end":
            turn, no = d.get("turn"), d.get("step")
            if turn is None or no is None:
                missing_keys += 1
            k = (turn, no)
            s = steps.setdefault(k, {"calls": []})
            s["end"] = ts
        elif t == "tool/call":
            cid = d.get("callId")
            if d.get("turn") is None or d.get("step") is None:
                missing_keys += 1
            name = d.get("name")
            if not isinstance(name, str):
                # 损坏日志里 name 可能缺失或为非字符串：归一为字符串，保证排序/指纹稳定
                name = "" if name is None else str(name)
            raw = d.get("arguments") or ""
            aobj = None
            canon = None     # aobj 可用时为 None（指纹现算现弃）；否则存规范化替代
            if not raw:
                canon = ""
                fp_hex = _hash_fp(name, canon)
            elif isinstance(raw, str):
                hit = fp_memo.get((name, raw))
                if hit is not None:
                    # 同参数串重复出现（轮询/空转的典型形态）：复用解析与指纹。
                    # aobj 是只读共享对象——所有使用点均为 .get() 读取，禁止就地修改。
                    aobj, canon, fp_hex = hit
                else:
                    try:
                        aobj = json.loads(raw)
                    except Exception:
                        canon = str(raw)
                    if canon is None:
                        fp_hex = (_hash_fp(name, _canon(aobj))
                                  if aobj is not None else _hash_fp(name, ""))
                    else:
                        fp_hex = _hash_fp(name, canon)
                    if len(fp_memo) < 200000:
                        fp_memo[(name, raw)] = (aobj, canon, fp_hex)
            elif isinstance(raw, (dict, list)):
                aobj = raw
                fp_hex = _hash_fp(name, _canon(aobj))
            else:
                canon = str(raw)
                fp_hex = _hash_fp(name, canon)
            calls[cid] = {
                "id": cid, "name": name,
                "aobj": aobj, "canon": canon, "time": ts,
                "turn": d.get("turn"), "step": d.get("step"),
                "fp": fp_hex,   # 只算一次，下游复用
            }
            sk = (d.get("turn"), d.get("step"))
            steps.setdefault(sk, {"calls": []})["calls"].append(cid)
        elif t == "tool/result":
            m = d.get("message") or {}
            if not isinstance(m, dict):
                continue
            cid = m.get("toolCallId") or d.get("toolCallId")
            txt = ""
            for b in (m.get("content") or []):
                if isinstance(b, dict) and b.get("type") == "text":
                    v = b.get("text")
                    if isinstance(v, str):    # 损坏日志的非字符串 text 块跳过，不崩溃
                        txt += v
            results[cid] = {
                "id": cid, "time": ts, "error": bool(m.get("isError")),
                "text": txt, "meta": d.get("meta") or {},
            }

    return calls, results, steps, missing_keys


def segments(evs):
    """按 gap 切活动段，剔除跨中断的伪影。"""
    times = sorted(x["time"] for x in evs if isinstance(x.get("time"), (int, float)))
    if not times:
        return []
    segs, cur = [], [times[0]]
    for a, b in zip(times, times[1:]):
        if b - a > GAP_MS:
            segs.append((cur[0], cur[-1]))
            cur = [b]
        else:
            cur.append(b)
    segs.append((cur[0], cur[-1]))
    return segs


class SegIndex:
    """活动段的二分定位：段按构造有序且互不重叠。"""
    __slots__ = ("segs", "_starts")

    def __init__(self, segs):
        self.segs = segs
        self._starts = [s for s, _ in segs]

    def same(self, a, b):
        i = bisect.bisect_right(self._starts, a) - 1
        if i < 0:
            return False
        return b <= self.segs[i][1]


def in_same_seg(idx, a, b):
    return idx.same(a, b)


def interval_seconds(intervals):
    """区间并集的墙钟秒数，串行相加、并行重叠只计一次。"""
    end = None
    total = 0.0
    for a, b in sorted(intervals):
        if b <= a:
            continue
        total += max(0, b - max(a, end if end is not None else a))
        end = max(b, end if end is not None else b)
    return total / 1000.0


def tool_interval(call, result, idx, horizon):
    if result is None:
        return None
    a, b = call.get("time"), result.get("time")
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return None
    if b < a or b - a >= CROSS_MS or not idx.same(a, b):
        return None
    return max(a, horizon), b


def _is_doc_file(path):
    """文档/数据类文件：改动它们不需要「跑测试验证」，不适用盲改检测。

    实测：29 次盲改误报集中在 .md（README 等）。改文档的验证方式是读，
    而读文档和跑测试是两码事——不能因为没跑测试就判「盲改」。
    """
    ext = os.path.splitext(path)[1].lower()
    return ext in (".md", ".markdown", ".txt", ".rst", ".adoc", ".json",
                   ".yaml", ".yml", ".toml", ".ini", ".cfg", ".csv", ".tsv",
                   ".log", ".html", ".css", ".svg")


_TIMEOUT_MARK = "still running after"


def is_timeout_result(text):
    """结果是否为「命令跑满 timeout、任务仍在跑」。

    不能只看子串：审计文档里就写着这个短语（SKILL.md 的规则表列了
    「结果包含 `still running after`」），于是读该文件时自己触发检测。
    实测 20 会话里这类误报占 42%。

    真实提示是短的、结构化的；文件内容是带行号/标签的大段文本。
    排除：含 Markdown 表格竖线 + 行号的引用、含文件读取标签、超长文本。
    """
    if not text or _TIMEOUT_MARK not in text:
        return False
    if "<content>" in text or "<path>" in text or "<type>file" in text:
        return False
    # 读到文档段落：行号前缀 "  N: " 或 Markdown 表格 "| ... |"
    if re.search(r"(^|\n)\s*\d+[:|]", text) or text.count("|") >= 2:
        return False
    # 真实超时提示很短；超过 400 字符基本是文件内容
    if len(text) > 400:
        return False
    return True


def _md_inline(text):
    """把可能含换行的用户内容压成单行，避免破坏 Markdown 结构。

    经验库的 fix/boundary 由用户写入，可能含换行、行首 `###`、`- ` 等。
    若原样拼进 review 的行内列表项，第二行会变成独立的结构元素
    （实测 `fix="正常说明\\n### 我是伪标题"` 会让伪标题成为真正的三级标题）。

    处理：换行折成空格并压缩连续空白；不做 HTML 实体转义
    （review 是给人读的，`**粗体**` 之类保留原样更可读）。
    """
    if text is None:
        return ""
    return " ".join(str(text).split())


# 经验文本在终端/复盘里的显示上限（截断阈值）。
# 依真实库标定：28 条经验的 fix 长度中位 147、p90 225、max 254。
# 阈值 220 会截断 4 条（14%）完整经验——太紧；300 以上零误伤。
FIX_MAX_CHARS = 300
# 落库时的硬上限（防止 10 万字符把库撑爆）。这是「要不要写进去」，
# 与上面的「显示时截多长」是两件事：落库保留更多，显示再截。
FIELD_MAX_CHARS = 4000


def _clip_field(text, limit=FIELD_MAX_CHARS):
    """落库前裁剪超长字段，防止单条经验把库撑爆。

    实测：--evidence / --boundary 曾可写入 10 万字符。真实库中这两个字段
    max 分别是 114 / 297 字，4000 的上限对正常使用完全无感。
    """
    if text is None:
        return None
    s = str(text)
    if len(s) <= limit:
        return s
    return s[:limit] + "…（已截断，原文 %d 字）" % len(s)


def _short(text, limit=FIX_MAX_CHARS):
    """单行化 + 超长截断，用于把经验文本嵌进一行输出。

    截断后加省略号并标注原长度，让读者知道还有内容被省掉了
    （而不是以为这条经验就这么短）。
    """
    s = _md_inline(text)
    if len(s) <= limit:
        return s
    return s[:limit].rstrip() + "…（共 %d 字）" % len(s)


def _capped_ctx(parts, cap):
    """即拼即截：产出与先全量拼接再 [:cap] 相同的前缀，但峰值内存有界。"""
    out = []
    total = 0
    for s in parts:
        out.append(s)
        total += len(s) + 1
        if total >= cap:
            break
    return " ".join(out)[:cap]


# ---------------------------------------------------------------- audit memory
#
# 跨轮次记忆：同一个会话里同一种 kind 被报过几次。用来区分「习惯问题」和
# 「偶发」——第 2 次出现时明确说"上次已提示过"。
# 状态存 <经验库同目录>/.audit_state/，与 .query_state 同一套约定：
# 原子替换写、不加锁、TTL 过期。审计本身仍然零写入经验库。

AUDIT_STATE_TTL_SEC = 30 * 24 * 3600
AUDIT_STATE_KEEP_RUNS = 5      # 每个 kind 只留最近几条，避免状态文件无限长


def _audit_state_dir():
    return os.path.join(os.path.dirname(LESSONS_PATH), ".audit_state")


def _audit_state_path(lessons_path=None, session=None):
    """跨轮次提醒的状态文件路径。

    必须同时以「经验库」和「会话」为 key：文案说的是「这是**本会话**第 N 次」，
    若只按经验库哈希，审计会话 A 的记录会污染会话 B 的计数
    （实测曾出现「本会话第 6 次」但该会话只审计过一次）。
    """
    raw = os.path.abspath(lessons_path or LESSONS_PATH)
    if session:
        raw = raw + "\0" + session
    key = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return os.path.join(_audit_state_dir(), key + ".json")


def load_audit_history(lessons_path=None, session=None):
    """读本会话的历史审计记录：{kind: [时间戳, ...]}。"""
    try:
        with open(_audit_state_path(lessons_path, session), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(doc, dict) or not isinstance(doc.get("kinds"), dict):
        return {}
    now = time.time()
    out = {}
    for kind, stamps in doc["kinds"].items():
        if not isinstance(stamps, list):
            continue
        keep = [t for t in stamps if isinstance(t, (int, float))
                and now - t <= AUDIT_STATE_TTL_SEC]
        if keep:
            out[kind] = keep[-AUDIT_STATE_KEEP_RUNS:]
    return out


def record_audit_history(kinds, lessons_path=None, session=None):
    """把本次报出的 kind 追加进历史。审计默认只读，这个写是刻意的最小状态。"""
    if not kinds:
        return
    path = _audit_state_path(lessons_path, session)
    history = load_audit_history(lessons_path, session)
    now = time.time()
    for kind in kinds:
        history.setdefault(kind, []).append(now)
        history[kind] = history[kind][-AUDIT_STATE_KEEP_RUNS:]
    d = _audit_state_dir()
    try:
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="astate-", suffix=".tmp", dir=d)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"kinds": history}, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    except OSError:
        pass      # 状态写失败不影响审计结论


def annotate_recurrence(holes, lessons_path=None, session=None):
    """给重复出现的 kind 加一句「上次已提示过」。就地修改 detail。"""
    if not holes:
        return
    history = load_audit_history(lessons_path, session)
    for h in holes:
        prior = len(history.get(h["kind"], []))
        if prior >= 1:
            h["detail"] = "%s ⚠ 这是本会话第 %d 次出现「%s」——上次已提示过，说明是习惯问题不是知识问题" % (
                h.get("detail", ""), prior + 1, h["kind"])


def parallel_profile(calls, rows, results):
    """窗口内的并行度画像。

    三个可机械判定的维度：
      subagent   —— 委派类的调用次数（真并行能力的最强证据）
      background —— run_in_background=true 的调用次数
      concurrent_steps —— 单步内 ≥2 个工具调用的步数（真正的并发执行）

    只统计有结果的调用，避免把"发起了但没记录"算成并行。
    """
    n_calls = len(calls)
    subagent = 0
    background = 0
    for cid, c in calls.items():
        if results.get(cid) is None:
            continue
        if c["name"] in DELEGATE_LIKE:
            subagent += 1
            continue
        aobj = c.get("aobj")
        if isinstance(aobj, dict) and aobj.get("run_in_background") is True:
            background += 1

    concurrent_steps = sum(1 for r in rows if len(r["fps"]) >= 2)
    single_steps = sum(1 for r in rows if len(r["fps"]) == 1)

    # 最长连续单工具步：期间完全没有并发机会被利用
    longest_n, longest_s, longest_a, longest_b = 0, 0.0, 0, 0
    i = 0
    while i < len(rows):
        if len(rows[i]["fps"]) != 1:
            i += 1
            continue
        j = i
        while j + 1 < len(rows) and len(rows[j + 1]["fps"]) == 1:
            j += 1
        span = sum(r["dur"] for r in rows[i:j + 1])
        if j - i + 1 > longest_n:
            longest_n, longest_s, longest_a, longest_b = j - i + 1, span, i, j
        i = j + 1

    return {
        "calls": n_calls,
        "subagent": subagent,
        "background": background,
        "concurrent_steps": concurrent_steps,
        "single_steps": single_steps,
        "longest": (longest_n, longest_s, longest_a, longest_b),
        "steps": len(rows),
    }


def _parallel_hole(para, rows, calls, total):
    """串行未并行：三条触发条件任一满足即报，措辞一律是「问一句」。

    阈值偏保守（宁可少报）：依赖链串行是完全正常的形态，误报会让
    审计结果被忽略，比漏报更贵。
    """
    n_calls = para["calls"]
    n_delegate = para["subagent"] + para["background"]
    longest_n, longest_s, a, b = para["longest"]
    n_steps = para["steps"]

    if n_steps == 0:
        return None

    # 并行入口的占比：偶尔跑一次 subagent 不代表有并发习惯，
    # 所以看比例而不是「有没有」。
    delegate_ratio = (n_delegate / n_calls) if n_calls else 0.0
    concurrent_ratio = (para["concurrent_steps"] / n_steps) if n_steps else 0.0

    # 1) 调用够多，却几乎没用过任何并行能力：
    #    subagent/后台占比 <2% **且** 并发步占比 <6%。
    #    两个条件缺一不可——只看 subagent 会误报（实测 session-24fffc08：
    #    subagent 0 但有 84 个并发步 = 36%，它确实在并行）；
    #    只看并发步也会误报（session-e63ad746：subagent 2 次但并发步 117 个）。
    #    绝对次数兜底：超过 20 次并行入口说明有并发习惯，比例再低也不算"未并行"
    #    （超大会话里 2% 是几十次，不该判它不会并行）。
    no_parallel_habit = n_delegate <= 20
    gate_a = (n_calls >= 40 and delegate_ratio < 0.02
              and concurrent_ratio < 0.06 and no_parallel_habit)
    # 2) 一长串单工具步（≥20 次、≥180s），且并发步占比 <5%（几乎全程串行），
    #    并且这串长度占全部步骤 ≥40% —— 排掉长会话里的一小段局部串行
    #    （session-e63ad746 的 71/2770 步）。
    #    不用「占窗口耗时 50%」：串行步通常短，按时间会低估（78943bed 是 42%，
    #    但那 122 步串行确实是它的主要形态）。
    gate_b = (longest_n >= 20 and longest_s >= 180.0
              and concurrent_ratio < 0.05 and longest_n >= 0.4 * n_steps
              and no_parallel_habit)

    # 3) 「可并行证据」门槛（全量 506 会话标定）
    #    实测：只靠上面两条，16%（81/506）的会话都会触发——因为
    #    ops_bash→write→ops_bash 这种「跑命令再写文件」的严格串行链
    #    在多数任务里就是正常形态。触发率 16% 等于没有区分度。
    #
    #    真能并行的形态是「N 个同质独立项」：同一个工具被调用很多次、
    #    步步之间不是依赖关系。所以要求在同质调用上：
    #      - 有一个工具占总调用 ≥40%（说明在重复做同类事，而非多样流水线）
    #      - 且该工具调用 ≥6 次（够组成一组 N 项）
    #      - 且没有 subagent/后台（否则已经在用并行）
    #    「跑命令→写文件」这类交替形态不满足单工具 ≥40%，因此不报。
    tool_counts = Counter()
    for c in calls.values():
        tool_counts[c["name"]] += 1
    top_tool, top_n = (tool_counts.most_common(1)[0] if tool_counts else ("", 0))
    homogeneous = (n_calls > 0 and top_n / n_calls >= 0.4 and top_n >= 6)
    if not homogeneous:
        return None
    if not (gate_a or gate_b):
        return None

    pct = lambda v: "%d%%" % (100.0 * v / n_calls) if n_calls else "0%"
    if gate_b and longest_n >= 20:
        seg = rows[a:b + 1]
        span_desc = "连续 %d 次单工具步、累计 %s — T%s.S%s → T%s.S%s" % (
            longest_n, fmt_dur(longest_s), seg[0]["turn"], seg[0]["step"],
            seg[-1]["turn"], seg[-1]["step"])
        sev = longest_s
        seg_keys = {(r["turn"], r["step"]) for r in seg}
        ctx_src = [c for c in calls.values() if (c.get("turn"), c.get("step")) in seg_keys]
    else:
        span_desc = "%d 次工具调用全程无 subagent、无后台作业" % n_calls
        sev = total
        ctx_src = list(calls.values())

    # 采样：挑几条能让人判断「这些是不是独立任务」的调用
    sample = [brief_args(c, 160) for c in ctx_src[:4] if c]

    return {
        "kind": "串行未并行",
        "sev": sev,
        "ratio": sev / total if total else 0,
        # 优先级：全量 506 会话标定后降到 0。
        # 「串行」本身不是缺陷——多数任务的真实形态就是
        # ops_bash→write→ops_bash 的串行链。实测 16% 会话都命中，
        # 且 75% 排在第一位，会把真正的信号（失败循环/超时）挤到后面。
        # 降到最低优先级：仍然如实列出并给出建议，但不抢注意力、
        # 不被当成「结论」里的第一优先项。
        "priority": 0,
        "evidence": "并行度: subagent %s（%d 次）/ 后台 %s（%d 次）/ 并发步 %d；%s" % (
            pct(para["subagent"]), para["subagent"],
            pct(para["background"]), para["background"],
            para["concurrent_steps"], span_desc),
        "detail": "单工具步 %d / 共 %d 步；这串调用里是否本来就互不依赖？"
                  "严格依赖链（改代码→编译→测试→重启）串行是正常的，不需要硬拆" % (
                      para["single_steps"], n_steps),
        "action": "核实这串调用里有没有**互不依赖**的独立项：多组验证用例 → asyncio.gather 或 N 个后台作业；"
                  "多个独立文件读取 → 同一条消息里并发多个工具；独立子任务 → 并发发多个 subagent。"
                  "确属依赖链就保持串行，本信号不必处理",
        "tools": sorted({c["name"] for c in ctx_src}),
        "ctx": _capped_ctx(itertools.chain(["串行 未并行 并发 subagent 后台作业"],
                                           iter(sample)), 1200),
    }


# ---------------------------------------------------------------- subagent 串行


def _step_key_adjacent(a, b):
    """两个 (turn, step) 是否同一轮里紧邻。

    只有紧邻的步才可能是「本该并起、却分两次发」。跨轮或跳跃的间隔
    更可能是「看到上一步结果才决定起下一个」，那是真依赖，不能算浪费。
    """
    return (isinstance(a[0], int) and isinstance(b[0], int) and a[0] == b[0]
            and isinstance(a[1], int) and isinstance(b[1], int)
            and b[1] == a[1] + 1)


def _child_active_seconds(child_id, index, cache, depth):
    """子会话的活跃秒数；读不到返回 None。cache 让同一次分析内不重复读。"""
    if child_id in cache:
        return cache[child_id]
    value = None
    path = index.get(child_id)
    if path is not None:
        try:
            rep = analyze(read_events(path), _depth=depth + 1)
            if rep.get("status") != "insufficient_data":
                value = float(rep.get("active") or 0.0)
        except Exception:
            value = None
    cache[child_id] = value
    return value


def _subagent_serial_hole(calls, results, total, depth=0):
    """subagent 串行：分步起 N 个本可一条消息并起的子任务。

    为什么单列这一类：subagent 调用是 fire-and-forget（约 0.1 秒返回
    started subagent <id>），墙钟成本不在父会话的调用时长里，而在子会话本身。
    N 个互不依赖的子任务并起 → 墙钟取 max；分步串起 → 取 sum。
    损失 = sum - max，这才是可回收的那一段——父会话自己量不出来，
    必须反查子会话的 active。

    只在「同一轮里紧邻的步」之间认定；同一步 >=2 个说明已经并起了，不计损失。
    读不到子会话时长时保守跳过，不猜。
    """
    per_step = {}
    for c in calls.values():
        if c["name"] not in DELEGATE_LIKE:
            continue
        r = results.get(c["id"])
        if r is None:
            continue
        mt = _SUBAGENT_ID_RE.search(r.get("text") or "")
        if not mt:
            continue
        key = (c.get("turn"), c.get("step"))
        per_step.setdefault(key, []).append((c, mt.group(1)))
    if not per_step:
        return None

    ordered = sorted(per_step.keys(),
                     key=lambda k: (k[0] if isinstance(k[0], int) else 0,
                                    k[1] if isinstance(k[1], int) else 0))
    runs = []
    cur = []
    prev = None
    for key in ordered:
        items = per_step[key]
        if len(items) >= 2:                     # 已并起，所在段断开
            if len(cur) >= 2:
                runs.append(cur)
            cur, prev = [], key
            continue
        if cur and prev is not None and not _step_key_adjacent(prev, key):
            if len(cur) >= 2:
                runs.append(cur)
            cur = []
        cur.append(items[0])
        prev = key
    if len(cur) >= 2:
        runs.append(cur)
    if not runs:
        return None

    index = {}
    for p in session_files():
        try:
            index[rid_of(p).replace("session-", "")] = p
        except Exception:
            continue

    cache = {}
    loss = 0.0
    known = []
    for run in runs:
        durs = []
        for _c, cid in run:
            if len(cache) >= MAX_SUBAGENT_LOOKUP:
                break
            d = _child_active_seconds(cid, index, cache, depth)
            if d is None:
                break
            durs.append(d)
        if len(durs) >= 2:
            saved = sum(durs) - max(durs)
            loss += saved
            known.append((len(durs), saved))
    if not known or loss < 60.0:
        return None

    longest = max(known, key=lambda x: x[1])
    return {
        "kind": "subagent 串行",
        "sev": loss,
        "ratio": loss / total if total else 0.0,
        "evidence": "%d 段分步启动的 subagent（最长一段 %d 个），并起可省 %s" % (
            len(known), longest[0], fmt_dur(loss)),
        "detail": "subagent 调用约 0.1 秒返回子会话 id，墙钟成本在子会话本身；"
                  "N 个互不依赖的子任务分步串起，墙钟是 sum 不是 max",
        "action": "确认这些子任务之间没有数据依赖（不需要看上一步产出再决定下一步）："
                  "无依赖就在**同一条消息里并发发起 N 个 subagent**，墙钟取最大值。"
                  "有依赖（A 的结论是 B 的输入）就保持串行，本信号不必处理",
        "tools": sorted({c["name"] for run in runs for c, _cid in run}),
        "ctx": _capped_ctx(itertools.chain(
            ["subagent 串行 并发 并行"],
            (brief_args(c, 160) for run in runs[:2] for c, _cid in run[:2])), 1200),
    }



# 「subagent 闲置」门槛：会话要长到值得分工才报。短会话拆了反而更慢，
# 误报会让审计本身失去可信度。
SUBAGENT_IDLE_MIN_ACTIVE = 3600.0
SUBAGENT_IDLE_MIN_CALLS = 100


def _subagent_idle_hole(para, active, total_calls, rows, tool_t, calls,
                        has_parallel_hole):
    """subagent 闲置：长会话全程零委派。

    这一条不是「实时可回收的等待」（那类由串行未并行判定），而是**规模维度的
    结构性事实**：会话已经长到值得分工，却一次都没把子问题交出去。所以 sev
    固定为 0，不计入速度总账，只作提示——把它算进可回收时长会把提示夸大成
    不存在的浪费。

    门槛刻意偏高：≥60 分钟活跃且 ≥100 次工具调用。串行未并行已经报过同类
    问题时不重复报，避免对同一个会话打两枪。
    """
    if para.get("subagent", 0) > 0:
        return None
    if active < SUBAGENT_IDLE_MIN_ACTIVE:
        return None
    if total_calls < SUBAGENT_IDLE_MIN_CALLS:
        return None
    if has_parallel_hole:
        return None

    top = sorted(tool_t.items(), key=lambda kv: -kv[1])[:4]
    # tool_t 存的是秒不是次数，标清单位，否则读成「调用了 5029 次」
    tool_desc = ", ".join("%s %.0fmin" % (k, v / 60.0) for k, v in top) or "（无计时数据）"
    return {
        "kind": "subagent 闲置",
        "sev": 0.0,
        "ratio": 0,
        "priority": 0,
        "evidence": "会话活跃 %.0f 分钟、%d 次工具调用、%d 步，全程 0 次 subagent；主要工具 %s" % (
            active / 60.0, total_calls, len(rows), tool_desc),
        "detail": "整段长会话没有把任何子问题交出去：调查、修改、验证全挤在一个上下文里串行完成。"
                  "这不是已经浪费掉的墙钟（sev 记 0，不计入可回收总时长），"
                  "而是「规模没换成速度」的结构性提示",
        "action": "回看有没有彼此无数据依赖的独立块——多文件/多会话/多 URL 同时查、"
                  "多组独立命令、多份互不影响的产出。有就下次在同一条消息里并起 subagent，墙钟取 max；"
                  "单点排查、严格依赖链（改代码→编译→测试）保持串行是对的",
        "tools": [k for k, _v in top],
        "ctx": _capped_ctx(itertools.chain(
            ["subagent 闲置 零委派 串行 并行"],
            (brief_args(c, 120) for c in list(calls.values())[:3])), 1200),
    }


# ---------------------------------------------------------------- analyze

def analyze(evs, since_min=None, _depth=0):
    if since_min is not None and (not math.isfinite(since_min) or since_min <= 0):
        raise AuditInputError("--since 必须为正的有限分钟数")
    all_calls, all_results, steps, missing_keys = build(evs)
    segs = segments(evs)
    idx = SegIndex(segs)

    last = max((x["time"] for x in evs if isinstance(x.get("time"), (int, float))), default=0)
    horizon = last - since_min * 60 * 1000 if since_min else 0
    # 所有检测和经验匹配共用此范围；跨窗口调用只统计窗口内的重叠时长。
    warnings = list(getattr(evs, "warnings", []))
    if missing_keys:
        warnings.append("%d 条步骤/调用事件缺 turn/step，已按未知步骤聚合" % missing_keys)
    truncated_read = any(w.startswith("压缩日志未完整读出") for w in warnings)

    ti_cache = {}

    def interval_of(cid, c):
        iv = ti_cache.get(cid, _MISSING)
        if iv is _MISSING:
            iv = tool_interval(c, all_results.get(cid), idx, horizon)
            ti_cache[cid] = iv
        return iv

    calls = {}
    for cid, c in all_calls.items():
        if not isinstance(c.get("time"), (int, float)):
            continue
        iv = interval_of(cid, c)
        if c["time"] >= horizon or (iv is not None and iv[1] > horizon):
            calls[cid] = c
    results = {cid: r for cid, r in all_results.items() if cid in calls}

    # ---- 逐步指标
    rows = []
    orphan_steps = 0
    for k, s in steps.items():
        start = s.get("start")
        end = s.get("end")
        # 孤儿步骤：有 turn/step、有调用，但日志里从没出现 step/start
        # （日志起点截断或撕裂写）。这些调用同样承载失败/重复证据，按零时长
        # 纳入检测；不给任何耗时口径贡献，并给出专门警告——此前是静默丢弃。
        orphan = (start is None and k[0] is not None and k[1] is not None
                  and bool(s["calls"]))
        if orphan:
            wcalls = [c for cid in s["calls"] if (c := calls.get(cid)) is not None]
            if not wcalls:
                continue
            orphan_steps += 1
            window_start = start = min(c["time"] for c in wcalls)   # 仅排序/展示用
            dur = 0.0
            complete = False
        else:
            if start is None or (end is not None and end <= horizon) or (end is None and start < horizon):
                continue
            window_start = max(start, horizon)
            dur = 0.0
            complete = end is not None and end >= start and idx.same(start, end)
            if complete:
                dur = (end - window_start) / 1000.0

        writes = 0
        reads = 0
        errs = 0
        outlen = 0
        polls = 0
        waits = 0
        fps = []
        timeouts = 0
        tool_intervals = []
        poll_intervals = []

        for cid in s["calls"]:
            c = calls.get(cid)
            if not c:
                continue
            r = results.get(cid)
            name = c["name"]
            fps.append(c["fp"])
            if r:
                outlen += len(r["text"])
                if r["error"]:
                    errs += 1
                if is_timeout_result(r["text"]):
                    timeouts += 1
                interval = interval_of(cid, c)
                if interval is not None and complete:
                    a, b = max(interval[0], window_start), min(interval[1], end)
                    if b >= a:
                        tool_intervals.append((a, b))
                        if name in POLL_LIKE:
                            poll_intervals.append((a, b))
                            polls += 1
                            aobj = c.get("aobj")
                            if isinstance(aobj, dict):
                                waits += bool(aobj.get("wait"))
            if name in PRODUCTIVE and r and not r["error"]:
                writes += 1
            if name in READ_LIKE:
                reads += 1

        tool_sec = interval_seconds(tool_intervals)
        poll_sec = interval_seconds(poll_intervals)
        rows.append({
            "turn": k[0], "step": k[1], "dur": dur,
            "tool": tool_sec, "llm": max(0.0, dur - tool_sec),
            "writes": writes, "reads": reads, "errs": errs,
            # 轮询是并行等多个 job 时可能累加超过本步耗时，封顶到步耗时
            "out": outlen, "poll_sec": min(poll_sec, dur), "polls": polls,
            "fps": fps, "timeouts": timeouts, "waits": waits,
            "start": window_start, "complete": complete,
        })

    rows.sort(key=lambda x: (x["start"] or 0))

    total = sum(r["dur"] for r in rows)
    total_calls = sum(len(r["fps"]) for r in rows)
    if since_min:
        # 只算窗口内的活动时间，否则报告里的"活动"和"步内合计"对不上
        active = sum(max(0.0, (e - max(s, horizon)) / 1000.0)
                     for s, e in segs if e > horizon)
    else:
        active = sum((e - s) for s, e in segs) / 1000.0

    # ---- 工具耗时分布
    tool_t = defaultdict(float)
    for c in calls.values():
        interval = interval_of(c["id"], c)
        if interval is not None:
            tool_t[c["name"]] += max(0, interval[1] - interval[0]) / 1000.0

    # ---- 黑洞检测
    holes = []

    # 1) 长轮询
    poll_rows = [r for r in rows if r["polls"] > 0]
    poll_total = sum(r["poll_sec"] for r in poll_rows)
    poll_n = sum(r["polls"] for r in poll_rows)
    poll_waits = sum(r["waits"] for r in poll_rows)
    if poll_total > 120 and poll_n >= 3:
        holes.append({
            "kind": "任务轮询",
            "sev": poll_total,
            "ratio": poll_total / total if total else 0,
            "evidence": "%d 次 job_output/job_list（%d 次 wait=true）— %s" % (
                poll_n, poll_waits,
                " ".join("T%s.S%s" % (r["turn"], r["step"]) for r in poll_rows[:5])),
            "detail": "累计 %s，中位 %.0fs/次" % (
                fmt_dur(poll_total),
                sorted(r["poll_sec"] / max(1, r["polls"]) for r in poll_rows)[len(poll_rows) // 2]
                if poll_rows else 0),
            "action": "核对轮询是否带来新状态；无变化时降低频率，有独立工作再并行推进",
            "tools": ["job_output", "job_list"],
            "ctx": _capped_ctx((brief_args(c, 300) for c in calls.values()
                                if c["name"] in POLL_LIKE), 1800),
        })

    # 1b) 起后台即阻塞等（最可回收的等待形态）
    #     精确归因（30 会话标定）：job_output wait=true 合计 243 分钟，
    #     其中 121 分钟（50%）是「起了 run_in_background 后 3 次调用内就
    #     wait=true 阻塞等」。后台的唯一价值是等待窗口内做别的事，
    #     起了就等等于同步调用只多一层调度开销。
    #     这里单独报出来——泛泛的「任务轮询」给不出这么具体的动作。
    ordered_all = sorted(
        (c for c in calls.values() if isinstance(c.get("time"), (int, float))),
        key=lambda c: c["time"])
    bg_block_sec = 0.0
    bg_block_items = []
    for pos, c in enumerate(ordered_all):
        if c["name"] not in POLL_LIKE:
            continue
        aobj = c.get("aobj")
        if not (isinstance(aobj, dict) and aobj.get("wait") is True):
            continue
        iv = interval_of(c["id"], c)
        if iv is None:
            continue
        dur = max(0.0, (iv[1] - iv[0]) / 1000.0)
        window = ordered_all[max(0, pos - 3):pos]
        started_bg = any(
            isinstance(p.get("aobj"), dict) and p["aobj"].get("run_in_background") is True
            for p in window)
        if started_bg:
            bg_block_sec += dur
            bg_block_items.append((dur, c, window))
    if bg_block_items and bg_block_sec >= 30.0:
        bg_block_items.sort(key=lambda x: -x[0])
        bdur, bcall, bwin = bg_block_items[0]
        holes.append({
            "kind": "起后台即阻塞等",
            "sev": bg_block_sec,
            "ratio": bg_block_sec / total if total else 0,
            "evidence": "%d 次「起了后台立刻 wait=true 阻塞等」，累计 %s（最长单次 %s）— T%s.S%s" % (
                len(bg_block_items), fmt_dur(bg_block_sec), fmt_dur(bdur),
                bcall.get("turn"), bcall.get("step")),
            "detail": "这 %s 是纯等待：后台任务已经起了，却在原地等它完成，"
                      "等于同步调用只多一层开销" % fmt_dur(bg_block_sec),
            "action": "起完 run_in_background 立刻转去做独立工作（写下一步脚本/改无关代码/"
                      "读文件），用 wait=false 探一次，没结果就继续做别的，回头再收。"
                      "只有「必须拿到结果才能决定下一步」时才该阻塞等",
            "tools": sorted({p["name"] for _d, _c, w in bg_block_items for p in w}
                            | {c["name"] for _d, c, _w in bg_block_items}),
            "ctx": _capped_ctx(itertools.chain(
                ["run_in_background wait=true 阻塞等"],
                (brief_args(p, 120) for _d, _c, w in bg_block_items[:3] for p in w),
                (brief_args(c, 120) for _d, c, _w in bg_block_items[:3])), 1200),
        })

    # 2) 超时命令
    #    单次超时是正常现象（某条命令恰好慢），不构成「模式」。
    #    全量 506 会话标定：旧条件（>=1 次）触发 76 个会话，其中
    #    59%（45 个）只超时 1 次 —— 纯噪音。提到 >=2 次才报。
    #
    #    速度归因（25 会话精确统计）：命令执行占 78.4% 的总耗时，
    #    其中「>120s」的 80 次占 30.9%（301 分钟）。这些命令 52% 在超时后
    #    下一步就去 job_output——说明它们本该起后台，却在前台跑到超时。
    #    所以 action 要针对这个真实形态给建议，而不是泛泛的"加预算或缩范围"。
    to_rows = [r for r in rows if r["timeouts"] > 0]
    to_total = sum(r["timeouts"] for r in to_rows)
    if to_rows and to_total >= 2:
        to_calls = [c for c in calls.values()
                    if results.get(c["id"]) and is_timeout_result(results[c["id"]]["text"])]
        # 超时后是否很快又去 job_output/job_kill = 命令实际还在跑
        ordered_to = sorted((c for c in calls.values() if isinstance(c.get("time"), (int, float))),
                            key=lambda c: c["time"])
        chased = 0
        for pos, c in enumerate(ordered_to):
            r = results.get(c["id"])
            if not r or not is_timeout_result(r.get("text")):
                continue
            nxt = ordered_to[pos + 1:pos + 3]
            if any(x["name"] in POLL_LIKE or x["name"] == "job_kill" for x in nxt):
                chased += 1
        chased_pct = chased / len(to_calls) if to_calls else 0
        if chased_pct >= 0.4:
            action = ("这些超时里有 %d/%d 在超时后立刻去 job_output/job_kill —— 说明命令实际没结束，"
                      "本该一开始就 run_in_background 起后台，前台干等只会白跑满 timeout。"
                      "预期 >60s 的命令直接起后台，前台只做与该结果无关的工作" % (chased, len(to_calls)))
        else:
            action = "命令超时 = 信号：要么加超时预算要么缩范围，别原地重跑"
        holes.append({
            "kind": "超时转后台",
            "sev": sum(r["dur"] for r in to_rows),
            "ratio": sum(r["dur"] for r in to_rows) / total if total else 0,
            "evidence": "%d 次命令跑满 timeout%s" % (
                sum(r["timeouts"] for r in to_rows),
                ("（其中 %d 次超时后仍在追同一任务）" % chased) if chased else ""),
            "detail": " ".join("T%s.S%s" % (r["turn"], r["step"]) for r in to_rows[:5]),
            "action": action,
            "tools": sorted({c["name"] for c in to_calls}),
            "ctx": _capped_ctx((brief_args(c, 300) for c in to_calls), 900),
        })

    # 2b) 盲等（sleep 类命令）
    #     速度归因（40 会话）：含 sleep/Start-Sleep 的命令 610 次、392.9 分钟，
    #     高度集中（单会话最多 219.7 分钟）。声明的秒数长尾很重：
    #     sleep 300s ×4、360s ×1、240s ×1 —— 这些是纯盲等，期间什么都做不了。
    #     只报 >=10s 的：更短的 sleep 常是给进程启停留余量，属正常做法。
    _SLEEP_RE = re.compile(r"(?:Start-Sleep|sleep)\s+(?:-Seconds\s+)?(\d+)", re.I)
    blind_items = []
    for c in calls.values():
        if c["name"] not in SHELL_LIKE:
            continue
        aobj = c.get("aobj")
        if not isinstance(aobj, dict):
            continue
        cmd = aobj.get("command") or ""
        mt = _SLEEP_RE.search(cmd)
        if not mt:
            continue
        declared = int(mt.group(1))
        if declared < 10:
            continue
        iv = interval_of(c["id"], c)
        if iv is None:
            continue
        dur = max(0.0, (iv[1] - iv[0]) / 1000.0)
        blind_items.append((dur, declared, c))
    blind_sec = sum(d for d, _s, _c in blind_items)
    if blind_items and blind_sec >= 20.0:
        blind_items.sort(key=lambda x: -x[0])
        wdur, wdecl, wcall = blind_items[0]
        holes.append({
            "kind": "盲等",
            "sev": blind_sec,
            "ratio": blind_sec / total if total else 0,
            "evidence": "%d 次 sleep 类命令，累计 %s（最长单次 %s，声明 %ds）— T%s.S%s" % (
                len(blind_items), fmt_dur(blind_sec), fmt_dur(wdur), wdecl,
                wcall.get("turn"), wcall.get("step")),
            "detail": "sleep 是纯阻塞：这段时间无法推进任何工作，也无法知道等待的条件是否已满足",
            "action": "先问这条 sleep 在等什么：①等某个状态 → 改成轮询该状态（wait=false 探一次，"
                      "没到就去做别的）；②等资源就绪（服务启动/文件落盘）→ 起后台并立即去做无关工作；"
                      "③在给刚启动的进程留余量 → 缩短到 1-3s 并改成检查进程是否就绪；"
                      "④什么都不等 → 删掉",
            "tools": sorted({c["name"] for _d, _s, c in blind_items}),
            "ctx": _capped_ctx((brief_args(c, 200) for _d, _s, c in blind_items[:3]), 900),
        })

    # 2c) 命令可合并（直接针对 LLM 轮次成本）
    #     速度归因（12 会话精确统计）：
    #       - 步内时间只占 active 的 63%，其余 37% 是「步骤之间」的 gap；
    #       - ≥3 分钟的 52 个 gap 全部紧跟 step/start（不是用户离开），
    #         即模型生成下一条回复的等待；
    #       - 单调用步 3526 个吃掉 499 分钟 LLM；其中 ops_bash+pwsh 占 270 分钟；
    #       - 每步 LLM 开销与输出量关系很小（输出>2000 字 9.9s vs 8.9s），
    #         说明主要是**每步固定开销**——提速只能靠减少步数。
    #     连续的单调用命令步是最容易合并的形态：合并后省掉中间的 LLM 轮次。
    #     只有「命令之间无数据依赖」才该合并，故给 3 步及以上、且参数各异的段。
    by_fp = {}
    for c in calls.values():
        if c.get("fp"):
            by_fp.setdefault(c["fp"], c)
    cmd_tools = ("ops_bash", "pwsh", "bash", "shell", "terminal")
    merge_runs = []
    cur_run = []
    for r in rows:
        fps = r.get("fps") or []
        c = by_fp.get(fps[0]) if len(fps) == 1 else None
        if c and c["name"] in cmd_tools:
            cur_run.append((r, c))
        else:
            if len(cur_run) >= 3:
                merge_runs.append(cur_run)
            cur_run = []
    if len(cur_run) >= 3:
        merge_runs.append(cur_run)
    # 同一条命令反复跑（如重跑测试）不算可合并——那是必要的重新验证
    merge_runs = [run_ for run_ in merge_runs
                  if len({c.get("fp") for _r, c in run_}) >= 2]
    # 「同目标逐步深入」不是可合并：实测自指审计 95 段里 76 段（80%）是
    # 对同一批文件反复 grep/sed/读，后一条要看前一条结果才知道怎么改
    # ——这属真依赖链，合并会破坏调试流程。判据：段内命令涉及的文件名
    # 去重后数量不超过一半，说明在少数目标上反复深入。
    _FILE_RE = re.compile(r"[\w\-.]+\.(?:py|md|json|jsonl|mjs|js|ts|yml|yaml|txt)\b")

    def _same_target_run(run_):
        names = []
        for _r, c in run_:
            cmd = (c.get("aobj") or {}).get("command") or ""
            names.extend(_FILE_RE.findall(cmd))
        if len(names) < 2:
            return False
        return len(set(names)) <= len(names) / 2

    merge_runs = [run_ for run_ in merge_runs if not _same_target_run(run_)]
    if merge_runs:
        saved_steps = sum(len(run_) - 1 for run_ in merge_runs)
        saved_llm = sum(sum((r.get("llm") or 0) for r, _c in run_) -
                        (sum((r.get("llm") or 0) for r, _c in run_) / len(run_))
                        for run_ in merge_runs)
        longest = max(merge_runs, key=len)
        if saved_steps >= 5:
            holes.append({
                "kind": "命令可合并",
                "sev": saved_llm,
                "ratio": saved_llm / total if total else 0,
                "evidence": "%d 段连续单调用命令步，合并可省 %d 步（约 %s LLM 等待）；"
                            "最长一段 %d 步 — T%s.S%s" % (
                                len(merge_runs), saved_steps, fmt_dur(saved_llm),
                                len(longest), longest[0][0].get("turn"),
                                longest[0][0].get("step")),
                "detail": "每次单独发一条命令就要多等一轮模型生成（实测每步固定约 8 秒，"
                          "与输出量关系很小）；合并后省掉的是这些轮次，不是命令本身的时间",
                "action": "先确认这些命令之间没有数据依赖（前一条的输出不需要先看）："
                          "无依赖就合并成一条（cmd1; cmd2 && cmd3）或同一条消息里并发发出。"
                          "省下的是 LLM 轮次不是命令执行时间——每省一步约省 8 秒。"
                          "有依赖（改代码→编译→测试）必须串行，不必处理",
                "tools": sorted({c["name"] for run_ in merge_runs for _r, c in run_}),
                "ctx": _capped_ctx((brief_args(c, 150) for _r, c in longest[:4]), 900),
            })

    # 3) 反复编辑（先算，供重复调用去重）
    #    只看文件计数会误报：在同一个大文件的不同位置迭代 30 次是正常开发。
    #    用 old_string 的重复度判断是不是真的在反复改同一段。
    edits = defaultdict(list)
    for c in calls.values():
        if c["name"] != "edit" or not results.get(c["id"]) or results[c["id"]]["error"]:
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
        if n < 5:
            continue
        uniq = len(set(hs))
        if uniq / float(n) <= 0.6:      # 多数编辑打在同一个 old_string 上 = 打补丁
            hot.append((p, n, uniq))
    hot.sort(key=lambda x: -x[1])
    hot_files = set(p for p, _, _ in hot)

    # 4) 重复指纹（排除已由「反复编辑」覆盖的文件；同时检查单步内重复）
    fp2call = {}
    fp_calls = defaultdict(list)
    err_text_groups = Counter()
    for c in calls.values():
        fp2call.setdefault(c["fp"], c)
        r = results.get(c["id"])
        if r:
            fp_calls[c["fp"]].append(c)
            if r["error"] and r["text"]:
                # 失败循环的"同文本错误"聚合：URL/路径 token 归一 + 数字→#
                # 后视为同一条报错（同模板不同路径/计数 = 疑似同一根因，
                # §19/§21 实证）。逐字仍不同的措辞骨架各自计数不合并。
                err_text_groups[norm_err_text(r["text"])] += 1
    cnt = Counter()        # 出现该指纹的步数
    step_occ = {}          # 单步内的最大出现次数
    for r in rows:
        row_counts = Counter(r["fps"])
        for f, k in row_counts.items():
            cnt[f] += 1
            if k > step_occ.get(f, 0):
                step_occ[f] = k
    cands = {f for f, n in cnt.items() if n >= 3} | {f for f, n in step_occ.items() if n >= 3}
    dup = []
    for f in cands:
        c = fp2call.get(f)
        if c and c["name"] in POLL_LIKE:
            continue        # 轮询由专门规则处理
        matching = fp_calls.get(f) or []
        if len(matching) < 3:
            continue
        # 相同操作如果每次返回不同内容，尚不足以证明在重复空转。
        # 仅首尾空白不同的输出视为同一内容（格式噪声不构成新信息）。
        outputs = [results[x["id"]]["text"].strip() for x in matching]
        if len(set(outputs)) == len(outputs):
            continue
        if c and c["name"] == "edit":
            a = c.get("aobj")
            p = (a.get("file_path") or a.get("path") or "") if isinstance(a, dict) else ""
            if p in hot_files:
                continue    # 已由「反复编辑同处」专门报告，不重复计噪音
        dup.append((f, max(cnt.get(f, 0), step_occ.get(f, 0)), step_occ.get(f, 0)))
    if dup:
        dup.sort(key=lambda x: -x[1])
        names, ctx = [], []
        for f, n, occ in dup[:6]:
            c = fp2call.get(f)
            nm = c["name"] if c else f.split("|")[0]
            snip = brief_args(c, 80) if c else ""
            suffix = ("（%s）" % snip) if snip else ""
            if occ >= 3:
                suffix += "（单步内×%d）" % occ
            names.append("%s×%d%s" % (nm, n, suffix))
            ctx.append("%s %s" % (nm, brief_args(c, 300) if c else ""))
        holes.append({
            "kind": "重复调用",
            "sev": sum(r["dur"] for r in rows if any(f in r["fps"] for f, _n, _o in dup[:6])),
            "ratio": 0,
            "evidence": "同一参数重复 ≥3 次: " + "; ".join(names),
            "detail": "最高 %d 次" % dup[0][1],
            "action": "比较重复调用的结果与预期；没有新信息时再改变假设或操作方法",
            "tools": sorted({c["name"] for f, _n, _o in dup[:6] if (c := fp2call.get(f))}),
            "ctx": _capped_ctx(iter(ctx), 2000),
        })

    # 5) 失败循环（连续≥3步 / 率≥12%且≥20步 / 同文本错误≥3次）
    worst = 0
    cur = 0
    for r in rows:
        if r["errs"] > 0:
            cur += 1
            worst = max(worst, cur)
        else:
            cur = 0
    fail_n = sum(1 for r in rows if r["errs"] > 0)
    fail_rate = fail_n / max(1, len(rows))
    same_err_n = max(err_text_groups.values(), default=0)
    if worst >= 3 or (fail_n >= 20 and fail_rate >= 0.12) or same_err_n >= 3:
        err_tools = sorted({c["name"] for c in calls.values()
                            if results.get(c["id"]) and results[c["id"]]["error"]})
        ev_bits = ["失败步 %d/%d（%.1f%%），连续最长 %d 步" % (
            fail_n, len(rows), 100.0 * fail_rate, worst)]
        if same_err_n >= 3:
            ev_bits.append("同文本错误×%d" % same_err_n)
        def _err_ctx():
            for c in calls.values():
                r = results.get(c["id"])
                if r and r["error"]:
                    yield brief_args(c, 400) + " " + r["text"][:800]
        holes.append({
            "kind": "失败循环",
            "sev": 0.0,
            "ratio": 0,
            "evidence": "；".join(ev_bits),
            "detail": "失败输出累计 %d 字符" % sum(r["out"] for r in rows if r["errs"]),
            "action": "连续 3 次报错 → 停下来读错误本身，别急着改代码",
            "tools": err_tools,
            "ctx": _capped_ctx(_err_ctx(), 4000),
            "priority": 2,
        })

    # 6) 无产出长段
    best = (0, 0, 0)  # len, i, j
    i = 0
    while i < len(rows):
        if rows[i]["writes"] == 0:
            j = i
            while j + 1 < len(rows) and rows[j + 1]["writes"] == 0:
                j += 1
            span = sum(r["dur"] for r in rows[i:j + 1])
            if j - i + 1 >= 6 and span > best[0]:
                best = (span, i, j)
            i = j + 1
        else:
            i += 1
    _span = sum(r["dur"] for r in rows[best[1]:best[2] + 1]) if best[0] else 0
    if best[2] - best[1] + 1 >= 6 and _span >= 300:
        _, a, b = best
        seg = rows[a:b + 1]
        # 探索段守卫：读目标多样（≥4 个不同读取指纹）、无单调用主导（最重复
        # 调用占比≤0.3）且输出充足（≥1000 字符）→ 正常只读探索形态，不判
        # 无产出长段。判据与预研探针 eval/noprod_fp_prework.py 的 explore
        # pole 逐字一致（REPORT §18：fired 段 23% 为该形态，纯研究段被误标）。
        seg_fps = [f for r in seg for f in r["fps"]]
        seg_cnt = {}
        for f in seg_fps:
            seg_cnt[f] = seg_cnt.get(f, 0) + 1
        seg_share = (max(seg_cnt.values()) / len(seg_fps)) if seg_fps else 0.0
        seg_read_n = len({f for f in seg_fps if f.split("|")[0] in READ_LIKE})
        seg_out = sum(r["out"] for r in seg)
        # 命令执行段：连续跑命令（编译/测试/脚本）是在推进，不是空转。
        # 独立判据（不计入 read_n）：本环境主力工具是 pwsh/ops_bash，
        # 若只把它们算「非读」，纯命令执行的调研段会被误判为空转。
        seg_shell_n = len({f for f in seg_fps if f.split("|")[0] in SHELL_LIKE})
        seg_shell_share = (sum(1 for f in seg_fps if f.split("|")[0] in SHELL_LIKE)
                           / len(seg_fps)) if seg_fps else 0.0
        explore_guard = (seg_read_n >= 4 and seg_share <= 0.3 and seg_out >= 1000)
        # 命令占主导（≥60%）且输出充足 → 在执行任务链，不判空转。
        shell_guard = seg_shell_share >= 0.6 and seg_out >= 1000
        if not (explore_guard or shell_guard):
            segment_keys = {(r["turn"], r["step"]) for r in seg}
            span = sum(r["dur"] for r in seg)
            holes.append({
                "kind": "无产出长段",
                "sev": span,
                "ratio": span / total if total else 0,
                "evidence": "%d 步连续无写入 — T%s.S%s → T%s.S%s" % (
                    len(seg), seg[0]["turn"], seg[0]["step"], seg[-1]["turn"], seg[-1]["step"]),
                "detail": "耗时 %s，输出 %d 字符，0 次 write/edit" % (fmt_dur(span), sum(r["out"] for r in seg)),
                "action": "问一句：这段产生了什么**可验证**的新结论？答不上来就该换方向",
                "tools": sorted({f.split("|")[0] for r in seg for f in r["fps"]}),
                "ctx": _capped_ctx((brief_args(c, 300) for c in calls.values()
                                    if (c.get("turn"), c.get("step")) in segment_keys), 3000),
            })

    # 7) 同一段被反复改
    if hot:
        holes.append({
            "kind": "反复编辑同处",
            "sev": 0.0,
            "ratio": 0,
            "evidence": ", ".join("%s×%d（仅 %d 处不同）" % (os.path.basename(p), n, u)
                                  for p, n, u in hot[:4]),
            "detail": "同一段 old_string 被重复改动，多半在打补丁",
            "action": "改 5 次还在改 = 没理解问题，先读全再动手",
            "tools": ["edit"],
            "ctx": " ".join(hot_files),
        })

    # 8) 串行同类调用（本可并行的候选）
    #    两种形态都算，因为「单次很快」正是它躲过旧检测的原因：
    #      长调用型：每次 ≥10s，≥4 次，累计 ≥60s
    #      短调用型：每次 ≥1s，≥15 次，累计 ≥180s
    #    机械上只能识别「同工具 + 单调用步 + 区间不重叠」这个形态；
    #    是否真的互不依赖必须由人/模型核实——严格依赖链（下载→分离→推理）
    #    同样会命中，所以给的是「问一句」，不是「该并行」的结论。
    SERIAL_MIN_CALLS = 4
    SERIAL_MIN_EACH = 10.0
    SERIAL_MIN_TOTAL = 60.0
    SHORT_MIN_CALLS = 15
    SHORT_MIN_EACH = 1.0
    SHORT_MIN_TOTAL = 180.0
    serial_runs = []
    i = 0
    while i < len(rows):
        r = rows[i]
        if not r["complete"] or len(r["fps"]) != 1:
            i += 1
            continue
        rname = r["fps"][0].split("|")[0]
        if rname in POLL_LIKE:
            i += 1
            continue
        j = i
        run_s = 0.0
        while j < len(rows):
            rr = rows[j]
            if not rr["complete"] or len(rr["fps"]) != 1:
                break
            if rr["fps"][0].split("|")[0] != rname or rr["tool"] < SHORT_MIN_EACH:
                break
            run_s += rr["tool"]
            j += 1
        n = j - i
        if n >= SERIAL_MIN_CALLS and run_s >= SERIAL_MIN_TOTAL:
            # 形态由段内实际单次时长的中位数决定，不靠「先撞哪个阈值」：
            # 90 次各 2 秒的串行，单次虽短但次数够，属短调用型。
            each = sorted(rows[k]["tool"] for k in range(i, j))
            median_each = each[len(each) // 2]
            form = "long" if median_each >= SERIAL_MIN_EACH else "short"
            serial_runs.append((rname, n, run_s, i, j - 1, form))
        elif n >= SHORT_MIN_CALLS and run_s >= SHORT_MIN_TOTAL:
            serial_runs.append((rname, n, run_s, i, j - 1, "short"))
        i = max(j, i + 1)
    if serial_runs:
        serial_runs.sort(key=lambda x: -x[2])
        sname, s_calls, s_sec, s_a, s_b, s_form = serial_runs[0]
        seg = rows[s_a:s_b + 1]
        seg_keys = {(r["turn"], r["step"]) for r in seg}
        if s_form == "long":
            shape = "%s 连续 %d 次串行长调用（每次≥%.0fs）" % (sname, s_calls, SERIAL_MIN_EACH)
            detail = "累计 %s，调用区间互不重叠（串行）" % fmt_dur(s_sec)
        else:
            shape = "%s 连续 %d 次串行短调用（每次 %.0f~%.0fs）" % (
                sname, s_calls, SHORT_MIN_EACH, SERIAL_MIN_EACH)
            detail = ("累计 %s——单次很快，这正是它躲过旧检测的原因；"
                      "短调用同样可能互不依赖" % fmt_dur(s_sec))
        holes.append({
            "kind": "串行长调用",
            "sev": s_sec,
            "ratio": s_sec / total if total else 0,
            "evidence": "%s — T%s.S%s → T%s.S%s" % (
                shape, seg[0]["turn"], seg[0]["step"], seg[-1]["turn"], seg[-1]["step"]),
            "detail": detail,
            "action": "核实这 %d 次调用是否互不依赖：不依赖就并行（N 项起 N 个后台作业），确属依赖链再保持串行" % s_calls,
            "tools": [sname],
            # ctx 前面加一句信号语义：经验库规则靠 match 关键词召回，
            # 而纯工具参数里不会出现「串行/并发」这类词（实测 3 个串行洞 0 召回）。
            "ctx": _capped_ctx(itertools.chain(
                ["串行 长调用 并发 未并行 串行调用"],
                (brief_args(c, 300) for c in calls.values()
                 if (c.get("turn"), c.get("step")) in seg_keys)), 2000),
        })

    # 8b) 串行未并行：整个窗口的并行度体检
    #     「串行长调用」只看同工具的连续段；这一类看全局——即使工具不断切换，
    #     只要全程没有 subagent、没有后台作业、没有单步多调用，就是没并发能力。
    para = parallel_profile(calls, rows, results)
    para_hole = _parallel_hole(para, rows, calls, total)
    # --since 窗口内一步都没有时，说清是「窗口空」而不是「数据不足」
    if since_min and not rows and calls:
        warnings.append("最近 %g 分钟窗口内没有完整步骤；窗口外的调用未计入。"
                        "去掉 --since 或换更长的窗口再审计" % since_min)
    if para_hole is not None:
        holes.append(para_hole)

    # 8c) subagent 串行：分步起本可并起的子任务，损失用子会话耗时算。
    #     读子会话是额外 I/O，所以只在真有 delegate 调用、且不在子会话里时进入
    #     （_depth>0 表示当前正在读子会话，避免递归展开）。
    if para["subagent"] and _depth == 0:
        sub_hole = _subagent_serial_hole(calls, results, total, _depth)
        if sub_hole is not None:
            holes.append(sub_hole)

    # 8d) subagent 闲置：长会话零委派。规模维度的提示，sev 固定 0，
    #     不进 SPEED_KINDS（它不代表已浪费的墙钟）。串行未并行已报则跳过。
    if _depth == 0:
        idle_hole = _subagent_idle_hole(
            para, active, total_calls, rows, tool_t, calls,
            any(h["kind"] == "串行未并行" for h in holes))
        if idle_hole is not None:
            holes.append(idle_hole)

    # 9) 盲改缺验证：同一文件 ≥3 次成功编辑，覆盖的窗口内既没有重读该文件，
    #    也没有跑测试。「改动是否有效」无法机械判定，这里只报代理事实：
    #    改了很多次却没有任何验证动作。已被「反复编辑同处」按 old_string
    #    重复度报告过的文件不重复计噪音；窗口向后放宽 5 分钟，让「改完再测」
    #    的常规流程不被误报。
    TEST_HINTS = ("pytest", "unittest", "npm test", "npm run test", "pnpm test",
                  "yarn test", "go test", "cargo test", "ctest", "coverage")
    verifies = []      # (start, end, path_or_empty_for_test_runner)
    for cid, c in calls.items():
        iv = interval_of(cid, c)
        if iv is None:
            continue
        aobj = c.get("aobj")
        if c["name"] in READ_LIKE:
            vp = (aobj.get("file_path") or aobj.get("path") or "") if isinstance(aobj, dict) else ""
            verifies.append((iv[0], iv[1], vp))
            continue
        if not isinstance(aobj, dict):
            continue
        cmd = aobj.get("command") or aobj.get("script") or ""
        if isinstance(cmd, str) and cmd and any(h in cmd.lower() for h in TEST_HINTS):
            verifies.append((iv[0], iv[1], ""))
    edited = defaultdict(list)     # path -> [(start, end)]
    for cid, c in calls.items():
        if c["name"] not in ("edit", "write"):
            continue
        r = results.get(c["id"])
        if r is None or r["error"]:
            continue
        aobj = c.get("aobj")
        p = (aobj.get("file_path") or aobj.get("path") or "") if isinstance(aobj, dict) else ""
        iv = interval_of(cid, c)
        if not p or iv is None:
            continue
        edited[p].append((iv[0], iv[1]))
    blind = []
    for p, spans in edited.items():
        if len(spans) < 3 or p in hot_files:
            continue
        # 文档类文件没有「跑测试验证」这个选项，改它们不重读是正常的：
        # 实测 29 次误报都是 .md（README 等）。只对可执行/可测试的源文件报。
        if _is_doc_file(p):
            continue
        lo = min(x[0] for x in spans)
        hi = max(x[1] for x in spans) + 5 * 60 * 1000
        base = os.path.basename(p)
        covered = False
        for v_start, v_end, v_path in verifies:
            if v_start < lo or v_end > hi:
                continue
            if v_path and p not in v_path and base not in v_path:
                continue    # 只有指向本文件的重读才算；测试运行器 v_path 为空
            covered = True
            break
        if not covered:
            blind.append((p, len(spans)))
    if blind:
        blind.sort(key=lambda x: -x[1])
        holes.append({
            "kind": "盲改缺验证",
            "sev": 0.0,
            "ratio": 0,
            "evidence": ", ".join("%s×%d 次成功编辑，期间无重读/无测试" % (os.path.basename(p), n)
                                  for p, n in blind[:4]),
            "detail": "改动之间的验证动作为 0：既没重读目标文件，也没跑测试",
            "action": "先给程序加可观测性（日志/断言）再改，别靠猜；判据是「改动没生效时能否从输出定位卡点」",
            "tools": ["edit", "write"],
            "ctx": " ".join(p for p, _n in blind[:6]),
        })

    for h in holes:
        h.setdefault("priority", 1)
    holes.sort(key=lambda h: (-h["priority"], -h["ratio"], -h["sev"]))

    completed = sum(r["complete"] for r in rows)
    incomplete = len(rows) - completed - orphan_steps
    if incomplete:
        warnings.append("%d 个步骤未结束或时间区间不完整，未计入耗时" % incomplete)
    if orphan_steps:
        warnings.append("%d 个步骤缺少 step/start 事件（日志起点截断或记录撕裂），"
                        "已按零时长纳入失败/重复检测，不计入耗时" % orphan_steps)
    status = "review" if holes else "ok"
    if not completed:
        # 0 个可计时完整步骤时："没有完整步骤"≠"没有数据"。读到一半被截断、
        # 或存在带调用/结果的孤儿步骤（起点截断/撕裂写）时，内容级证据仍然
        # 存在——如实标 partial 让 holes 照常展示，不得因缺时间戳隐藏证据。
        status = "partial" if (truncated_read or orphan_steps) else "insufficient_data"
    elif warnings and not holes:
        status = "partial"

    return {
        "rows": rows, "holes": holes, "total": total, "active": active,
        "calls": total_calls, "tool_t": dict(tool_t), "segs": segs,
        "polls": poll_total, "poll_n": poll_n,
        "parallel": para,
        "status": status, "warnings": warnings, "completed_steps": completed,
        "incomplete_steps": incomplete, "last_event_ms": last,
        "window_min": since_min,
    }


# ---------------------------------------------------------------- lessons
#
# lessons.jsonl 是与脚本同目录的持久化教训库。审计本身只读，
# 不写文件；写入只发生在 --record（确认一个解法）时。
# 键设计：kind 必须与黑洞检测里的 kind 完全一致，才能被机械匹配。

LESSONS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lessons.jsonl")
# 路径是否由用户显式指定（--lessons-path / set_lessons_path）。
# 默认路径不存在 = 首次使用，返回内置示例是合理的；
# 显式指定的路径不存在 = 拼写错误，必须报错而不是静默返回示例。
# 实测：--lessons --lessons-path /no/such/lib.jsonl 曾静默返回 2 条示例，
# 而真库有 55 条——用户会以为经验库坏了。
LESSONS_PATH_EXPLICIT = False


def set_lessons_path(path):
    """重定向经验库（--lessons-path）：测试/隔离副本用；状态目录随库走。"""
    global LESSONS_PATH, LESSONS_PATH_EXPLICIT
    LESSONS_PATH = os.path.abspath(path)
    LESSONS_PATH_EXPLICIT = True

# 与 analyze() 里每个 holes.append 的 kind 保持一致；新增检测规则时同步这里。
KNOWN_SCOPES = ("contextual", "general")

# feedback 事件的合法取值。CLI 层有 argparse choices 校验，但插件直接调用
# 引擎函数时不经过 argparse——实测 event="bogus"/""/None 曾被接受并静默
# 落库（stats 不计入，但库里留下垃圾记录）。
FEEDBACK_EVENTS = ("recommended", "adopted", "success", "failure")

KNOWN_KINDS = [    "任务轮询", "无产出长段", "超时转后台",
    "重复调用", "反复编辑同处", "失败循环",
    "串行长调用", "盲改缺验证", "串行未并行",
    "起后台即阻塞等",
    "盲等",
    "命令可合并",
    "subagent 串行",
    "subagent 闲置",
]

DEFAULT_LESSONS = [
    {
        "kind": "任务轮询",
        "fix": "wait=false 探一次结果就去做不依赖它的步骤；长任务拆成能独立跑的子集（pytest -k / 单测 / 单文件）",
        "hits": 0, "evidence": [], "demo": True,
    },
    {
        "kind": "无产出长段",
        "fix": "写一句「这段让我知道了 X」。写不出来 → 换方向，并把「为什么不行」记为产出",
        "hits": 0, "evidence": [], "demo": True,
    },
]

def _lessons_snapshot(items):
    """深拷贝：调用方（如 record_feedback）会就地改写，不能共享对象；
    DEFAULT_LESSONS 的 evidence/feedback 列表也不能被跨调用共享。"""
    return json.loads(json.dumps(items, ensure_ascii=False))


def load_lessons():
    # 设计记录（B3 撤回）：曾试验按 (mtime_ns, size) 缓存解析结果，
    # Windows mtime 粒度约 15ms，同大小快速重写会陈旧命中；且收益仅
    # ~0.3%/报告。一致性价值不足以抵消正确性风险，故保持每次读文件
    # +解析（单次报告内 match_lessons 至多 2N+2 次读取，经验库为 KB 级，
    # 实测 <5ms）。
    path = LESSONS_PATH
    try:
        os.stat(path)
    except FileNotFoundError:
        # 显式指定的库不存在 → 报错。若静默返回示例，用户会以为
        # 「经验库只有两条示例」，而实际是自己路径写错了（实测 55 条 vs 2 条）。
        if LESSONS_PATH_EXPLICIT:
            raise AuditInputError(
                "经验库不存在：%s（--lessons-path 指定）。"
                "若是首次使用请先 --record 建库，或核对路径" % path)
        return _lessons_snapshot(DEFAULT_LESSONS)
    out = []
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict) or not isinstance(item.get("fix"), str) or item.get("kind") not in KNOWN_KINDS:
                    raise ValueError("invalid lesson")
                out.append(item)
            except (ValueError, TypeError) as exc:
                raise AuditInputError("经验库第 %d 行无效；保留原文件，请核对后再记录" % number) from exc
    return out


def save_lessons(items):
    # 跨进程写入必须串行，避免两个会话读取旧快照后相互覆盖。
    if not os.path.exists(LESSONS_PATH + ".lock"):
        raise RuntimeError("经验库写入必须持有锁")
    fd, tmp = tempfile.mkstemp(prefix="lessons-", suffix=".tmp", dir=os.path.dirname(LESSONS_PATH))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for it in items:
                f.write(json.dumps(it, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, LESSONS_PATH)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


class LessonLock:
    # 锁内实际写入通常 <0.1s（KB 级文件+fsync）。超过 STALE_SEC 的锁说明持有
    # 进程已崩溃或被杀——遗留锁会让 --record/--feedback 永久失败，必须可恢复。
    # 极小窗口（检查陈旧与删除之间恰好有新写入者重建锁）可致并发写一次，
    # save_lessons 为原子替换，最坏丢失一条记录；远优于永久锁死。
    STALE_SEC = 60
    DEADLINE_SEC = 5

    def __enter__(self):
        self.path = LESSONS_PATH + ".lock"
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
                        os.remove(self.path)      # 崩溃残留：清理后立即重试
                    except OSError:
                        pass                       # 与其他清理者竞争：重走循环
                    continue
                if time.monotonic() >= deadline:
                    raise AuditInputError("经验库正在写入，或存在遗留 .lock；确认写入进程结束后重试")
                time.sleep(0.05)

    def __exit__(self, *_args):
        os.close(self.fd)
        try:
            os.remove(self.path)                  # 锁可能已被陈旧恢复流程清理
        except OSError:
            pass


def lesson_id(lesson):
    return lesson.get("id") or hashlib.sha256(
        (lesson["kind"] + "\0" + lesson["fix"]).encode()).hexdigest()[:16]


def lesson_stats(lesson):
    """旧 hits 只是记录次数；反馈按独立 case 去重，最后一次结果生效。

    容错：feedback 可能是字符串/None（手改库或旧格式），
    逐条跳过非 dict 项而不是崩溃——实测 `feedback: "bad"` 曾让
    verified_lesson 抛 AttributeError，整个审计失败。
    """
    recommended, adopted, outcomes = set(), set(), {}
    raw_feedback = lesson.get("feedback")
    if not isinstance(raw_feedback, list):
        raw_feedback = []
    for event in raw_feedback:
        if not isinstance(event, dict):
            continue
        case, result = event.get("case"), event.get("event")
        if not case:
            continue
        if result == "recommended":
            recommended.add(case)
        elif result == "adopted":
            adopted.add(case)
        elif result in ("success", "failure") and event.get("evidence"):
            adopted.add(case)
            outcomes[case] = result
    return {"recommended": len(recommended), "adopted": len(adopted),
            "success": sum(x == "success" for x in outcomes.values()),
            "failure": sum(x == "failure" for x in outcomes.values())}


def verified_lesson(lesson):
    stats = lesson_stats(lesson)
    return stats["success"] > 0 and stats["failure"] == 0 and not lesson.get("demo")


def lessons_for(kind):
    """按黑洞类型取解法，命中次数高的在前。"""
    return sorted([l for l in load_lessons() if l.get("kind") == kind],
                  key=lambda x: (-lesson_stats(x)["success"], lesson_id(x)))


def _kw_hits(kw, haystack):
    """关键词命中判定：工具名一律要词边界，其余短词要边界、长短语可子串。

    纯子串匹配会误命中：实测 `list_agents` 出现在某个文件路径片段里，
    导致「串行未并行」信号被一条「重复调用」经验跨类型召回（2% 噪音）。
    所以**工具名形态（全小写+下划线/短横线）无论多长都按词边界判定**——
    `list_agents` 有 11 字符，若按「≥8 就子串」会漏掉这条保护。
    中长短语（≥8 字符，多为报错模板）保留子串匹配，因为报错行里
    关键词常嵌在长句中。
    """
    if not kw:
        return False
    is_tool_name = re.fullmatch(r"[a-z0-9]+([_\-][a-z0-9]+)+", kw) is not None
    if len(kw) >= 8 and not is_tool_name:
        return kw in haystack
    return re.search(r"(?<![a-z0-9_\-])" + re.escape(kw) + r"(?![a-z0-9_\-])",
                     haystack) is not None


def _cross_capable(kws):
    """这组关键词是否足以支撑「跨类型」召回。

    跨类型是高风险动作：经验属于另一个 kind，若只靠一个工具名撞上，
    几乎必然是噪音（实测 list_agents 让「串行未并行」带出「重复调用」经验）。
    判据：
      - 命中 2 个及以上关键词 → 语境足够具体，允许跨类型；
      - 单个关键词时，必须是「语义词」而不是工具名：
        含中文、或长度 ≥8 的短语（多为完整报错模板）才允许。
    工具名形如 list_agents / job_output —— 全小写 ASCII 加下划线，排除。
    """
    if len(kws) >= 2:
        return True
    if not kws:
        return False
    kw = kws[0]
    if any("\u4e00" <= ch <= "\u9fff" for ch in kw):
        return True
    # 工具名形态（list_agents / job_output / run_in_background）不是语义线索，
    # 光靠它撞上几乎必然是跨类型噪音。判据：全 ASCII、无空格、含下划线或短横线。
    if re.fullmatch(r"[a-z0-9]+([_\-][a-z0-9]+)+", kw):
        return False
    return len(kw) >= 8


def _looks_independent(kws, haystack):
    """跨类型召回的额外门槛：命中的关键词不能只是路径/标识符里的碎片。

    允许的情形：关键词两侧是空白、标点、或中文字符（即独立成词）。
    拒绝的情形：紧贴路径分隔符（/ \\ :）或长标识符（形如 a_b_c_d 的片段）。
    """
    for kw in kws:
        if not _kw_hits(kw, haystack):
            continue
        start = 0
        while True:
            i = haystack.find(kw, start)
            if i < 0:
                break
            left = haystack[i - 1] if i > 0 else " "
            right = haystack[i + len(kw)] if i + len(kw) < len(haystack) else " "
            if left not in "/\\:_.-~" and right not in "/\\:_.-~":
                return True
            start = i + 1
    return False


def match_lessons(hole):
    """三层召回：精确命中 → 同类型部分命中 → 同类型通用。

    实测背景（40 会话 / 33 个洞）：旧规则要求同类型也「关键词全部命中」，
    而规则里的关键词往往绑死具体项目细节（sqlite/forge.db/104003），
    换个场景就 0 召回——同类型召回率只有 12%。kind 已经对上了，
    再要求关键词全中等于双重门槛。

    但也不能同类型无条件全召回：那会把无关的 legacy 经验也带出来
    （test_unrelated_legacy_lesson_is_not_recommended 锁定了这个边界）。
    因此分三层，按置信度降序：
      exact   —— match 关键词全部命中（同类型或跨类型都算）
      partial —— 同类型，且命中至少 1 个 match 关键词（可能相关）
      generic —— 同类型，无 match 但声明了 scope=general（通用办法）
    演示条目（demo）只在同类型且没有其它命中时兜底。
    """
    out, seen = [], set()
    ctx = ((hole.get("ctx") or "") + " " + " ".join(hole.get("tools") or [])).lower()
    tools_only = " ".join(str(t) for t in (hole.get("tools") or [])).lower()
    for l in load_lessons():
        key = (l.get("kind"), l.get("fix"))
        if key in seen:
            continue
        kws = [str(k).lower() for k in (l.get("match") or []) if k]
        same = l.get("kind") == hole.get("kind")
        hits = sum(1 for k in kws if _kw_hits(k, ctx))
        if kws and hits == len(kws):
            # 跨类型额外把关（两道）：
            #  1) 命中关键词必须独立出现，不能只是路径/标识符碎片；
            #  2) 不能只有一个泛词命中——单关键词经验（如 match=["list_agents"]）
            #     本质上就该只在同类型里用。实测：会话里用过 list_agents 这个
            #     工具，就让「串行未并行」信号跨类型带出了「重复调用」经验，
            #     语义完全无关。
            if same:
                out.append((l, "same", hits))
                seen.add(key)
            elif _looks_independent(kws, ctx) and _cross_capable(kws):
                out.append((l, "cross", hits))
                seen.add(key)
        elif same and kws and hits >= 1:
            out.append((l, "same", hits))          # 部分命中：低一档置信
            seen.add(key)
        elif same and l.get("scope") == "general":
            # scope=general = 作者明确声明「这条适用于整个 kind」。
            # 不能因为带了 match 关键词就要求全中——关键词是为了给具体
            # 场景加提示，不是召回的硬门槛（实测盲改缺验证因此 0 召回）。
            out.append((l, "same", hits))
            seen.add(key)
        elif same and not kws and l.get("demo"):
            out.append((l, "same", 0))             # 兜底示例，排序最后
            seen.add(key)
    def _rank(t):
        lesson, way, hits = t
        kws = len(lesson.get("match") or [])
        ratio = (hits / kws) if kws else 0.0
        return (
            not verified_lesson(lesson),     # 验证过的优先
            way != "same",                   # 同类型优先于跨类型
            -ratio,                          # 命中率高的优先（不是命中数：1/1 胜过 1/3）
            -hits,
            -kws,
            -lesson_stats(lesson)["success"],
            lesson_id(lesson),
        )
    return sorted(out, key=_rank)


def first_fix(hole):
    """优先用沉淀过的具体解法；没有才退回通用动作。"""
    for l, _w, _hits in match_lessons(hole):
        if verified_lesson(l):
            return l["fix"]
    return hole["action"]


def lesson_tag(lesson, way=None):
    """经验在报告里的标签：与 render 的措辞保持一处定义。"""
    if lesson.get("demo"):
        return "示例"
    stats = lesson_stats(lesson)
    tag = "有反例，待复核" if stats["failure"] else (
        "已验证成功%d个案例" % stats["success"] if stats["success"] else "候选，未验证复用")
    if way == "cross":
        tag = "跨类型·" + tag
    return tag


def record_lesson(kind, fix, evidence=None, match=None, scope=None, boundary=None):
    with LessonLock():
        return _record_lesson(kind, fix, evidence, match, scope, boundary)


def _record_lesson(kind, fix, evidence, match, scope, boundary):
    """记录是候选经验；不能据此声称复用成功。"""
    # fix 归一化：CLI 层会 strip，但直接调用/批量导入不会。
    # 不归一会让 "fix D" 与 " fix D " 被当成两条不同经验（实测确认），
    # 造成库内重复条目——而重复条目只会稀释召回，不会带来新信息。
    fix = (fix or "").strip()
    if not fix:
        raise AuditInputError("fix 不能为空或纯空白：它是经验的主体动作描述")
    if kind not in KNOWN_KINDS:
        raise AuditInputError("未知类型 %r；可用：%s" % (kind, " / ".join(KNOWN_KINDS)))
    # scope 白名单也必须由引擎层把关：CLI 的 argparse choices 只保护 `--record`，
    # 而插件/批量脚本直接调 record_lesson。实测 scope="bogus"/"GENERAL"/123
    # 曾被原样落库，让 match_lessons 的 `scope == "general"` 判定悄悄失效。
    if scope is not None and scope not in KNOWN_SCOPES:
        raise AuditInputError(
            "scope 必须是 %s 之一（或省略），收到 %r"
            % (" / ".join(KNOWN_SCOPES), scope))
    # 落库前裁剪超长字段：实测 evidence/boundary 曾可写入 10 万字符。
    fix = _clip_field(fix)
    evidence = _clip_field(evidence)
    boundary = _clip_field(boundary)
    # record 是「建库」的唯一入口：显式路径不存在时应从空库开始，
    # 不能因为 load_lessons() 对显式缺失路径报错而无法创建。
    # read 场景（--lessons/审计）仍按严格语义报错。
    try:
        items = load_lessons()
    except AuditInputError:
        if LESSONS_PATH_EXPLICIT:
            items = []
        else:
            raise
    now = int(time.time())
    # 关键词去重并保持首次出现顺序：重复词不影响召回，但会扭曲排序
    # （match_lessons 按 hits/len(match) 算命中率，"a,a,b,b" 与 "a,b" 名义相同）。
    # 同时限制单关键词长度，防止 500 字符的单词拖慢每次召回的字符串匹配。
    seen_kw = set()
    kws = []
    for raw in (match or "").replace("，", ",").split(","):
        w = raw.strip()
        if not w or w in seen_kw:
            continue
        if len(w) > 200:
            w = w[:200]
        seen_kw.add(w)
        kws.append(w)
    for it in items:
        if it.get("kind") == kind and it.get("fix") == fix:
            it["hits"] = it.get("hits", 0) + 1
            it["last_used"] = now
            if evidence and evidence not in it.get("evidence", []):
                it.setdefault("evidence", []).append(evidence)
            if kws:
                it["match"] = sorted(set(it.get("match") or []) | set(kws))
            it["id"] = lesson_id(it)
            if scope is not None:
                it["scope"] = scope
            else:
                it.setdefault("scope", "contextual")
            if boundary:
                it["boundary"] = boundary
            it.pop("demo", None)
            save_lessons(items)
            return it, False
    it = {
        "kind": kind, "fix": fix, "hits": 1, "created": now, "last_used": now,
        "evidence": [evidence] if evidence else [],
    }
    if kws:
        it["match"] = kws
    it.update(id=lesson_id(it), scope=scope or "contextual", feedback=[])
    if boundary:
        it["boundary"] = boundary
    items.append(it)
    save_lessons(items)
    return it, True


def record_feedback(identity, event, case, evidence=None):
    if event not in FEEDBACK_EVENTS:
        raise AuditInputError(
            "event 必须是 %s 之一，收到 %r" % (" / ".join(FEEDBACK_EVENTS), event))
    if event in ("success", "failure") and not evidence:
        raise AuditInputError("成功/失败反馈必须给 --evidence，不能靠推荐次数判定有效")
    # case 是「独立任务标识」，去重与晋升判定都靠它。
    # 空/空白/None 会被当成一个独立案例（实测 `"  "` 与 `""` 各算一次），
    # 导致"3 个独立成功案例"的晋升门槛被无意义地凑满。
    if case is None:
        raise AuditInputError("反馈需要独立的 case 标识（不能用空值）")
    case = str(case).strip()
    if not case:
        raise AuditInputError("反馈的 case 标识不能为空或纯空白")
    if len(case) > 200:
        case = case[:200]
    with LessonLock():
        items = load_lessons()
        item = next((x for x in items if lesson_id(x) == identity), None)
        if item is None or item.get("demo"):
            raise AuditInputError("找不到该经验，或它只是示例")
        item["id"] = identity
        history = item.setdefault("feedback", [])
        same_case = [x for x in history if x.get("case") == case]
        previous = ([x for x in same_case if x.get("event") in ("success", "failure")]
                    if event in ("success", "failure") else [x for x in same_case if x.get("event") == event])
        if not previous or previous[-1].get("event") != event or previous[-1].get("evidence") != evidence:
            history.append({"case": case, "event": event,
                            "evidence": _clip_field(evidence),
                            "time": int(time.time())})
            save_lessons(items)
        return item


# ---------------------------------------------------------------- 报错查经验（query）
#
# 与 match_lessons（审计报告侧推荐）的分工：报错发生时由 Agent 主动调用，
# 输入是工具名+报错摘要，输出至多一条已验证经验（经验 ID/下一步/验证方法）。
# 只召回 verified_lesson 且 match 关键词全部命中「工具名 + 归一化报错文本」
# 的条目——与失败循环聚合同用 norm_err_text（路径→PATH），正式库 pattern_key
# 形态的关键词因此能命中真实报错。无关键词的经验不参与报错召回（无法判定
# 适用范围，宁缺毋滥；scope: general 经验仍走审计报告侧）。
#
# 会话去重：同一会话同一错误（工具名+归一化报错的指纹）只提示一次；状态
# 存 <经验库同目录>/.query_state/<sha16(session)>.json，7 天过期。状态文件
# 不是经验库——原子替换写、不加锁（并发重复提示的最坏情形可接受，经验库
# 本身零写入），首次提示的时间与经验 ID 留在 repeat 应答里供回填。


QUERY_STATE_TTL_SEC = 7 * 24 * 3600


def _query_state_dir():
    return os.path.join(os.path.dirname(LESSONS_PATH), ".query_state")


def _query_state_path(session):
    return os.path.join(_query_state_dir(),
                        hashlib.sha256(session.encode("utf-8")).hexdigest()[:16] + ".json")


def _err_fingerprint(tool, error_text):
    return hashlib.sha256(("%s\0%s" % ((tool or "").strip().lower(),
                                       norm_err_text(error_text or ""))).encode("utf-8")).hexdigest()[:16]


def _load_query_state(session):
    st = {"session": session, "seen": {}}
    try:
        with open(_query_state_path(session), encoding="utf-8") as fh:
            doc = json.load(fh)
        if isinstance(doc, dict) and isinstance(doc.get("seen"), dict):
            st["seen"] = {k: v for k, v in doc["seen"].items()
                          if isinstance(v, dict) and isinstance(v.get("lesson"), str)}
    except (OSError, ValueError):
        pass
    return st


def _save_query_state(st):
    d = _query_state_dir()
    os.makedirs(d, exist_ok=True)
    now = int(time.time())
    st["seen"] = {k: v for k, v in st["seen"].items() if now - v.get("time", 0) <= QUERY_STATE_TTL_SEC}
    try:  # 顺带清理其他会话的过期状态（best effort，目录 KB 级）
        for name in os.listdir(d):
            p = os.path.join(d, name)
            try:
                if now - os.path.getmtime(p) > QUERY_STATE_TTL_SEC:
                    os.remove(p)
            except OSError:
                pass
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(prefix="qstate-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"session": st["session"], "seen": st["seen"]}, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, _query_state_path(st["session"]))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def query_lesson(tool, error_text, session=None):
    """报错查经验：返回 {status, lesson_id, lesson, ...}；status ∈ hit/no_hit/repeat。

    排序（最相关在前）：match 关键词多者优先（更具体）→ 验证成功案例多者
    优先 → 经验 ID 字典序（稳定）。同一报错在提供 session 时只提示一次。
    """
    ctx = ("%s %s" % ((tool or "").strip(), norm_err_text(error_text or ""))).lower()
    cands = []
    for l in load_lessons():
        if not verified_lesson(l):
            continue
        kws = [str(k).lower() for k in (l.get("match") or []) if k]
        if kws and all(k in ctx for k in kws):
            cands.append(l)
    cands.sort(key=lambda l: (-len(l.get("match") or []),
                              -lesson_stats(l)["success"], lesson_id(l)))

    fp = _err_fingerprint(tool, error_text)
    base = {"tool": tool or "", "error_norm": norm_err_text(error_text or ""),
            "verified_total": sum(1 for l in load_lessons() if verified_lesson(l)),
            "library_total": len(load_lessons())}
    if session:
        base["state_path"] = _query_state_path(session)

    if session:
        st = _load_query_state(session)
        seen = st["seen"].get(fp)
        if seen is not None:
            return {**base, "status": "repeat", "repeat": True, "lesson": None,
                    "lesson_id": seen.get("lesson"), "first_prompted": seen.get("time")}

    if not cands:
        return {**base, "status": "no_hit", "repeat": False, "lesson": None, "lesson_id": None}

    best = cands[0]
    if session:
        st = _load_query_state(session)
        st["seen"][fp] = {"lesson": lesson_id(best), "time": int(time.time()),
                          "tool": (tool or "")[:80]}
        _save_query_state(st)
    return {**base, "status": "hit", "repeat": False,
            "lesson": {**best, "id": lesson_id(best), "stats": lesson_stats(best)},
            "lesson_id": lesson_id(best)}


def render_query_result(res):
    """query 结果的文本形态：Agent 直接读，按「下一步」行动、按「验证方法」回填。"""
    if res["status"] == "hit":
        l = res["lesson"]
        stats = l["stats"]
        # 字段可能被手改成非字符串（实测 boundary=123 时
        # `l.get("boundary") or ...` 返回 int，%s 拼接会抛 TypeError）。
        boundary = l.get("boundary")
        boundary = "" if boundary is None else str(boundary)
        verify = l.get("verify") or boundary or \
            "复用后以实际结果为准：成功/失败都回填 feedback（success/failure 必须附证据）"
        lines = ["命中经验 [%s] %s 类型: %s" % (lesson_tag(l), l["id"], l["kind"]),
                 "下一步: %s" % _short(l["fix"]),
                 "验证方法: %s" % verify]
        if l.get("verify") and boundary:
            lines.append("适用边界: %s" % boundary)
        if l.get("evidence"):
            ev = l["evidence"]
            ev = ev if isinstance(ev, list) else [ev]
            lines.append("证据: %s" % "; ".join(_short(str(x), 80) for x in ev[:3]))
        lines.append("回填: blackhole_lessons action=feedback event=success|failure "
                     "lesson_id=%s case=<独立任务标识> evidence=<实际结果>" % l["id"])
        return "\n".join(lines)
    if res["status"] == "repeat":
        return ("重复报错: 该报错在本会话 %s 已提示过经验 %s，本次不再重复提示。"
                "按首次提示的「下一步」操作，或用 feedback（case=<独立任务标识>）回填实际结果。"
                % (time.strftime("%H:%M:%S", time.localtime(res.get("first_prompted") or 0)),
                   res.get("lesson_id")))
    return ("未命中: 没有已验证经验匹配该报错（库 %d 条，已验证 %d 条）。"
            "按常规方式排查，不要原样重试同一操作。"
            % (res["library_total"], res["verified_total"]))


# ---------------------------------------------------------------- render

def rid_of(path):
    m = re.search(r"(session-[0-9a-f-]{36})", path)
    if m:
        return m.group(1)
    stem = os.path.basename(path).split(".")[0]
    return os.path.basename(os.path.dirname(path)) if stem == "session" else stem


def _window_note(rep):
    win = rep.get("window_min")
    return "最近 %g 分钟（以日志最后一条事件的时间为终点）" % win if win else "整个会话日志"


def _fmt_local_ts(ms):
    """本地时间显示；损坏日志的时间戳可能超出平台可表示范围
    （1e18 毫秒、负值在 Windows localtime 会 OSError）——降级为原始值，
    不能让复盘导出在 --json/render/brief 都正常时单独崩溃。"""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000.0))
    except (OSError, OverflowError, ValueError):
        return "（超出可显示范围，仅保留原始毫秒值）"


def render(rep, path, top=5):
    rid = rid_of(path)
    print("=" * 72)
    print("时间黑洞审计  %s" % rid)
    print("活动 %s / %d 步 / %d 次工具调用 / 步内合计 %s" % (
        fmt_dur(rep["active"]), len(rep["rows"]), rep["calls"], fmt_dur(rep["total"])))
    print("数据范围: %s" % _window_note(rep))
    for warning in rep.get("warnings", []):
        print("提示: " + warning)
    if rep.get("status") == "insufficient_data":
        print("结论: 数据不足，不能判断是否存在时间黑洞。")
        print("→ 现在做: 核对日志、时间窗口和未结束的步骤。")
        return

    _tot = sum(rep["tool_t"].values())
    tt = [(k, v) for k, v in sorted(rep["tool_t"].items(), key=lambda x: -x[1])
          if _tot and v / _tot >= 0.01][:5]
    if tt and _tot > 0:
        s = _tot
        print("工具调用累计时长（并行调用可重叠）: " + " | ".join("%s %.0f%%" % (k, 100 * v / s) for k, v in tt))

    # 数据不完整时也把已掌握的那部分指标说清楚——「结论不完整」不等于「没有结论」。
    # 只覆盖已闭合步骤能算出的东西，并明确标注范围。
    if rep.get("status") == "partial":
        para = rep.get("parallel") or {}
        if para:
            print("已知区间内的并行度（数据不完整，仅覆盖已闭合步骤）: "
                  "subagent %d 次 / 后台 %d 次 / 并发步 %d / 共 %d 步" % (
                      para.get("subagent", 0), para.get("background", 0),
                      para.get("concurrent_steps", 0), para.get("steps", 0)))
            ln, ls, _a, _b = para.get("longest", (0, 0, 0, 0))
            if ln:
                print("  最长连续单工具步 %d 次 / %s（该区间内无并发）" % (ln, fmt_dur(ls)))

    if not rep["holes"]:
        print("\n在可分析记录中未发现达到阈值的低效信号。")
    else:
        print()
        for i, h in enumerate(rep["holes"][:top], 1):
            mark = "🔴" if h.get("priority", 1) >= 2 else "🟡"
            pct = (" %.0f%%" % (100 * h["ratio"])) if h["ratio"] > 0 else ""
            print("%s #%d %s%s  %s" % (mark, i, h["kind"], pct, h["evidence"]))
            print("   %s" % h["detail"])
            matched = match_lessons(h)
            real = [(l, w) for l, w, _h in matched if not l.get("demo")]
            show = real[:2] if real else []
            if show:
                for l, w in show:
                    print("   ▶ [%s %s] %s" % (lesson_tag(l, w), lesson_id(l), _short(l["fix"])))
                    if l.get("boundary"):
                        print("      适用边界: " + l["boundary"])
            else:
                print("   ▶ %s" % h["action"])
            print()

    # 一句话结论 → 必须落到一个动作上，否则这份报告就只是总结
    if rep["holes"]:
        h = rep["holes"][0]
        print("结论: 优先核查「%s」。" % h["kind"])
        if h.get("sev"):
            print("   相关步骤涉及 %s；不能直接当作浪费或可节省时间。" % fmt_dur(h["sev"]))
        action = first_fix(h)
    else:
        print("结论: " + ("记录不完整，不能据此判断整体健康。" if rep.get("status") == "partial" else "当前记录未触发检测规则。"))
        action = "结合实际任务结果继续判断；只读探索同样可能产生有效结论。"

    ready = [l for l in load_lessons() if verified_lesson(l) and lesson_stats(l)["success"] >= 3]
    if ready:
        print()
        print("待人工审核的通用规则候选（至少3个独立成功案例，且无已记录反例）:")
        for l in ready[:3]:
            print("  - %s: %s" % (l["kind"], _short(l["fix"])))
    print("→ 现在做: %s" % action)


def render_review(rep, path, top=5):
    """结构化复盘材料（Markdown，stdout，只读）：
    数据范围、状态、信号与证据、匹配经验与适用边界、需要人工/模型判断的部分、下一步。"""
    rid = rid_of(path)
    out = []
    out.append("# 时间黑洞复盘材料 — %s" % rid)
    out.append("")
    out.append("- 数据范围: %s" % _window_note(rep))
    out.append("- 最后事件: %s（毫秒时间戳 %d）" % (
        _fmt_local_ts(rep["last_event_ms"]) if rep.get("last_event_ms") else "无",
        rep.get("last_event_ms") or 0))
    out.append("- 规模: %d 步（完整 %d，未结束 %d），%d 次工具调用，活动 %s，步内合计 %s" % (
        len(rep["rows"]), rep["completed_steps"], rep.get("incomplete_steps", 0),
        rep["calls"], fmt_dur(rep["active"]), fmt_dur(rep["total"])))
    _tot = sum(rep["tool_t"].values())
    if _tot > 0:
        tt = sorted(rep["tool_t"].items(), key=lambda x: -x[1])[:5]
        out.append("- 工具耗时分布（区间并集，并行重叠只计一次；代理指标，不等于浪费）: " + ", ".join(
            "%s %s（%.0f%%）" % (k, fmt_dur(v), 100 * v / _tot) for k, v in tt))
    out.append("- 状态: `%s` — %s" % (rep["status"], STATUS_MEANING.get(rep["status"], "")))
    for w in rep.get("warnings", []):
        out.append("- 警告: %s" % w)
    out.append("")
    out.append("## 信号与证据")
    out.append("")
    if not rep["holes"]:
        out.append("未发现达到阈值的低效信号。这只说明机械规则没有触发，"
                   "不证明这段工作高效——只读探索、必要重试都可能是合理工作。")
    for i, h in enumerate(rep["holes"][:top], 1):
        pct = ("（占步内合计 %.0f%%）" % (100 * h["ratio"])) if h["ratio"] > 0 else ""
        out.append("### %d. %s%s" % (i, h["kind"], pct))
        out.append("- 证据: %s" % _md_inline(h["evidence"]))
        out.append("- 细节: %s" % _md_inline(h["detail"]))
        if h.get("sev"):
            out.append("- 相关步骤涉及 %s（代理指标，不等于浪费或可节省时间）" % fmt_dur(h["sev"]))
        out.append("- 涉及工具: %s" % (", ".join(h.get("tools") or []) or "—"))
        out.append("- 通用动作: %s" % h["action"])
        out.append("- 需要人工/模型判断: %s" % VERIFY_QUESTIONS.get(h["kind"], "结合任务证据核查。"))
        matched = [(l, w) for l, w, _h in match_lessons(h) if not l.get("demo")][:2]
        if matched:
            out.append("- 匹配经验（检索范围: 同类型，或跨类型关键词全命中）:")
            for l, w in matched:
                line = "  - [%s] `%s` %s" % (lesson_tag(l, w), lesson_id(l), _short(l["fix"]))
                out.append(line)
                if l.get("boundary"):
                    out.append("    - 适用边界: %s" % _md_inline(l["boundary"]))
        out.append("")
    out.append("## 复盘问题（供下一轮任务前回看）")
    out.append("")
    out.append("1. 本次会话最大的时间去向是什么？哪些是任务必需，哪些可以避免？")
    out.append("2. 上面的信号哪些核实为真？根因是什么？（核实后可用 --record 沉淀，用 --feedback 记录采用与验证结果）")
    out.append("3. 下次同类任务开工前，哪一条经验应该先被想起？")
    out.append("")
    if rep["holes"]:
        h = rep["holes"][0]
        out.append("## 下一步")
        out.append("")
        out.append("优先核查「%s」：%s" % (h["kind"], first_fix(h)))
    else:
        out.append("## 下一步")
        out.append("")
        out.append("结合实际任务结果继续判断；只读探索同样可能产生有效结论。")
    print("\n".join(out))


def brief(rep):
    if rep.get("status") == "insufficient_data":
        return "数据不足：没有可计时的完整步骤；核对日志、窗口或未结束的任务"
    if not rep["holes"]:
        if rep.get("status") == "partial":
            return "数据不完整：未发现达到阈值的信号，不能判断整体健康"
        return "未发现达到阈值的信号：%d 步 / %s" % (len(rep["rows"]), fmt_dur(rep["total"]))
    h = rep["holes"][0]
    pct = ("%.0f%% " % (100 * h["ratio"])) if h["ratio"] > 0 else ""
    prefix = "记录部分可用；" if rep.get("warnings") else ""
    if rep.get("window_min"):
        prefix = ("近%g分钟窗口；" % rep["window_min"]) + prefix
    return prefix + "待核查「%s」%s→ %s" % (h["kind"], pct, first_fix(h)[:100])


# ---------------------------------------------------------------- trend

# 「速度型」信号：它们的 sev 是可直接回收的等待/轮次时间，而不是"相关步骤耗时"。
# 其它信号（失败循环/反复编辑等）的 sev 是受影响步骤的总时长，不能当作可回收时间相加。
# 「subagent 串行」也计入：它的 sev 是 sum - max，即并行本可省下的墙钟，
# 与其余四项同为「可直接回收的等待」而非「受影响步骤时长」。
SPEED_KINDS = ("起后台即阻塞等", "盲等", "命令可合并", "超时转后台",
               "subagent 串行")


def _speed_summary(agg_sec):
    """把速度型信号的可回收时长汇总成一行结论。

    agg_sec: {kind: 累计秒}
    返回 (总秒数, 排名列表)。空 dict 返回 (0, [])。
    """
    rows = [(k, v) for k, v in agg_sec.items() if k in SPEED_KINDS and v >= 1]
    rows.sort(key=lambda x: -x[1])
    return sum(v for _k, v in rows), rows


def cmd_trend(n, since=None, as_json=False):
    """跨会话聚合：同一个黑洞在越多会话里复现，越不是偶发。

    性能与可用性（实测）：508 个会话全量分析需 18.5 秒，瓶颈在读盘/解压
    （占 86%，analyze 本身只占 14%）。这本身无法避免——趋势必须全量看。
    但两个地方要改：
      1. 默认上限：一次分析几百个会话会让人以为卡死，且趋势统计不需要那么多样本；
      2. 进度提示写 stderr：stdout 可能被脚本消费，进度不能混进去。

    `as_json` 与 `--json` 对齐：argument-hint 把 --json 列为通用选项，
    此前 --trend + --json 会输出人类可读文本（静默的接口不一致）。
    """
    if n > MAX_TREND_SESSIONS:
        sys.stderr.write("[i] --trend %d 超出单次上限，只分析最近 %d 个会话"
                         "（每个约 0.04s，全量更慢且统计意义不增）\n"
                         % (n, MAX_TREND_SESSIONS))
        n = MAX_TREND_SESSIONS
    files = session_files()[:n]
    # 排除正在写入的当前会话：它的时长/信号每轮都在涨，
    # 会让「最近 N 个」的统计在相邻两次调用之间变化达 0.5h 量级，
    # 看起来像代码行为变了，实际是自身增长（实测 13.87h → 14.4h 全来自此）。
    # 用一个很短的 mtime 阈值判断「活跃」：当前会话每秒都在追加事件。
    live_id = os.environ.get("DSH_SESSION_ID", "").replace("session-", "")
    if live_id:
        files = [f for f in files if live_id not in f] or files[:1]
    if not files:
        raise AuditInputError("找不到会话文件")

    agg = {}
    usable = 0
    skipped = 0
    total_files = len(files)
    for idx, f in enumerate(files, 1):
        try:
            rep = analyze(read_events(f), since)
        except AuditInputError as exc:
            print("跳过不可读取会话: %s" % exc)
            skipped += 1
            continue
        if rep["status"] in ("insufficient_data", "partial") or rep["warnings"]:
            skipped += 1
            continue
        usable += 1
        rid = rid_of(f)
        for h in rep["holes"]:
            k = h["kind"]
            a = agg.setdefault(k, {"sec": 0.0, "sessions": [], "best": None,
                                   "action": h.get("action")})
            a["sec"] += h.get("sev") or 0
            a["sessions"].append(rid)
            if a["best"] is None or (h.get("ratio") or 0) > (a["best"].get("ratio") or 0):
                a["best"] = h
        # 进度写 stderr：大批量时让用户看到在动，而不是以为卡死。
        if total_files >= 60 and idx % 40 == 0:
            sys.stderr.write("[i] 已分析 %d/%d 个会话…\n" % (idx, total_files))

    if as_json:
        rows = []
        for k, a in sorted(agg.items(),
                           key=lambda x: (-len(set(x[1]["sessions"])), -x[1]["sec"])):
            ns = len(set(a["sessions"]))
            rows.append({
                "kind": k,
                "sessions": ns,
                "usable": usable,
                "ratio": (ns / usable) if usable else 0.0,
                "related_sec": a["sec"],
                "sessions_ids": sorted(set(a["sessions"])),
                "action": (a["best"] or {}).get("action", ""),
            })
        print(json.dumps({
            "analysed": len(files),
            "usable": usable,
            "skipped": skipped,
            "window_min": since,
            "signals": rows,
            "speed_reclaimable_sec": _speed_summary(
                {r["kind"]: r["related_sec"] for r in rows})[0],
        }, ensure_ascii=False, indent=2))
        return 0 if usable else 2

    print("最近 %d 个会话，%d 个可分析，%d 个数据不足/不完整" % (len(files), usable, skipped))
    if not usable:
        print("数据不足，不能判断跨会话趋势。")
        return 2
    print("同一个黑洞在越多会话复现，越不是偶发——那该改工作流，不是改这一次。\n")
    # 速度型信号单独给个总账：它们的 sev 就是可直接回收的等待时间
    sp_total, sp_rows = _speed_summary({k: a["sec"] for k, a in agg.items()})
    if sp_total >= 60:
        print("可直接回收的等待时间：%s（%d 类速度型信号）" % (
            fmt_dur(sp_total), len(sp_rows)))
        # 注意 len(sp_rows) 是「有值的类数」，不是 SPEED_KINDS 的长度
        for k, v in sp_rows[:3]:
            print("    %-14s %s" % (k, fmt_dur(v)))
        print("    这些都是纯等待/多余轮次，不是干活的时间——改掉就是净省。\n")
    for k, a in sorted(agg.items(),
                       key=lambda x: (-len(set(x[1]["sessions"])), -x[1]["sec"])):
        ns = len(set(a["sessions"]))
        flag = "  ← 多数会话重复出现，需核实是否为同一原因" if ns >= max(2, usable // 2 + 1) else ""
        sec_s = fmt_dur(a["sec"]) if a["sec"] >= 1 else "—"
        print("- %s：%d/%d 个可分析会话出现，相关步骤累计 %s%s" % (k, ns, usable, sec_s, flag))
        print("    %s" % (a["best"] or {}).get("action", "")[:70])
    return 0


# ---------------------------------------------------------------- main

def _main():
    _out()
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", default=None)
    ap.add_argument("--recent", type=int, default=0)
    ap.add_argument("--since", type=float, default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--brief", action="store_true")
    ap.add_argument("--review", action="store_true",
                    help="输出结构化复盘材料（Markdown）；可与 --session/--since/--json 组合")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--lessons", action="store_true", help="列出教训库")
    ap.add_argument("--pending", action="store_true",
                    help="配合 --lessons：只列还没被真实结果验证过的规则（按影响面排序）")
    ap.add_argument("--record", action="store_true", help="沉淀一条解法")
    ap.add_argument("--kind", default=None, help="黑洞类型，须与审计输出一致")
    ap.add_argument("--fix", default=None, help="具体做法")
    ap.add_argument("--evidence", default=None, help="出处，如 session-xxx T70.S59")
    ap.add_argument("--match", default=None, help="跨类型关键词，逗号分隔，如 pytest,全量")
    ap.add_argument("--scope", choices=("contextual", "general"), default=None,
                    help="contextual 需匹配关键词；general 明确声明为同类型通用经验")
    ap.add_argument("--boundary", default=None, help="经验适用环境、前提和不适用情况")
    ap.add_argument("--feedback", choices=("recommended", "adopted", "success", "failure"),
                    help="显式记录推荐、采用或经过验证的结果；审计本身不写经验库")
    ap.add_argument("--lesson-id", default=None)
    ap.add_argument("--case", default=None, help="独立任务/验证案例标识；同案例重复反馈不重复计数")
    ap.add_argument("--trend", type=int, default=0, help="聚合最近 N 个会话的同类黑洞")
    ap.add_argument("--query", action="store_true",
                    help="报错查经验：--tool 工具名 + --error 报错摘要 → 至多一条已验证经验")
    ap.add_argument("--tool", default=None, help="query: 产生报错的工具名")
    ap.add_argument("--error", default=None, help="query: 报错摘要；路径/URL 归一化后再匹配 match 关键词")
    ap.add_argument("--query-session", default=None,
                    help="query: 会话标识；同会话同一错误只提示一次（缺省不去重、零写入）")
    ap.add_argument("--lessons-path", default=None,
                    help="经验库文件路径（默认脚本同目录 lessons.jsonl；测试/隔离副本用）")
    a = ap.parse_args()
    # --lessons --pending --session 是合法组合：用会话实际触发的信号来
    # 筛出「这次就能验证」的规则。所以 --session 在 lessons+pending 时不算冲突。
    _session_is_filter = a.lessons and a.pending
    if sum(bool(x) for x in (a.trend, a.lessons, a.record, a.feedback, a.recent,
                             (a.session and not _session_is_filter), a.query)) > 1:
        ap.error("--trend/--lessons/--record/--feedback/--recent/--session/--query 每次只选一种模式")
    if not a.query and (a.tool or a.error or a.query_session):
        ap.error("--tool/--error/--query-session 只能与 --query 搭配")
    if a.pending and not a.lessons:
        # 否则 --pending 被静默忽略，用户以为看到了待验证清单，实际跑了普通审计
        ap.error("--pending 必须与 --lessons 搭配（--lessons --pending）")
    if a.lessons_path:
        set_lessons_path(a.lessons_path)
    if a.recent < 0 or a.trend < 0 or a.top <= 0:
        ap.error("会话数量不能为负数，--top 必须为正整数")
    if a.since is not None and (not math.isfinite(a.since) or a.since <= 0):
        ap.error("--since 必须为正的有限分钟数")

    if a.trend:
        return cmd_trend(a.trend, a.since, as_json=a.json)

    if a.lessons:
        items = load_lessons()
        if not items:
            print("(教训库为空。用 --record 沉淀第一条)")
            return 0
        if a.json:
            print(json.dumps([{**it, "id": lesson_id(it), "stats": lesson_stats(it)} for it in items], ensure_ascii=False, indent=2))
            return 0
        # --pending：只列「还没被真实使用验证过」的规则，按影响面排序。
        # 存在的意义：库里 30+ 条规则时，用户不知道先验证哪条。
        # 「影响面」优先看被召回/记录次数——召回多的规则错了会误导更多次。
        if a.pending:
            pend = [it for it in items
                    if not it.get("demo") and not verified_lesson(it)]
            # --pending 配 --session：只留下「这次会话触发了对应信号」的规则。
            # 意义：验证有真实成本，而刚跑完审计的会话正好提供了验证素材——
            # 把「可验证的机会」和「待验证的规则」直接接上，降低往返成本。
            scope_note = ""
            if a.session:
                try:
                    _rep = analyze(read_events(find_session(a.session)), a.since)
                    _kinds = {h["kind"] for h in _rep["holes"]}
                except AuditInputError as exc:
                    sys.stderr.write("[!] 无法读取该会话，忽略 --session 过滤：%s\n" % exc)
                    _kinds = set()
                if _kinds:
                    pend = [it for it in pend if it.get("kind") in _kinds]
                    scope_note = "（只含本会话触发过信号的类型：%s）" % " / ".join(sorted(_kinds))
            if not pend:
                print("没有待验证规则。")
                return 0
            pend.sort(key=lambda x: (-(x.get("hits") or 0), -lesson_stats(x)["adopted"],
                                     lesson_id(x)))
            total = len([it for it in items if not it.get("demo")])
            print("待验证规则 %d/%d 条（按影响面排序：记录/采用次数多的先验证）%s"
                  % (len(pend), total, scope_note))
            print("验证方法：真实用到某条规则后，按下面的形状回填——")
            print("  --feedback success|failure --lesson-id <id> --case <独立任务> "
                  "--evidence <实际结果>")
            print("没有 evidence 的 success/failure 不予记录，防止靠次数凑验证。")
            for it in pend:
                stats = lesson_stats(it)
                used = (it.get("hits") or 0) + stats["adopted"] + stats["recommended"]
                print("[%s] %s %s → %s" % (
                    "影响面 %d" % used if used else "从未被用过",
                    lesson_id(it), it["kind"], _short(it["fix"], 120)))
                if it.get("match"):
                    print("     匹配词: %s" % ", ".join(it["match"][:6]))
            return 0
        for it in sorted(items, key=lambda x: (-lesson_stats(x)["success"], lesson_id(x))):
            stats = lesson_stats(it)
            tag = "示例" if it.get("demo") else "记录%d次；推荐%d/采用%d/成功%d/失败%d" % (
                it.get("hits", 0), stats["recommended"], stats["adopted"], stats["success"], stats["failure"])
            print("[%s] %s %s → %s" % (tag, lesson_id(it), it["kind"], _short(it["fix"])))
            if it.get("evidence"):
                # evidence 是用户写入的自由文本，可能很长（实测 2000 字会产出
                # 2006 字符的单行）。逐条截断后再拼接。
                print("      %s" % "; ".join(_short(x, 80) for x in it["evidence"][:3]))
        return 0

    if a.record:
        if not a.kind or not a.fix or not a.fix.strip():
            sys.stderr.write("[!] --record 需要同时给 --kind 和 --fix\n")
            return 1
        if a.kind not in KNOWN_KINDS:
            sys.stderr.write("[!] 未知类型 %r，沉淀了也匹配不上。可用：%s\n" % (
                a.kind, " / ".join(KNOWN_KINDS)))
            return 1
        it, new = record_lesson(a.kind, a.fix.strip(), a.evidence, a.match, a.scope, a.boundary)
        print(("[新增候选] " if new else "[再次记录] ") + "%s %s → %s  (记录=%d)" % (
            lesson_id(it), it["kind"], it["fix"], it["hits"]))
        if not it.get("match") and it.get("scope") != "general":
            print("提示: 没有匹配词，暂不自动推荐；补充 --match 或明确声明 --scope general。")
        print("记录次数不等于验证成功次数。")
        return 0

    if a.feedback:
        if not a.lesson_id or not a.case or not a.case.strip():
            ap.error("--feedback 需要 --lesson-id 和 --case")
        it = record_feedback(a.lesson_id, a.feedback, a.case.strip(), a.evidence)
        print(json.dumps({"id": lesson_id(it), "stats": lesson_stats(it)}, ensure_ascii=False))
        return 0

    if a.query:
        if not a.error or not a.error.strip():
            sys.stderr.write("[!] --query 需要非空的 --error 报错摘要（--tool 建议一并提供）\n")
            return 1
        res = query_lesson(a.tool, a.error, a.query_session)
        if a.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(render_query_result(res))
        return 0

    if a.recent:
        files = session_files()[:a.recent]
    else:
        one = find_session(a.session)
        files = [one] if one else []

    if not files:
        raise AuditInputError("找不到指定/当前会话文件；请核对 --session 或 DSH_SESSION_ID")

    out = []
    for f in files:
        evs = read_events(f)
        rep = analyze(evs, a.since)
        # 跨轮次提醒：同一会话同一种 kind 再次出现时，把「第 N 次」写进 detail。
        # 只在审计单会话时有意义（--recent/--trend 是横向比较，不是同一会话重复）。
        single = not a.recent and not a.trend and len(files) == 1
        if single and rep["holes"]:
            try:
                # 会话 id 必须进状态 key：文案说的是「本会话第 N 次」，
                # 若只按经验库记账，审计别的会话会污染本会话的计数。
                sid = rid_of(f)
                annotate_recurrence(rep["holes"], session=sid)
                record_audit_history([h["kind"] for h in rep["holes"]], session=sid)
            except Exception:      # 状态层任何异常都不能让审计失败
                pass
        out.append((f, rep))

    if a.json:
        print(json.dumps([
            {
                "session": rid_of(f),
                "status": r["status"], "warnings": r["warnings"],
                "completed_steps": r["completed_steps"], "incomplete_steps": r["incomplete_steps"],
                "last_event_ms": r["last_event_ms"],
                "window_min": r.get("window_min"),
                "active_sec": r["active"], "step_sec": r["total"],
                "steps": len(r["rows"]), "calls": r["calls"],
                "tool_seconds": r["tool_t"],
                # --top 与 render/--review 保持一致：此前 JSON 忽略 --top，
                # 同一会话传 --top 1 在人类可读模式只出 1 条、JSON 仍出全部。
                "holes": [{"kind": h["kind"], "ratio": h["ratio"],
                           "priority": h["priority"], "related_sec": h["sev"],
                           "evidence": h["evidence"], "action": h["action"],
                           "fix": first_fix(h),
                           "lessons": [{"id": lesson_id(l), "tag": lesson_tag(l, w),
                                        "boundary": l.get("boundary")}
                                       for l, w, _h in match_lessons(h) if not l.get("demo")][:2]}
                          for h in r["holes"][:a.top]],
            } for f, r in out
        ], ensure_ascii=False, indent=2))
    elif a.review:
        for f, r in out:
            render_review(r, f, a.top)
    elif a.brief:
        for f, r in out:
            print(brief(r))
    else:
        for f, r in out:
            render(r, f, a.top)
    return 2 if any(r["status"] in ("insufficient_data", "partial") for _, r in out) else 0


def main():
    try:
        return _main()
    except (AuditInputError, OSError) as exc:
        if "--json" in sys.argv:
            print(json.dumps([{"status": "error", "error": str(exc)}], ensure_ascii=False))
        else:
            sys.stderr.write("[!] 审计未完成: %s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
