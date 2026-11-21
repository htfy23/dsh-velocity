/**
 * Session time-blackhole auditor for DSH.
 *
 * Host half only: three model-facing tools drive the audited `assets/blackhole.py`
 * engine (and its sibling batch retrospective entry `batch_review.py`) over the
 * caller's own session transcript, and one prompt section states when a
 * self-audit is worth the run. The engine is unchanged from the
 * `time-blackhole-audit` skill so all entry points share one lesson library.
 */

import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve as resolvePath } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SKILL_SCRIPT = join('skills', 'time-blackhole-audit', 'blackhole.py')
const SKILL_BATCH_SCRIPT = join('skills', 'time-blackhole-audit', 'batch_review.py')

/** Upper bound on one auditor run; whole-transcript audits are seconds at most. */
const DEFAULT_TIMEOUT_MS = 120_000
/**
 * Upper bound on one batch-retrospective action. Re-extracting ~20 transcripts
 * takes minutes, and `attribute` spawns one real-model call per group
 * (~10–15 s each), so minutes are the expected case here.
 */
const DEFAULT_BATCH_TIMEOUT_MS = 900_000
/** Guard against a pathological report reaching the model in full. */
const MAX_STREAM_CHARS = 4 * 1024 * 1024

const LESSON_KINDS = ['失败循环', '重复调用', '反复编辑同处', '无产出长段', '任务轮询', '超时转后台', '串行长调用', '盲改缺验证', '串行未并行', '起后台即阻塞等', '盲等', '命令可合并', 'subagent 串行', 'subagent 闲置']
const FEEDBACK_EVENTS = ['recommended', 'adopted', 'success', 'failure']
const AUDIT_MODES = ['summary', 'brief', 'review', 'full', 'json']
const BATCH_ACTIONS = ['extract', 'groups', 'context', 'attribute', 'write', 'quick']
const QUICK_SCRIPT = 'quick_review.py'
const SPEEDUP_SCRIPT = 'verify_speedup.py'

export const name = 'dsh-velocity'
export const inject = ['tools']

/** Defaults applied when the row carries no config or an invalid field. */
const DEFAULT_SETTINGS = {
  pythonPath: '',
  scriptPath: '',
  timeoutMs: DEFAULT_TIMEOUT_MS,
  batchTimeoutMs: DEFAULT_BATCH_TIMEOUT_MS,
  promptGuide: true,
}

/**
 * The row config is read directly rather than declared as a schema: this
 * package resolves without any DSH dependency, so it cannot import the schema
 * builder the loader validates with. Unknown or malformed fields fall back to
 * the defaults instead of failing activation.
 */
function normalizeSettings(raw) {
  const source = raw !== null && typeof raw === 'object' ? raw : {}
  const pythonPath = typeof source.pythonPath === 'string' ? source.pythonPath.trim() : ''
  const scriptPath = typeof source.scriptPath === 'string' ? source.scriptPath.trim() : ''
  const timeoutMs = Number.isFinite(source.timeoutMs) && source.timeoutMs > 0
    ? Math.trunc(source.timeoutMs)
    : DEFAULT_SETTINGS.timeoutMs
  const batchTimeoutMs = Number.isFinite(source.batchTimeoutMs) && source.batchTimeoutMs > 0
    ? Math.trunc(source.batchTimeoutMs)
    : DEFAULT_SETTINGS.batchTimeoutMs
  return { pythonPath, scriptPath, timeoutMs, batchTimeoutMs, promptGuide: source.promptGuide !== false }
}

/** Resolve the DSH home the same way the auditor engine does. */
function dshHome() {
  const overridden = process.env.DSH_HOME?.trim()
  return overridden ? overridden : join(homedir(), '.dsh')
}

/**
 * The script's own directory owns `lessons.jsonl`, so prefer the installed
 * skill's copy: lessons recorded through either entry point stay in one file.
 * The bundled copy keeps the plugin working where the skill is absent.
 */
function resolveScript(settings) {
  const candidates = []
  if (settings.scriptPath !== '') candidates.push(settings.scriptPath)
  const overridden = process.env.BLACKHOLE_SCRIPT?.trim()
  if (overridden) candidates.push(overridden)
  candidates.push(join(dshHome(), SKILL_SCRIPT))
  candidates.push(join(HERE, 'assets', 'blackhole.py'))
  for (const candidate of candidates) {
    if (existsSync(candidate)) return resolvePath(candidate)
  }
  return undefined
}

function resolvePython(settings) {
  if (settings.pythonPath !== '') return settings.pythonPath
  const overridden = process.env.BLACKHOLE_PYTHON?.trim()
  if (overridden) return overridden
  return process.platform === 'win32' ? 'python' : 'python3'
}

function missingScriptError() {
  return new Error(
    '找不到 blackhole.py：既没有 $DSH_HOME/skills/time-blackhole-audit/blackhole.py，'
      + '也没有插件自带的 assets/blackhole.py。设置 BLACKHOLE_SCRIPT 指向脚本可修复。',
  )
}

function missingBatchScriptError() {
  return new Error(
    '找不到 batch_review.py：既没有审计脚本同目录的副本，也没有 '
      + '$DSH_HOME/skills/time-blackhole-audit/batch_review.py 或插件自带的 assets/batch_review.py。'
      + '设置 BLACKHOLE_BATCH_SCRIPT 指向脚本可修复。',
  )
}

/**
 * The batch retrospective entry (`batch_review.py`) ships next to the audit
 * engine and writes its products under its own directory, so prefer the copy
 * sitting beside the resolved audit script; env, the installed skill and the
 * bundled asset follow. `resolveScript` already handles the scriptPath /
 * BLACKHOLE_SCRIPT overrides, so they carry over to the sibling lookup.
 */
function resolveBatchScript(settings) {
  const candidates = []
  const auditScript = resolveScript(settings)
  if (auditScript !== undefined) candidates.push(join(dirname(auditScript), 'batch_review.py'))
  const overridden = process.env.BLACKHOLE_BATCH_SCRIPT?.trim()
  if (overridden) candidates.push(overridden)
  candidates.push(join(dshHome(), SKILL_BATCH_SCRIPT))
  candidates.push(join(HERE, 'assets', 'batch_review.py'))
  for (const candidate of candidates) {
    if (existsSync(candidate)) return resolvePath(candidate)
  }
  return undefined
}

/**
 * The one-click quick-review entry (`quick_review.py`, B7) sits beside
 * `batch_review.py` and imports it, so the same directory-preference chain
 * applies: audit-script sibling first, env override, installed skill, plugin
 * asset last.
 */
function resolveQuickScript(settings) {
  const candidates = []
  const auditScript = resolveScript(settings)
  if (auditScript !== undefined) candidates.push(join(dirname(auditScript), QUICK_SCRIPT))
  const overridden = process.env.BLACKHOLE_QUICK_SCRIPT?.trim()
  if (overridden) candidates.push(overridden)
  candidates.push(join(dshHome(), 'skills', 'time-blackhole-audit', QUICK_SCRIPT))
  candidates.push(join(HERE, 'assets', QUICK_SCRIPT))
  for (const candidate of candidates) {
    if (existsSync(candidate)) return resolvePath(candidate)
  }
  return undefined
}

/**
 * The speed A/B verifier (`verify_speedup.py`) sits beside the audit engine and
 * imports it, so the same lookup chain applies.
 */
function resolveSpeedupScript(settings) {
  const candidates = []
  const auditScript = resolveScript(settings)
  if (auditScript !== undefined) candidates.push(join(dirname(auditScript), SPEEDUP_SCRIPT))
  const overridden = process.env.BLACKHOLE_SPEEDUP_SCRIPT?.trim()
  if (overridden) candidates.push(overridden)
  candidates.push(join(dshHome(), 'skills', 'time-blackhole-audit', SPEEDUP_SCRIPT))
  candidates.push(join(HERE, 'assets', SPEEDUP_SCRIPT))
  for (const candidate of candidates) {
    if (existsSync(candidate)) return resolvePath(candidate)
  }
  return undefined
}

/**
 * `batch_review.py`'s default path consumes the session selection produced by
 * its sibling `eval/batch_scan_select.py` (the "recent 20 ended sessions"
 * probe), so `extract` runs that first. Same directory-preference chain as
 * the batch entry itself.
 */
function resolveSelectScript(settings) {
  const candidates = []
  const batchScript = resolveBatchScript(settings)
  if (batchScript !== undefined) candidates.push(join(dirname(batchScript), 'eval', 'batch_scan_select.py'))
  const auditScript = resolveScript(settings)
  if (auditScript !== undefined) candidates.push(join(dirname(auditScript), 'eval', 'batch_scan_select.py'))
  candidates.push(join(HERE, 'assets', 'eval', 'batch_scan_select.py'))
  for (const candidate of candidates) {
    if (existsSync(candidate)) return resolvePath(candidate)
  }
  return undefined
}

/**
 * Run the auditor once. Arguments are passed as an argv array, never a shell
 * string, so transcript ids and fix text cannot inject command fragments.
 * @param {string} script absolute path to blackhole.py
 * @param {readonly string[]} argv auditor arguments
 * @param {{ env?: Record<string, string>, signal?: AbortSignal, timeoutMs?: number }} options
 * @returns {Promise<{ code: number | null, signal: string | null, stdout: string, stderr: string }>}
 */
function runAuditor(script, argv, options = {}) {
  const python = options.python ?? (process.platform === 'win32' ? 'python' : 'python3')
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const signal = options.signal
  const extraEnv = options.env ?? {}

  return new Promise((settle, fail) => {
    if (signal?.aborted) {
      fail(new Error('审计已取消'))
      return
    }

    const env = { ...process.env }
    for (const [key, value] of Object.entries(extraEnv)) {
      if (typeof value === 'string') env[key] = value
    }

    const child = spawn(python, [script, ...argv], {
      cwd: homedir(),
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })

    let stdout = ''
    let stderr = ''
    let settled = false
    let timer

    const cleanup = () => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
    }
    const finish = (fn, value) => {
      if (settled) return
      settled = true
      cleanup()
      fn(value)
    }
    const onAbort = () => {
      child.kill()
      finish(fail, new Error('审计已取消'))
    }

    timer = setTimeout(() => {
      child.kill()
      const budget = timeoutMs >= 1000 ? `${Math.round(timeoutMs / 1000)} 秒` : `${timeoutMs} 毫秒`
      finish(fail, new Error(`审计超过 ${budget}未结束，已中止`))
    }, timeoutMs)
    signal?.addEventListener('abort', onAbort, { once: true })

    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      if (settled) return
      if (stdout.length + chunk.length > MAX_STREAM_CHARS) {
        child.kill()
        finish(fail, new Error('审计输出超过 4 MiB，已中止'))
        return
      }
      stdout += chunk
    })
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', (chunk) => {
      if (stderr.length < MAX_STREAM_CHARS) stderr += chunk
    })
    child.on('error', (error) => {
      if (error?.code === 'ENOENT') {
        finish(fail, new Error(
          `找不到 Python 解释器 "${python}"。安装 Python 3，或设置环境变量 BLACKHOLE_PYTHON 指向解释器路径。`,
        ))
        return
      }
      finish(fail, new Error(`无法启动审计进程: ${error?.message ?? error}`))
    })
    child.on('close', (code, signalName) => {
      finish(settle, { code, signal: signalName, stdout, stderr })
    })
  })
}

/** The calling agent's own session, so an omitted `session` audits itself. */
function sessionIdOf(exec) {
  const id = exec?.agent?.id
  return typeof id === 'string' && id.length > 0 ? id : undefined
}

function duration(seconds) {
  const value = Number(seconds)
  if (!Number.isFinite(value) || value <= 0) return '0s'
  // Round first, then split: 1139.6s must read 19m00s, not 18m60s.
  const total = Math.round(value)
  if (total < 60) return `${total}s`
  if (total < 3600) return `${Math.floor(total / 60)}m${String(total % 60).padStart(2, '0')}s`
  return `${(value / 3600).toFixed(2)}h`
}

function nextStep(session) {
  const first = (session.holes ?? [])[0]
  if (first !== undefined) return `优先核查「${first.kind}」，核实根因后再决定继续、缩小范围或换方法。`
  if (session.status === 'ok') return '结合实际任务结果继续判断；只读探索同样可能产生有效结论。'
  return '数据不足或不完整：先核对日志、时间窗口和未结束的步骤，不能据此判断健康。'
}

function formatSession(session) {
  const window = session.window_min ? `近 ${Math.round(session.window_min * 10) / 10} 分钟窗口` : '整个会话日志'
  const lines = [
    `${session.session}  status=${session.status}  `
      + `${session.steps} 步 / ${session.calls} 次工具调用 / 步内合计 ${duration(session.step_sec)}  (${window})`,
  ]
  for (const warning of session.warnings ?? []) lines.push(`  提示: ${warning}`)

  const holes = session.holes ?? []
  if (holes.length === 0) {
    lines.push(session.status === 'ok'
      ? '  未触发检测规则；这不等于已证明高效。'
      : '  未触发检测规则，但数据不完整，不能判断整体健康。')
  } else {
    lines.push(`  待核查信号 ${holes.length} 个:`)
    holes.forEach((hole, index) => {
      const share = hole.ratio > 0 ? `（占步内合计 ${Math.round(hole.ratio * 100)}%）` : ''
      lines.push(`    ${index + 1}. ${hole.kind}${share} — ${hole.evidence}`)
      if (hole.related_sec > 0) {
        lines.push(`       相关步骤涉及 ${duration(hole.related_sec)}；代理指标，不等于浪费或可节省时间`)
      }
      lines.push(`       下一步: ${hole.fix}`)
      for (const lesson of hole.lessons ?? []) {
        lines.push(`       匹配经验 [${lesson.id}]${lesson.boundary ? ` 适用边界: ${lesson.boundary}` : ''}`)
      }
    })
  }
  lines.push(`  → ${nextStep(session)}`)
  return lines.join('\n')
}

/**
 * The engine reports an unreadable input as a JSON row with `status: "error"`
 * and exit code 2. That is an incomplete audit, not a finding, so it must fail
 * the tool call instead of reaching the model as a report.
 */
function failureFromJson(rawText) {
  if (!rawText.startsWith('[')) return undefined
  let parsed
  try {
    parsed = JSON.parse(rawText)
  } catch {
    return undefined
  }
  if (!Array.isArray(parsed)) return undefined
  const broken = parsed.find(item => item?.status === 'error')
  const detail = broken?.error
  return typeof detail === 'string' && detail !== '' ? detail : undefined
}

function formatSummary(rawText) {
  const failure = failureFromJson(rawText)
  if (failure !== undefined) throw new Error(`审计未完成: ${failure}`)
  let sessions
  try {
    sessions = JSON.parse(rawText)
  } catch {
    return rawText
  }
  if (!Array.isArray(sessions) || sessions.length === 0) return rawText
  return sessions.map(formatSession).join('\n\n')
}

function auditTool(settings) {
  return {
    name: 'blackhole_audit',
    description:
      'Audit DSH session transcripts for stall signals: failure loops, repeated calls, spots edited over and over, '
      + 'unproductive stretches, task polling and timeout-backgrounding. Returns timestamped evidence and one next '
      + 'action; every signal still needs task-level verification. Omit `session` to audit the calling session.',
    parameters: {
      type: 'object',
      properties: {
        session: {
          type: 'string',
          description: 'Session id or transcript path. Omit to audit the calling session.',
        },
        since: {
          type: 'number',
          description:
            "Look back this many minutes from the transcript's last event instead of the whole log. "
            + 'Suits retrospection over history; it is not "the last N minutes of wall clock".',
        },
        recent: {
          type: 'integer',
          description: 'Audit the N most recently written sessions instead of one session.',
        },
        trend: {
          type: 'integer',
          description:
            'Aggregate the same signal across the N most recent sessions instead of auditing one session. '
            + 'Returns text only. A signal recurring across sessions is a lead, not a shared root cause.',
        },
        mode: {
          type: 'string',
          enum: AUDIT_MODES,
          description:
            'summary (default) returns structured findings; brief one line; review a markdown retrospective; '
            + 'full the rendered report; json the raw machine-readable array.',
        },
        top: {
          type: 'integer',
          description: 'Maximum findings to list; default 5.',
        },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: typeof value === 'string' ? value : String(value) }],
    },
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const script = resolveScript(settings)
      if (script === undefined) throw missingScriptError()

      const session = typeof args.session === 'string' && args.session.trim() !== ''
        ? args.session.trim()
        : undefined
      const recent = Number.isInteger(args.recent) ? args.recent : undefined
      const trend = Number.isInteger(args.trend) ? args.trend : undefined
      const since = typeof args.since === 'number' && Number.isFinite(args.since) ? args.since : undefined
      const top = Number.isInteger(args.top) && args.top > 0 ? args.top : undefined
      const mode = typeof args.mode === 'string' && AUDIT_MODES.includes(args.mode) ? args.mode : 'summary'

      if (trend !== undefined && (session !== undefined || recent !== undefined)) {
        throw new Error('trend 不能与 session/recent 同时使用：trend 自己选择最近 N 个会话。')
      }
      if (recent !== undefined && session !== undefined) {
        throw new Error('recent 与 session 只能选一个。')
      }
      if (trend !== undefined && trend <= 0) throw new Error('trend 必须是正整数。')
      if (recent !== undefined && recent <= 0) throw new Error('recent 必须是正整数。')
      if (since !== undefined && since <= 0) throw new Error('since 必须是正的分钟数。')

      const argv = []
      if (trend !== undefined) argv.push('--trend', String(trend))
      else if (recent !== undefined) argv.push('--recent', String(recent))
      else if (session !== undefined) argv.push('--session', session)
      if (since !== undefined) argv.push('--since', String(since))
      if (top !== undefined) argv.push('--top', String(top))
      if (mode === 'brief') argv.push('--brief')
      else if (mode === 'review') argv.push('--review')
      else if (mode === 'summary' || mode === 'json') argv.push('--json')

      const sessionId = sessionIdOf(exec)
      const result = await runAuditor(script, argv, {
        python: resolvePython(settings),
        timeoutMs: settings.timeoutMs,
        env: sessionId === undefined ? {} : { DSH_SESSION_ID: sessionId },
        signal: exec.signal,
      })

      const stdout = result.stdout.trim()
      const stderr = result.stderr.trim()
      if (result.code === 0 || (result.code === 2 && stdout !== '')) {
        if (mode === 'json' || trend !== undefined) {
          const failure = failureFromJson(stdout)
          if (failure !== undefined) throw new Error(`审计未完成: ${failure}`)
          return stdout
        }
        if (mode === 'summary') return formatSummary(stdout)
        return stdout
      }
      const detail = stdout || stderr || `退出码 ${result.code ?? result.signal}`
      throw new Error(`审计未完成: ${detail}`)
    },
  }
}

function lessonsTool(settings) {
  return {
    name: 'blackhole_lessons',
    description:
      'Read and maintain the blackhole lesson library: query the one verified fix for a tool error, list '
      + 'candidate fixes, record a new one, or record what happened after a fix was recommended or adopted. '
      + 'Recording a lesson is not proof it worked; the success and failure events carry that evidence.',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['query', 'list', 'record', 'feedback'],
          description:
            'query: verified lesson for a tool error (deduped per session). list: read library. '
            + 'record: add a lesson. feedback: what happened after it was used.',
        },
        json: {
          type: 'boolean',
          description: 'list: return ids, stats and boundaries as JSON instead of text.',
        },
        tool: {
          type: 'string',
          description: 'query: name of the tool that produced the error.',
        },
        error: {
          type: 'string',
          description:
            'query: verbatim error line — do not paraphrase or drop "Error:". Paths/URLs are normalized before matching.',
        },
        session: {
          type: 'string',
          description: 'query: dedup key, defaults to current session. Omit to disable dedup (writes nothing).',
        },
        lessons_path: {
          type: 'string',
          description: 'query/feedback: alternate library path (tests/isolated runs). Unset = real library.',
        },
        kind: {
          type: 'string',
          enum: LESSON_KINDS,
          description: 'record: the signal kind this fix addresses. Must match the audit report wording.',
        },
        fix: {
          type: 'string',
          description: 'record: the concrete action to take next time.',
        },
        evidence: {
          type: 'string',
          description: 'record: source, e.g. "session-abc T10.S2". feedback: the observed result (required for success/failure).',
        },
        match: {
          type: 'string',
          description:
            'record: comma-separated keywords. Suggested only when ALL appear in the signal context; '
            + 'without match (or with scope=general) it is stored but never suggested.',
        },
        scope: {
          type: 'string',
          enum: ['contextual', 'general'],
          description: 'record: general declares the fix applies to the whole signal kind.',
        },
        boundary: {
          type: 'string',
          description: 'record: environment, preconditions, and where the fix does not apply.',
        },
        event: {
          type: 'string',
          enum: FEEDBACK_EVENTS,
          description:
            'feedback: recommended / adopted / success / failure (used+verified). success and failure imply adopted.',
        },
        lesson_id: {
          type: 'string',
          description: 'feedback: lesson id from list.',
        },
        case: {
          type: 'string',
          description: 'feedback: independent task or case id; repeats for one case do not add a case.',
        },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: typeof value === 'string' ? value : String(value) }],
    },
    isConcurrencySafe: () => false,
    async execute(args, exec) {
      const script = resolveScript(settings)
      if (script === undefined) throw missingScriptError()

      const action = args.action
      const argv = []
      if (action === 'list') {
        argv.push('--lessons')
        if (args.json === true) argv.push('--json')
      } else if (action === 'record') {
        const kind = typeof args.kind === 'string' ? args.kind : ''
        const fix = typeof args.fix === 'string' ? args.fix.trim() : ''
        if (!LESSON_KINDS.includes(kind)) {
          throw new Error(`record 需要 kind，取值之一：${LESSON_KINDS.join(' / ')}`)
        }
        if (fix === '') throw new Error('record 需要非空的 fix。')
        argv.push('--record', '--kind', kind, '--fix', fix)
        if (typeof args.evidence === 'string' && args.evidence.trim() !== '') {
          argv.push('--evidence', args.evidence.trim())
        }
        if (typeof args.match === 'string' && args.match.trim() !== '') {
          argv.push('--match', args.match.trim())
        }
        if (args.scope === 'contextual' || args.scope === 'general') argv.push('--scope', args.scope)
        if (typeof args.boundary === 'string' && args.boundary.trim() !== '') {
          argv.push('--boundary', args.boundary.trim())
        }
      } else if (action === 'feedback') {
        const event = typeof args.event === 'string' ? args.event : ''
        const lessonId = typeof args.lesson_id === 'string' ? args.lesson_id.trim() : ''
        const caseId = typeof args.case === 'string' ? args.case.trim() : ''
        if (!FEEDBACK_EVENTS.includes(event)) {
          throw new Error(`feedback 需要 event，取值之一：${FEEDBACK_EVENTS.join(' / ')}`)
        }
        if (lessonId === '') throw new Error('feedback 需要 lesson_id（用 action: list 查）。')
        if (caseId === '') throw new Error('feedback 需要独立的 case 标识。')
        argv.push('--feedback', event, '--lesson-id', lessonId, '--case', caseId)
        if (typeof args.evidence === 'string' && args.evidence.trim() !== '') {
          argv.push('--evidence', args.evidence.trim())
        }
      } else if (action === 'query') {
        const errorText = typeof args.error === 'string' ? args.error.trim() : ''
        if (errorText === '') throw new Error('query 需要非空的 error（报错摘要；tool 建议一并提供）。')
        argv.push('--query')
        if (typeof args.tool === 'string' && args.tool.trim() !== '') argv.push('--tool', args.tool.trim())
        argv.push('--error', errorText)
        // 会话去重身份：显式传入优先，否则用当前 DSH 会话 id；两者都缺省=不去重且零写入
        const session = typeof args.session === 'string' && args.session.trim() !== ''
          ? args.session.trim()
          : sessionIdOf(exec)
        if (session !== undefined) argv.push('--query-session', session)
      } else {
        throw new Error('action 必须是 query / list / record / feedback 之一。')
      }

      if (typeof args.lessons_path === 'string' && args.lessons_path.trim() !== '') {
        // list/query/feedback 允许指向隔离副本（只读或演练写）；record 只走真实库——
        // 沉淀是面向正式库的确认动作，测试种子用 CLI --lessons-path。
        if (action !== 'query' && action !== 'feedback' && action !== 'list') {
          throw new Error(`lessons_path 仅支持 list/query/feedback，当前 action 是 ${action}。`)
        }
        argv.push('--lessons-path', args.lessons_path.trim())
      }

      const result = await runAuditor(script, argv, {
        python: resolvePython(settings),
        timeoutMs: settings.timeoutMs,
        signal: exec.signal,
      })
      const stdout = result.stdout.trim()
      const stderr = result.stderr.trim()
      if (result.code === 0 && stdout !== '') return stdout
      const detail = stderr || stdout || `退出码 ${result.code ?? result.signal}`
      throw new Error(`经验库操作未完成: ${detail}`)
    },
  }
}

/**
 * Parse the `OUT <path>` line the batch CLI prints on success and return the
 * product path, so tool output can be augmented with a compact digest read
 * from the product instead of forcing the model to open the JSON itself.
 */
function productPathFromStdout(stdout) {
  const line = stdout.split('\n').reverse().find(l => l.replace(/\r$/, '').startsWith('OUT '))
  return line === undefined ? undefined : line.replace(/\r$/, '').slice(4).trim()
}

/** Compact gid digest of an aggregated-groups product: one line per group. */
function digestGroups(path) {
  let doc
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    return ''
  }
  const groups = Array.isArray(doc?.groups) ? doc.groups : []
  if (groups.length === 0) return ''
  const lines = groups.slice(0, 15).map(g => {
    const mergeKey = typeof g.merge_key === 'string' ? g.merge_key.slice(0, 70) : ''
    return `  ${g.gid}  ${g.kind}  sessions=${g.n_sessions ?? 1}  calls=${g.calls ?? '?'}`
      + `  ${Math.round(g.total_s ?? 0)}s  ${mergeKey}`
  })
  return `\n按优先级的组清单(前 ${Math.min(15, groups.length)}/${groups.length},`
    + `完整产物见上方 OUT):\n${lines.join('\n')}`
}

/**
 * Batch retrospective entry: select a batch of ended sessions, extract the
 * time-concentrated spans, aggregate cross-session patterns, attribute root
 * causes with a real model call per group, and write the avoidable ones into
 * the lesson library. Long-running by design — see DEFAULT_BATCH_TIMEOUT_MS.
 */
function batchReviewTool(settings) {
  return {
    name: 'blackhole_batch_review',
    description:
      'Batch retrospective over ended sessions: aggregate cross-session patterns into prioritized '
      + 'groups, attribute root causes (one model call per group, 10-15 s), write only verified '
      + 'avoidable patterns (auto-backup; necessary/insufficient groups never written). '
      + 'Chain: extract -> groups -> attribute -> write, 3-10 gids per batch; minutes per call are normal. '
      + 'action=quick does the whole chain in one call (capped at the 3 most promising groups) and '
      + 'writes nothing — returns up to 3 evidence-backed blockers. To persist a quick result, call '
      + 'write with attrib_path/groups_path from it.',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: BATCH_ACTIONS,
          description:
            'quick: ONE-CLICK preview (no gids needed) — select recent ended sessions, extract, group, '
            + 'attribute the top ≤3 candidates (real model), and return an action list of up to 3 '
            + 'evidence-backed blockers; writes nothing. extract: re-select and re-extract the recent '
            + 'ended sessions (also do this first if transcripts changed since the last run); groups: '
            + 'aggregate spans into prioritized evidence groups; context: attach each group\'s original '
            + 'goal/user messages; attribute: classify and attribute the given `gids` (requires gids, '
            + 'real-model cost per group); write: merge attributed avoidable `gids` into the lesson '
            + 'library (requires gids; see lessons_path/attrib_path/groups_path/confirm).',
        },
        gids: {
          type: 'string',
          description:
            'Comma-separated evidence-group ids (G001,G004,...) for attribute/write. attribute and write '
            + 'refuse to run without them: a full unbatched attribution is a 20-30 minute run.',
        },
        lessons_path: {
          type: 'string',
          description:
            'write: absolute path of a target library file instead of the engine\'s own lessons.jsonl. '
            + 'Use this for test/dry-pipeline runs; the real library keeps its zero-write guarantee.',
        },
        attrib_path: {
          type: 'string',
          description:
            'write: absolute path of the attribution JSON to consume (default: the five-step entry\'s '
            + 'own eval/batch_attribution.json). REQUIRED when writing quick-review results — pass the '
            + 'quick product (…/eval/quick/quick_attribution.json) so gids resolve against the right '
            + 'attribution, and pass groups_path with it.',
        },
        groups_path: {
          type: 'string',
          description:
            'write: absolute path of the evidence-groups JSON the gids refer to (default: the five-step '
            + 'entry\'s own eval/batch_evidence_groups.json). REQUIRED when writing quick-review results '
            + '(…/eval/quick/quick_groups.json) — quick gid numbering is its own.',
        },
        dry_run: {
          type: 'boolean',
          description: 'write: preview the merge/create plan without touching any library.',
        },
        confirm: {
          type: 'boolean',
          description:
            'write: confirm a REAL write into the engine\'s own lesson library (auto-backed-up first). '
            + 'Required unless dry_run is set or lessons_path redirects the target.',
        },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: typeof value === 'string' ? value : String(value) }],
    },
    isConcurrencySafe: () => false,
    async execute(args, exec) {
      const batchScript = resolveBatchScript(settings)
      if (batchScript === undefined) throw missingBatchScriptError()

      const action = typeof args.action === 'string' && BATCH_ACTIONS.includes(args.action)
        ? args.action
        : undefined
      if (action === undefined) {
        throw new Error(`action 必须是 ${BATCH_ACTIONS.join(' / ')} 之一。`)
      }
      const gidsRaw = typeof args.gids === 'string' ? args.gids.trim() : ''
      const gids = gidsRaw !== ''
        ? gidsRaw.split(',').map(s => s.trim()).filter(s => s !== '')
        : undefined

      /** Each run is [scriptPath, argv]; `extract` needs two runs. */
      const runs = []
      if (action === 'quick') {
        const quickScript = resolveQuickScript(settings)
        if (quickScript === undefined) {
          throw new Error('找不到 quick_review.py（一键复盘入口，与 batch_review.py 同目录）。'
            + '安装完整的 time-blackhole-audit skill 或设置 BLACKHOLE_QUICK_SCRIPT 后重试。')
        }
        runs.push([quickScript, ['--model', 'headless']])
      } else if (action === 'extract') {
        const selectScript = resolveSelectScript(settings)
        if (selectScript === undefined) {
          throw new Error('找不到 eval/batch_scan_select.py（extract 的第一步：选取最近已结束会话）。'
            + '安装完整的 time-blackhole-audit skill 或设置 BLACKHOLE_BATCH_SCRIPT 后重试。')
        }
        runs.push([selectScript, []], [batchScript, []])
      } else if (action === 'groups') {
        runs.push([batchScript, ['--groups']])
      } else if (action === 'context') {
        runs.push([batchScript, ['--context']])
      } else if (action === 'attribute') {
        if (gids === undefined || gids.length === 0) {
          throw new Error('attribute 需要 gids（如 G001,G004）；不带 gids 的全量归因是 20-30 分钟的运行，请先 groups 看清单再分批。')
        }
        runs.push([batchScript, ['--attribute', '--gids', gids.join(',')]])
      } else if (action === 'write') {
        if (gids === undefined || gids.length === 0) {
          throw new Error('write 需要 gids（与 attribute 的批次一致），否则会一次性写入全部候选。')
        }
        const dryRun = args.dry_run === true
        const lessonsPath = typeof args.lessons_path === 'string' && args.lessons_path.trim() !== ''
          ? args.lessons_path.trim()
          : undefined
        if (!dryRun && lessonsPath === undefined && args.confirm !== true) {
          throw new Error('write 默认写入引擎所在目录的正式经验库（先自动备份）。确认真写请传 confirm: true；'
            + '测试请传 lessons_path 指向临时库，或先用 dry_run: true 看预览。')
        }
        const argv = ['--write-lessons', '--gids', gids.join(',')]
        const attribPath = typeof args.attrib_path === 'string' && args.attrib_path.trim() !== ''
          ? args.attrib_path.trim()
          : undefined
        const groupsPath = typeof args.groups_path === 'string' && args.groups_path.trim() !== ''
          ? args.groups_path.trim()
          : undefined
        if (attribPath !== undefined) argv.push('--attrib', attribPath)
        if (groupsPath !== undefined) argv.push(groupsPath)   // positional GROUPS_JSON
        if (lessonsPath !== undefined) argv.push('--lessons-path', lessonsPath)
        if (dryRun) argv.push('--dry-run')
        runs.push([batchScript, argv])
      }

      const python = resolvePython(settings)
      let stdout = ''
      let stderr = ''
      for (const [script, argv] of runs) {
        const result = await runAuditor(script, argv, {
          python,
          timeoutMs: settings.batchTimeoutMs,
          signal: exec.signal,
        })
        stdout = result.stdout.trim()
        stderr = result.stderr.trim()
        if (result.code !== 0) {
          const detail = stdout || stderr || `退出码 ${result.code ?? result.signal}`
          throw new Error(`批量复盘未完成: ${detail}`)
        }
      }
      // The batch CLI prints its per-run tally (groups=… / candidates=…) on
      // stderr and only the `OUT <path>` line on stdout — surface both.
      let output = stderr !== '' ? `${stdout}\n${stderr}` : stdout
      if (action === 'groups') {
        const product = productPathFromStdout(stdout)
        if (product !== undefined) output += digestGroups(product)
      }
      return output
    },
  }
}

function speedupTool(settings) {
  return {
    name: 'velocity_speedup',
    description:
      'Measure how much faster a NEW conversation is versus an OLD one, in one call. Compares the reclaimable '
      + 'wait rate (blocking waits, blind sleeps, unmergeable commands, timeouts) over the same recent window. '
      + 'Prompt changes only reach conversations started after them, so an old session keeps its old habits — '
      + 'this tool is how you verify a fix actually landed. Use it after changing skills or prompts, and to '
      + 'report the per-round speedup percentage.',
    parameters: {
      type: 'object',
      properties: {
        baseline: {
          type: 'string',
          description:
            'Session id of the OLD conversation (started before the change). Omit to auto-pick the second most '
            + 'recently active session.',
        },
        candidate: {
          type: 'string',
          description:
            'Session id of the NEW conversation (started after the change). Omit to auto-pick the most '
            + 'recently active session.',
        },
        minutes: {
          type: 'number',
          description:
            'Only inspect the last N minutes of both sessions (default 60). Keep it equal on both sides — '
            + 'comparing different windows makes the numbers meaningless.',
        },
        list: {
          type: 'boolean',
          description: 'List the most recently active sessions with their idle minutes, then stop.',
        },
      },
      additionalProperties: false,
    },
    // DSH 0.2.2-rc.3 起要求每个工具声明 output；缺了它整包 fiberPhase=failed
    // （实测诊断：tool "velocity_speedup" must declare output）。渲染统一交给
    // render，execute 只返回字符串。
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: typeof value === 'string' ? value : String(value) }],
    },
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const script = resolveSpeedupScript(settings)
      if (script === undefined) {
        throw new Error(
          '找不到 verify_speedup.py：既没有审计脚本同目录的副本，也没有 '
            + '$DSH_HOME/skills/time-blackhole-audit/verify_speedup.py 或插件自带的 assets/verify_speedup.py。'
            + '设置 BLACKHOLE_SPEEDUP_SCRIPT 指向脚本可修复。',
        )
      }
      const argv = []
      if (args.list === true) {
        argv.push('--list')
      } else {
        const baseline = typeof args.baseline === 'string' ? args.baseline.trim() : ''
        const candidate = typeof args.candidate === 'string' ? args.candidate.trim() : ''
        if (baseline !== '') argv.push('--baseline', baseline)
        if (candidate !== '') argv.push('--candidate', candidate)
        if (Number.isFinite(args.minutes) && args.minutes > 0) {
          argv.push('--minutes', String(args.minutes))
        }
      }
      argv.push('--json')
      const result = await runAuditor(script, argv, {
        python: resolvePython(settings),
        timeoutMs: settings.timeoutMs,
        signal: exec?.signal,
      })
      const text = (result.stdout ?? '').trim()
      if (result.code !== 0 && text === '') {
        const detail = (result.stderr ?? '').trim() || `退出码 ${result.code ?? result.signal}`
        throw new Error(`速度对比失败: ${detail}`)
      }
      if (args.list === true) {
        let sessions
        try {
          sessions = JSON.parse(text).sessions
        } catch {
          return text || '(无活跃会话)'
        }
        if (!Array.isArray(sessions) || sessions.length === 0) {
          return '(无活跃会话)'
        }
        const body = sessions.map((r) => `  ${r.idle_min.toFixed(1).padStart(7)} 分钟前  ${r.session}`)
        return ['最近活跃会话（分钟前 / id）：', ...body].join('\n')
      }
      let doc
      try {
        doc = JSON.parse(text)
      } catch {
        return text
      }
      if (doc?.baseline === undefined || doc?.candidate === undefined) {
        return JSON.stringify(doc, null, 2)
      }
      const pct = doc.speedup_pct
      const lines = [
        `近 ${doc.minutes} 分钟对比：`,
        `  旧对话 ${doc.baseline.session}  浪费率 ${doc.baseline.waste_pct}%`
          + `（活动 ${(doc.baseline.active_sec / 3600).toFixed(2)}h，可回收 ${(doc.baseline.waste_sec / 60).toFixed(1)}min）`,
        `  新对话 ${doc.candidate.session}  浪费率 ${doc.candidate.waste_pct}%`
          + `（活动 ${(doc.candidate.active_sec / 3600).toFixed(2)}h，可回收 ${(doc.candidate.waste_sec / 60).toFixed(1)}min）`,
        '',
        `浪费率下降 ${pct} 个百分点` + (doc.ratio ? `，相对加速 ${doc.ratio} 倍` : ''),
        `本轮加速：${pct}%（目标 ≥1%，${doc.meets_1pct ? '达标' : '未达标'}）`,
      ]
      if (doc.candidate.waste_pct < 0.05) {
        lines.push('注意：新对话浪费率已接近 0，进一步下降空间有限（分母效应）。')
      }
      return lines.join('\n')
    },
  }
}

function promptSection() {
  return {
    name: 'blackhole-audit',
    order: 60,
    text: [
      '`blackhole_audit` 从会话转录里机械地找低效信号（目标是**把任务跑得更快**，不是找茬）。'
      + '信号种类与判据由工具自己给出，不用记——只看它报出来的证据。',
      '触发点：连续出现同类失败、准备重复试过的操作、多轮轮询没有新状态、或长时间探索后说不清最近拿到了什么可验证结论。默认审计当前会话，用 since 收窄窗口。不要每步都审计——只读分析、排除假设、等待必要计算都可能是合理工作。',
      '**长任务必须中途自查**（实测教训：一个跨度 319 小时的会话，7 次审计全部发生在最后 7% 的时间里，7 个信号在前 316 小时就已积累完毕——等于全程没被纠正）。判据：距上次审计已过 100+ 次工具调用、或刚完成一个可交付节点、或单会话已超 2 小时，就主动跑一次 `blackhole_audit`（用 since 只看最近一段，便宜）。不要等任务做完或用户质疑才查。',
      '**等待时间是最大的可回收成本**（实测 24 个会话 11.2 小时）：①预期 >60 秒的命令一开始就 run_in_background 起后台，起完立刻去做与之无关的工作，用 wait=false 探一次；绝对不要起了后台又 wait=true 干等（等于同步调用）。②不要用 sleep 盲等——等状态就轮询状态，等资源就起后台做别的，给进程留余量就缩到 1-3 秒并检查就绪。③无数据依赖的多条命令合并成一条（cmd1; cmd2 && cmd3）或同一消息里并发发；省的是 LLM 轮次不是命令时间，每步固定约 8 秒，与输出量无关——所以减少步数才是提速主途径。④**能拆就拆，送到 subagent 去**：subagent 调用是 fire-and-forget（约 0.1 秒返回 started subagent <id>），执行在子会话里异步跑；N 个在**同一条消息里起 N 个**，墙钟取 max 不是 sum（实测 29 次的子会话累计活跃 332 分钟，串行就是 5.5 小时）。别去权衡「算不算独立子任务」——按机械判据拆：同一轮里要检查 **≥2 个互不相关的对象**（文件 / 会话 / URL / 仓库 / 配置项）、要跑 **≥2 组不共享输入的独立命令**、或要拿 **≥2 份互不影响的产出**，就并发发出去。拿不准时倾向拆：拆错的代价是秒级启动开销，不拆的代价是整段串行墙钟。只有严格依赖链（A 的输出是 B 的输入，如改代码→编译→测试）才留在自己手里。',
            '**验证改进是否真的生效，用 `velocity_speedup`**：提示词/skill 的改动只对**改完之后新开的对话**生效，已开始的对话沿用旧提示词。所以对比必须「新对话 vs 旧对话、同一时间窗」——它直接给出浪费率下降几个百分点、相对加速几倍，以及是否达到 1% 目标。改完提示词、或每轮优化收尾时跑一次，用它的数字回答「快了百分之几」，不要凭感觉估。',
'信号是待核实的线索，不是结论：读证据再决定继续、缩小范围或改变方法，不要仅因耗时就打断有进展的任务。',
      '核实后的解法用 `blackhole_lessons` 的 record 沉淀（带 match 关键词或 scope: general 才会被建议），用 feedback 记录被推荐、被采用以及采用后的验证结果；记录次数不等于验证成功。',
      '工具报错第一次出现时，先用 `blackhole_lessons` 的 query 查经验：action=query、tool=工具名、error=报错原文整行（逐字复制，不要改写摘要或省略 Error: 前缀；默认按当前会话去重，同一错误只提示一次）。命中就按返回的「下一步」行动、完成后把实际结果 feedback 回填到同一条经验（success/failure 必须附证据，证据不足保持待验证）；未命中就按常规排查，不要原样重试同一操作。query/feedback 可传 lessons_path 指向隔离副本做演练，不传即真实库。',
      '阶段性回顾多会话用 `blackhole_batch_review`：要快速拿结论用 action=quick（一次调用跑完整条链，'
      + '不写库，返回 ≤3 条有证据的卡点）；要逐步控制就 extract→groups→attribute→write。',
    ].join('\n'),
  }
}

export function apply(ctx, config) {
  const settings = normalizeSettings(config)
  ctx.effect(() => {
    const disposers = [
      ctx.tools.register(auditTool(settings)),
      ctx.tools.register(lessonsTool(settings)),
      ctx.tools.register(batchReviewTool(settings)),
      ctx.tools.register(speedupTool(settings)),
    ]
    const systemPrompt = ctx.get('systemPrompt')
    if (settings.promptGuide && systemPrompt !== undefined) {
      disposers.push(systemPrompt.section(promptSection()))
    }
    return () => {
      for (const dispose of disposers) dispose()
    }
  })
}
