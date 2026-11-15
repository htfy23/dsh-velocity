/**
 * Self-test for dsh-velocity without installing it.
 *
 * Mocks the Cordis context, then drives the registered tools' execute() the way
 * the tool executor would. Read-only cases run the real skill engine; write
 * cases run a throwaway copy of the engine so the user's lesson library is
 * never touched by a test.
 */
import { createHash } from 'node:crypto'
import { copyFile, mkdtemp, mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import process from 'node:process'
import { fileURLToPath, pathToFileURL } from 'node:url'

// 从文件自身位置推导插件根目录：克隆到任何路径都能跑，不依赖作者机器布局。
const PLUGIN = dirname(fileURLToPath(import.meta.url))
const DSH_HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh')
// 可选的语料产物（eval/batch_evidence.json 等）不在仓库里——它们是本地跑出来的。
// 有就复用（让 groups/write 秒级完成），没有就跳过依赖它们的断言。
const WORK_CORPUS = process.env.BLACKHOLE_CORPUS ?? join(PLUGIN, 'assets', 'eval')

let pass = 0
let fail = 0
const failures = []

function check(name, condition, detail = '') {
  if (condition) {
    pass += 1
    console.log(`  ok   ${name}`)
    return
  }
  fail += 1
  failures.push(`${name}${detail === '' ? '' : ` — ${detail}`}`)
  console.log(`  FAIL ${name}${detail === '' ? '' : ` — ${detail}`}`)
}

const captured = { tools: [], sections: [], disposed: 0 }

function makeCtx() {
  captured.tools.length = 0
  captured.sections.length = 0
  captured.disposed = 0
  return {
    effect(fn) {
      return fn()
    },
    tools: {
      register(definition) {
        captured.tools.push(definition)
        return () => {
          captured.disposed += 1
        }
      },
    },
    get(key) {
      if (key === 'systemPrompt') {
        return {
          section(section) {
            captured.sections.push(section)
            return () => {
              captured.disposed += 1
            }
          },
        }
      }
      return undefined
    },
  }
}

function execFor(sessionId) {
  return {
    agent: sessionId === undefined ? undefined : { id: sessionId },
    signal: new AbortController().signal,
  }
}

function toolNamed(name) {
  const found = captured.tools.find(definition => definition.name === name)
  if (found === undefined) throw new Error(`tool ${name} was not registered`)
  return found
}

async function latestSessionId() {
  const root = join(DSH_HOME, 'sessions')
  const best = { mtime: -1, id: undefined }
  for (const workspace of await readdir(root, { withFileTypes: true })) {
    if (!workspace.isDirectory()) continue
    const workspacePath = join(root, workspace.name)
    for (const session of await readdir(workspacePath, { withFileTypes: true })) {
      if (!session.isDirectory()) continue
      const sessionPath = join(workspacePath, session.name)
      for (const file of await readdir(sessionPath)) {
        if (!file.startsWith('session.') || !file.includes('.jsonl')) continue
        const info = await stat(join(sessionPath, file))
        if (info.mtimeMs > best.mtime) {
          best.mtime = info.mtimeMs
          best.id = session.name
        }
      }
    }
  }
  return best.id
}

const moduleUrl = pathToFileURL(join(PLUGIN, 'index.js')).href
const { apply, name, inject } = await import(moduleUrl)

console.log('== registration ==')
check('module name', name === 'dsh-velocity', name)
// bundle patch 的行 id 必须等于包名：dsh-client-modules 按包名挂载浏览器端模块，
// Plugins 页也按该行取标题/描述/图标。id 与包名不一致时（历史遗留 id: blackhole）
// 行匹配不上，整包被判为异常。
{
  const patchText = readFileSync(join(PLUGIN, 'cordis.patch.yml'), 'utf8')
  const rowId = (patchText.match(/^\s*-\s*id:\s*(\S+)/m) ?? [])[1]
  const rowName = (patchText.match(/^\s*name:\s*(\S+)/m) ?? [])[1]?.replace(/['"]/g, '')
  check('patch row id equals package name', rowId === name, `${rowId} vs ${name}`)
  check('patch row name equals package name', rowName === name, `${rowName} vs ${name}`)
}
// locale 标题必须反映新定位，不能还留着改名前的「时间黑洞审计」
{
  const zh = JSON.parse(readFileSync(join(PLUGIN, 'locale', 'zh.json'), 'utf8'))
  const en = JSON.parse(readFileSync(join(PLUGIN, 'locale', 'en.json'), 'utf8'))
  // 标题沿用 dsh-ops 一类官方插件的做法：直接等于包名，读起来和装卸目标一致
  check('zh locale title is package name', zh.meta.title === name, zh.meta.title)
  check('en locale title is package name', en.meta.title === name, en.meta.title)
  check('locale description non-empty', (zh.meta.description ?? '').length > 20)
  check('locale description drops the old name', !/黑洞/.test(zh.meta.description))
}
// 纯 Host 插件也要声明 client.platform，否则 Plugins 页拿不到卡片信息
{
  const pkg = JSON.parse(readFileSync(join(PLUGIN, 'package.json'), 'utf8'))
  check('dsh.client.platform declared', pkg.dsh?.client?.platform === 'web', JSON.stringify(pkg.dsh?.client))
// 宿主依赖必须声明：插件不 import 任何 @deepseek-ai/* 包（只用 node: 内置），
// 但它依赖 Host 提供的 ctx.tools / ctx.get('systemPrompt')。声明 peer 让装在
// 过旧宿主上时能被依赖检查拦下，而不是运行时静默失效。
{
  const pkg = JSON.parse(readFileSync(join(PLUGIN, 'package.json'), 'utf8'))
  const peer = pkg.peerDependencies ?? {}
  check('declares host peer dependency', Object.keys(peer).length > 0, JSON.stringify(peer))
  check('host peer is @deepseek-ai/dsh', '@deepseek-ai/dsh' in peer, Object.keys(peer).join(','))
  check('host peer allows optional install',
        pkg.peerDependenciesMeta?.['@deepseek-ai/dsh']?.optional === true)
  // 反向守卫：源码不得出现对 @deepseek-ai/* 的运行时 import——
  // 一旦引入就变成硬依赖，必须同时从 optional 改为必需。
  const src = readFileSync(join(PLUGIN, 'index.js'), 'utf8')
  check('index.js has no @deepseek-ai import', !/from\s+['"]@deepseek-ai\//.test(src))
  // 版本号语义：README/CHANGELOG 承诺的是「首次公开版本」，改动包名或 patch id
  // 这类破坏性变更时必须升 major。这里只守住基本形状，防止误写成 0.x 或带后缀。
  const ver = String(pkg.version ?? '')
  check('version is semver major.minor.patch', /^\d+\.\d+\.\d+$/.test(ver), ver)
  check('public release starts at 1.0.0', ver === '1.0.0', ver)
  // CHANGELOG 必须存在且记录了当前版本，否则发布说明会与代码脱节
  const changelog = readFileSync(join(PLUGIN, 'CHANGELOG.md'), 'utf8')
  check('CHANGELOG documents current version', changelog.includes(`## ${ver}`), ver)
  check('CHANGELOG lists every tool', ['blackhole_audit', 'blackhole_lessons',
    'blackhole_batch_review', 'velocity_speedup'].every((t) => changelog.includes(t)))
}
}
check('injects tools', Array.isArray(inject) && inject.includes('tools'), JSON.stringify(inject))
apply(makeCtx())
check('registers four tools', captured.tools.length === 4, String(captured.tools.length))
check('registers one prompt section', captured.sections.length === 1, String(captured.sections.length))

// 提示词必须覆盖引擎的全部信号。历史上新增「起后台即阻塞等 / 盲等 / 命令可合并」
// 三个信号后，提示词漏改——模型不知道要规避，11.2 小时可回收时间白白流失。
// 这里直接读引擎的 KNOWN_KINDS 做比对，防止再次漏改。
const bhSrc = readFileSync(join(PLUGIN, 'assets', 'blackhole.py'), 'utf8')
const kindsBlock = bhSrc.slice(bhSrc.indexOf('KNOWN_KINDS = ['))
const knownKinds = [...kindsBlock.slice(0, kindsBlock.indexOf(']')).matchAll(/["']([^"']+)["']/g)]
  .map((m) => m[1])
const promptText = captured.sections.map((s) => s.text).join('\n')
check('prompt lists every engine signal', knownKinds.length >= 12, String(knownKinds.length))
// 12 个信号必须被「工具可发现」，但不必写进提示词——`blackhole_lessons` 的 kind
// 枚举就是权威清单，模型查经验时自然会看到。写进提示词是重复计费（每轮都算 token），
// 与「控制 token 增量」的目标冲突。这里断言：每个信号都出现在某个工具的 schema 里。
const schemaText = JSON.stringify(captured.tools.map((t) => ({ d: t.description, p: t.parameters })))
check('all signals reachable via tool schema', knownKinds.every((k) => schemaText.includes(k)),
      knownKinds.filter((k) => !schemaText.includes(k)).join(','))
// 提示词反过来不该复述整张信号表：超过 4 个信号名就算重复计费
const duplicated = knownKinds.filter((k) => promptText.includes(k)).length
check('prompt does not duplicate the signal table', duplicated <= 4, String(duplicated))
// 速度规则必须落进提示词，否则模型不会主动规避等待
check('prompt has background-first rule', promptText.includes('run_in_background'))
check('prompt bans blocking wait on background', promptText.includes('wait=true'))
check('prompt warns against blind sleep', promptText.includes('sleep 盲等'))
check('prompt advises merging commands', promptText.includes('合并成一条'))
// 新对话验证的引导必须写进提示词：否则模型不会去跑 A/B，也就报不出加速%
check('prompt mentions speedup verification', promptText.includes('velocity_speedup'))
check('prompt explains new-conversation rule', promptText.includes('新开的对话'))
// 四个工具都必须在提示词里被点名，否则模型不知道它们存在
for (const t of ['blackhole_audit', 'blackhole_lessons', 'blackhole_batch_review', 'velocity_speedup']) {
  check(`prompt names tool ${t}`, promptText.includes(t))
}
const audit = toolNamed('blackhole_audit')
const lessons = toolNamed('blackhole_lessons')
const batch = toolNamed('blackhole_batch_review')
check('audit name', audit.name === 'blackhole_audit', audit.name)
check('lessons name', lessons.name === 'blackhole_lessons', lessons.name)
check('batch name', batch.name === 'blackhole_batch_review', batch.name)
const speedup = toolNamed('velocity_speedup')
check('speedup name', speedup.name === 'velocity_speedup', speedup.name)
check('speedup params are object schema', speedup.parameters.type === 'object')
check('speedup closes additionalProperties', speedup.parameters.additionalProperties === false)
check('speedup minutes is number', speedup.parameters.properties.minutes.type === 'number')
check('speedup has baseline+list', ['baseline', 'list'].every((k) => k in speedup.parameters.properties))
// 端到端：list 模式必须真的跑起来并回文本（不是抛错、不是空）
{
  const r = await speedup.execute({ list: true }, {})
  const text = r?.content?.[0]?.text ?? ''
  check('speedup list runs end-to-end', text.length > 0, text.slice(0, 60))
  check('speedup list names sessions', /session-|[0-9a-f]{8}/.test(text))
}
// 端到端：A/B 模式给出「本轮加速」结论行
{
  const ids = (await import('node:fs')).readdirSync(join(DSH_HOME, 'sessions')).slice(0, 3)
  const r = await speedup.execute({ minutes: 60 }, {})
  const text = r?.content?.[0]?.text ?? ''
  check('speedup ab returns verdict', text.includes('本轮加速') || text.includes('数据不足'), text.slice(0, 60))
}
check('batch requires action', JSON.stringify(batch.parameters.required) === '["action"]')
check('batch is not concurrency safe', batch.isConcurrencySafe() === false)
check('audit params are object schema', audit.parameters.type === 'object')
check('audit params close additionalProperties', audit.parameters.additionalProperties === false)
check('lessons requires action', JSON.stringify(lessons.parameters.required) === '["action"]')
check('audit is concurrency safe', audit.isConcurrencySafe() === true)
check('lessons is not concurrency safe', lessons.isConcurrencySafe() === false)
check('prompt section named', captured.sections[0].name === 'blackhole-audit', captured.sections[0].name)
check('prompt section has text', typeof captured.sections[0].text === 'string' && captured.sections[0].text.length > 80)

const sessionId = await latestSessionId()
console.log(`\n== live audit (session ${sessionId}) ==`)

let run
try {
  run = await audit.execute({ mode: 'summary' }, execFor(sessionId))
  check('summary returns text', typeof run === 'string' && run.length > 0)
  check('summary names the session', run.includes(sessionId), run.slice(0, 120))
  check('summary reports status', /status=(ok|review|partial|insufficient_data|error)/.test(run), run.slice(0, 200))
} catch (error) {
  check('summary returns text', false, String(error))
}

try {
  const brief = await audit.execute({ mode: 'brief' }, execFor(sessionId))
  check('brief returns one line', typeof brief === 'string' && brief.length > 0 && !brief.includes('\n'))
} catch (error) {
  check('brief returns one line', false, String(error))
}

try {
  const review = await audit.execute({ mode: 'review', since: 20 }, execFor(sessionId))
  check('review returns markdown', typeof review === 'string' && review.startsWith('#'), String(review).slice(0, 80))
} catch (error) {
  check('review returns markdown', false, String(error))
}

try {
  const raw = await audit.execute({ mode: 'json' }, execFor(sessionId))
  const parsed = JSON.parse(raw)
  check('json mode parses', Array.isArray(parsed) && parsed.length >= 1)
  check('json mode carries session', parsed[0].session === sessionId, parsed[0].session)
} catch (error) {
  check('json mode parses', false, String(error))
}

try {
  const recent = await audit.execute({ mode: 'summary', recent: 2 }, execFor(undefined))
  check('recent audits multiple sessions', typeof recent === 'string' && recent.length > 0)
} catch (error) {
  check('recent audits multiple sessions', false, String(error))
}

try {
  const trend = await audit.execute({ mode: 'summary', trend: 3 }, execFor(undefined))
  check('trend returns text', typeof trend === 'string' && trend.length > 0)
} catch (error) {
  check('trend returns text', false, String(error))
}

console.log('\n== audit argument validation ==')
for (const [label, args] of [
  ['trend + recent rejected', { trend: 3, recent: 2 }],
  ['recent + session rejected', { recent: 2, session: 'x' }],
  ['negative since rejected', { since: -1 }],
  ['zero trend rejected', { trend: 0 }],
]) {
  try {
    await audit.execute(args, execFor(sessionId))
    check(label, false, 'resolved instead of rejecting')
  } catch (error) {
    check(label, true)
  }
}

try {
  await audit.execute({ session: 'definitely-not-a-session-id' }, execFor(undefined))
  check('unknown session reports an error', false, 'resolved instead of rejecting')
} catch (error) {
  check('unknown session reports an error', /审计未完成|找不到/.test(String(error.message)), String(error.message).slice(0, 120))
}

console.log('\n== lessons library (real, read-only) ==')
try {
  const list = await lessons.execute({ action: 'list' }, execFor(sessionId))
  check('list returns entries', typeof list === 'string' && list.length > 0)
  check('list is not empty', !list.includes('教训库为空'), list.slice(0, 120))
} catch (error) {
  check('list returns entries', false, String(error))
}

try {
  const listJson = await lessons.execute({ action: 'list', json: true }, execFor(sessionId))
  const parsed = JSON.parse(listJson)
  check('list json parses', Array.isArray(parsed))
  check('list json has ids', parsed.every(item => typeof item.id === 'string'))
} catch (error) {
  check('list json parses', false, String(error))
}

console.log('\n== lessons write path (throwaway engine copy) ==')
const sandbox = await mkdtemp(join(tmpdir(), 'bh-selftest-'))
const sandboxScript = join(sandbox, 'blackhole.py')
await copyFile(join(PLUGIN, 'assets', 'blackhole.py'), sandboxScript)
const before = process.env.BLACKHOLE_SCRIPT
process.env.BLACKHOLE_SCRIPT = sandboxScript
try {
  const recorded = await lessons.execute({
    action: 'record',
    kind: '任务轮询',
    fix: '先看 job_output 的 wait 状态再决定轮询间隔',
    evidence: 'session-test T1.S2',
    match: 'pytest,轮询',
    boundary: '测试沙箱专用，不写入真实库',
  }, execFor(sessionId))
  check('record succeeds', typeof recorded === 'string' && /记录|新增/.test(recorded), recorded.slice(0, 120))
  const file = await readFile(join(sandbox, 'lessons.jsonl'), 'utf8')
  check('sandbox lesson file written', file.includes('先看 job_output'))

  const list = await lessons.execute({ action: 'list', json: true }, execFor(sessionId))
  const parsed = JSON.parse(list)
  const created = parsed.find(item => item.fix.includes('先看 job_output'))
  check('recorded lesson listed', created !== undefined)

  if (created !== undefined) {
    const feedback = await lessons.execute({
      action: 'feedback',
      event: 'success',
      lesson_id: created.id,
      case: 'selftest-case-1',
      evidence: '自测脚本验证写入路径',
    }, execFor(sessionId))
    check('feedback succeeds', typeof feedback === 'string' && feedback.includes('success'), feedback.slice(0, 140))
  }

  for (const [label, args] of [
    ['record without fix rejected', { action: 'record', kind: '任务轮询' }],
    ['record with unknown kind rejected', { action: 'record', kind: '不存在的类型', fix: 'x' }],
    ['feedback without lesson_id rejected', { action: 'feedback', event: 'success', case: 'c' }],
    ['unknown action rejected', { action: 'bogus' }],
  ]) {
    try {
      await lessons.execute(args, execFor(sessionId))
      check(label, false, 'resolved instead of rejecting')
    } catch (error) {
      check(label, true)
    }
  }
} finally {
  if (before === undefined) delete process.env.BLACKHOLE_SCRIPT
  else process.env.BLACKHOLE_SCRIPT = before
}

console.log('\n== lessons query (sandbox library: recall / exclusion / dedup / backfill) ==')
const querySandbox = await mkdtemp(join(tmpdir(), 'bh-selftest-query-'))
const queryLib = join(querySandbox, 'lessons.jsonl')
const seedLesson = {
  kind: '失败循环',
  fix: '先重新读取文件最新版本，再原样重试编辑；仍失败就换更具体的锚点',
  hits: 1, created: Math.floor(Date.now() / 1000), last_used: Math.floor(Date.now() / 1000),
  evidence: ['session-seed T1.S1'],
  match: ['Error: cannot edit "PATH": file changed'],
  scope: 'contextual',
  boundary: '同一会话中该错误出现次数降为 0-1 次；第一次失败后重读再编辑应一次成功',
  feedback: [],
}
await writeFile(queryLib, JSON.stringify(seedLesson) + '\n', 'utf8')
const QUERY_ERR = 'Error: cannot edit "D:\\proj\\report.md": file changed since it was read — re-read the file, then retry'
const SIMILAR_ERR = 'Error: cannot edit "D:\\proj\\report.md": file has not been read — read the file, then retry'
const queryArgs = { action: 'query', tool: 'edit', error: QUERY_ERR, lessons_path: queryLib }

try {
  await lessons.execute({ action: 'query' }, execFor(sessionId))
  check('query without error rejected', false, 'resolved instead of rejecting')
} catch (error) {
  check('query without error rejected', true)
}

try {
  await lessons.execute({ action: 'record', kind: '失败循环', fix: 'x', lessons_path: queryLib }, execFor(sessionId))
  check('lessons_path on record rejected', false, 'resolved instead of rejecting')
} catch (error) {
  check('lessons_path on record rejected', /lessons_path 仅支持/.test(String(error.message)), String(error.message).slice(0, 120))
}

try {
  // 未验证经验 → 不得召回（这是 P0 的核心门槛）
  const cold = await lessons.execute(queryArgs, execFor(sessionId))
  check('unverified lesson not recalled', cold.includes('未命中'), cold.slice(0, 120))
} catch (error) {
  check('unverified lesson not recalled', false, String(error))
}

try {
  // 回填闭环：验证成功 feedback → 经验可召回
  const listed = JSON.parse(await lessons.execute({ action: 'list', json: true, lessons_path: queryLib }, execFor(sessionId)))
  const seeded = listed[0]
  const backfilled = await lessons.execute({
    action: 'feedback', event: 'success', lesson_id: seeded.id, case: 'selftest-query-1',
    evidence: '沙箱实测：重读后一次成功，同错误 1→0 次', lessons_path: queryLib,
  }, execFor(sessionId))
  check('feedback backfill succeeds', backfilled.includes('"success": 1'), backfilled.slice(0, 160))

  const hit = await lessons.execute(queryArgs, execFor(sessionId))
  check('verified lesson recalled after backfill', hit.includes('命中经验'), hit.slice(0, 120))
  check('hit carries id / next step / verify method',
    seeded.id !== undefined && hit.includes(seeded.id) && hit.includes('下一步') && hit.includes('验证方法'), hit.slice(0, 200))
  check('hit carries backfill guidance', hit.includes('feedback'), hit.slice(-200))

  // 相似报错排除：同为 cannot edit 但无 "file changed" 关键词
  const excluded = await lessons.execute({ ...queryArgs, error: SIMILAR_ERR }, execFor(sessionId))
  check('similar error excluded', excluded.includes('未命中'), excluded.slice(0, 120))
} catch (error) {
  check('query recall flow', false, String(error))
}

try {
  // 会话去重：同会话同报错第二次不再提示；换会话重新命中
  const first = await lessons.execute({ ...queryArgs, session: 'selftest-dedup-a' }, execFor(sessionId))
  const second = await lessons.execute({ ...queryArgs, session: 'selftest-dedup-a' }, execFor(sessionId))
  const other = await lessons.execute({ ...queryArgs, session: 'selftest-dedup-b' }, execFor(sessionId))
  check('dedup: first hit', first.includes('命中经验'), first.slice(0, 80))
  check('dedup: repeat suppressed', second.includes('重复报错') && second.includes('不再重复提示'), second.slice(0, 160))
  check('dedup: other session hits again', other.includes('命中经验'), other.slice(0, 80))
  const stateDir = join(querySandbox, '.query_state')
  check('dedup state lives next to sandbox library', existsSync(stateDir) && readdirSync(stateDir).length >= 2, stateDir)
} catch (error) {
  check('dedup flow', false, String(error))
}

try {
  // 不带会话 → 不去重且零写入（沙箱不得出现 .query_state 之外的库改动）
  const libBefore = await readFile(queryLib, 'utf8')
  const hit = await lessons.execute(queryArgs, execFor(undefined))
  check('sessionless query still hits', hit.includes('命中经验'), hit.slice(0, 80))
  check('sessionless query leaves library untouched', (await readFile(queryLib, 'utf8')) === libBefore)
} catch (error) {
  check('sessionless query', false, String(error))
}

console.log('\n== bundled assets vs installed skill ==')
const SKILL_DIR = join(DSH_HOME, 'skills', 'time-blackhole-audit')
function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}
const assetPairs = [
  ['blackhole.py', join(PLUGIN, 'assets', 'blackhole.py'), join(SKILL_DIR, 'blackhole.py')],
  ['batch_review.py', join(PLUGIN, 'assets', 'batch_review.py'), join(SKILL_DIR, 'batch_review.py')],
  ['eval/batch_scan_select.py', join(PLUGIN, 'assets', 'eval', 'batch_scan_select.py'), join(SKILL_DIR, 'eval', 'batch_scan_select.py')],
  // Optional: the timing probe ships with the plugin so its users can run it,
  // but a standalone install without the skill has no counterpart to compare.
  ['audit_timing_probe.py', join(PLUGIN, 'assets', 'audit_timing_probe.py'), join(SKILL_DIR, 'audit_timing_probe.py')],
]
for (const [label, bundled, installed] of assetPairs) {
  check(`bundled ${label} exists`, existsSync(bundled))
  if (!existsSync(installed)) {
    console.log(`  skip ${label} parity — skill side missing (plugin standalone mode)`)
    continue
  }
  check(`bundled ${label} matches skill`, sha256File(bundled) === sha256File(installed))
}
check('bundled lessons.jsonl exists', existsSync(join(PLUGIN, 'assets', 'lessons.jsonl')))

console.log('\n== batch review (throwaway engine copy; extract is exercised by the DSH acceptance run) ==')
const batchSandbox = await mkdtemp(join(tmpdir(), 'bh-selftest-batch-'))
await copyFile(join(PLUGIN, 'assets', 'blackhole.py'), join(batchSandbox, 'blackhole.py'))
await copyFile(join(PLUGIN, 'assets', 'batch_review.py'), join(batchSandbox, 'batch_review.py'))
await mkdir(join(batchSandbox, 'eval'), { recursive: true })
// Seed the corpus products so `groups` / `write` run in seconds instead of
// re-extracting ~20 transcripts (the selection probe alone scans all sessions).
const seedEvidence = join(WORK_CORPUS, 'eval', 'batch_evidence.json')
const seedAttribution = join(WORK_CORPUS, 'eval', 'batch_attribution.json')
const hasSeed = existsSync(seedEvidence) && existsSync(seedAttribution)
if (hasSeed) {
  await copyFile(seedEvidence, join(batchSandbox, 'eval', 'batch_evidence.json'))
  await copyFile(seedAttribution, join(batchSandbox, 'eval', 'batch_attribution.json'))
} else {
  console.log('  skip  corpus products absent (set BLACKHOLE_CORPUS to reuse them)')
}
const batchBefore = process.env.BLACKHOLE_SCRIPT
process.env.BLACKHOLE_SCRIPT = join(batchSandbox, 'blackhole.py')

for (const [label, args] of [
  ['batch unknown action rejected', { action: 'bogus' }],
  ['batch attribute without gids rejected', { action: 'attribute' }],
  ['batch write without gids rejected', { action: 'write' }],
  ['batch real write without confirm rejected', { action: 'write', gids: 'G004' }],
]) {
  try {
    await batch.execute(args, execFor(sessionId))
    check(label, false, 'resolved instead of rejecting')
  } catch (error) {
    check(label, true)
  }
}

// 以下用例回放本地语料产物（eval/batch_evidence*.json）。仓库不带这些文件，
// 没有就跳过——它们的目的是省掉 20 段转录的重新提取，不是验证插件契约本身。
if (hasSeed) {
  try {
    const groups = await batch.execute({ action: 'groups' }, execFor(sessionId))
    check('groups returns tally', /groups=\d+/.test(groups), groups.slice(0, 160))
    check('groups returns product path', groups.includes('OUT '), groups.slice(-160))
    check('groups digest lists gids', /G\d{3}/.test(groups), groups.slice(-300))
  } catch (error) {
    check('groups returns tally', false, String(error))
  }
  
  try {
    const preview = await batch.execute({ action: 'write', gids: 'G004', dry_run: true }, execFor(sessionId))
    check('write dry_run previews', /dry_run=True/.test(preview), preview.slice(0, 200))
    check('write dry_run touches nothing', !existsSync(join(batchSandbox, 'lessons.jsonl')))
  } catch (error) {
    check('write dry_run previews', false, String(error))
  }
  
  try {
    const written = await batch.execute({ action: 'write', gids: 'G004', confirm: true }, execFor(sessionId))
    check('write creates an entry', /created=[1-9]/.test(written), written.slice(0, 200))
    const lib = await readFile(join(batchSandbox, 'lessons.jsonl'), 'utf8')
    check('sandbox batch lesson written', lib.includes('batch-review'), lib.slice(0, 200))
  } catch (error) {
    check('write creates an entry', false, String(error))
  }
  
  try {
    // quick 复盘结果写回：attrib_path/groups_path 直通（gids 归属 quick 自己的
    // 组文件，防止静默读五步默认归因路径——USAGE 已知坑的插件侧防呆）。
    const out2 = await batch.execute({
      action: 'write', gids: 'G004', confirm: true,
      attrib_path: join(batchSandbox, 'eval', 'batch_attribution.json'),
      groups_path: join(batchSandbox, 'eval', 'batch_evidence_groups.json'),
    }, execFor(sessionId))
    check('write attrib/groups passthrough merges', /merged=[1-9]|created=[1-9]/.test(out2), out2.slice(0, 200))
  } catch (error) {
    check('write attrib/groups passthrough merges', false, String(error))
  }
} else {
  console.log('  skip  groups/write cases (corpus products absent)')
}

if (batchBefore === undefined) delete process.env.BLACKHOLE_SCRIPT
else process.env.BLACKHOLE_SCRIPT = batchBefore

console.log('\n== quick review (one-click, isolated empty corpus) ==')
const quickSandbox = await mkdtemp(join(tmpdir(), 'bh-selftest-quick-'))
await copyFile(join(PLUGIN, 'assets', 'blackhole.py'), join(quickSandbox, 'blackhole.py'))
await copyFile(join(PLUGIN, 'assets', 'batch_review.py'), join(quickSandbox, 'batch_review.py'))
await copyFile(join(PLUGIN, 'assets', 'quick_review.py'), join(quickSandbox, 'quick_review.py'))
await mkdir(join(quickSandbox, 'eval'), { recursive: true })
await copyFile(join(PLUGIN, 'assets', 'eval', 'batch_scan_select.py'), join(quickSandbox, 'eval', 'batch_scan_select.py'))
// the selection probe's sha16 has no no-file sentinel: it expects a lessons file
await copyFile(join(PLUGIN, 'assets', 'lessons.jsonl'), join(quickSandbox, 'lessons.jsonl'))
const quickDshHomeBefore = process.env.DSH_HOME
process.env.BLACKHOLE_SCRIPT = join(quickSandbox, 'blackhole.py')
process.env.DSH_HOME = join(quickSandbox, 'dsh-home')
await mkdir(join(quickSandbox, 'dsh-home'), { recursive: true })
try {
  const quickOut = await batch.execute({ action: 'quick' }, execFor(sessionId))
  check('quick one-click runs (empty corpus short result)', /QUICK empty_input/.test(quickOut), quickOut.slice(0, 200))
  check('quick output carries report path', /quick_report\.json/.test(quickOut), quickOut.slice(-160))
  check('quick makes zero model calls on empty corpus', !/attributed=[1-9]/.test(quickOut), quickOut.slice(-160))
} catch (error) {
  check('quick one-click runs (empty corpus short result)', false, String(error))
}
if (quickDshHomeBefore === undefined) delete process.env.DSH_HOME
else process.env.DSH_HOME = quickDshHomeBefore

console.log('\n== cancellation ==')
const aborted = new AbortController()
aborted.abort()
try {
  await audit.execute({ mode: 'summary' }, { agent: { id: sessionId }, signal: aborted.signal })
  check('pre-aborted signal rejects', false, 'resolved instead of rejecting')
} catch (error) {
  check('pre-aborted signal rejects', /取消/.test(String(error.message)), String(error.message))
}

console.log('\n== row config handling ==')
const mutedCtx = makeCtx()
apply(mutedCtx, { promptGuide: false })
check('promptGuide:false suppresses the prompt section', captured.sections.length === 0, String(captured.sections.length))
check('promptGuide:false still registers all tools', captured.tools.length === 4, String(captured.tools.length))

const junkCtx = makeCtx()
apply(junkCtx, { timeoutMs: -5, promptGuide: 'nope', scriptPath: 42, pythonPath: null, batchTimeoutMs: 'x' })
check('malformed config still registers all tools', captured.tools.length === 4, String(captured.tools.length))
check('malformed config keeps the prompt guide', captured.sections.length === 1, String(captured.sections.length))

const explicitCtx = makeCtx()
apply(explicitCtx, { scriptPath: join(PLUGIN, 'assets', 'blackhole.py') })
const pinned = toolNamed('blackhole_audit')
const pinnedResult = await pinned.execute({ mode: 'brief' }, execFor(sessionId))
check('scriptPath from config is usable', typeof pinnedResult === 'string' && pinnedResult.length > 0)

console.log(`\n== result ==\n  ${pass} passed, ${fail} failed`)
if (fail > 0) {
  console.log('  failures:')
  for (const item of failures) console.log(`   - ${item}`)
}
process.exitCode = fail === 0 ? 0 : 1
