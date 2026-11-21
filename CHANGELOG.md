# Changelog

Notable changes to `dsh-velocity`. This is the first public release; earlier
internal iterations are not versioned here.

## 1.0.4

### Prompt: mechanical fan-out triggers instead of "independent subtasks"

Measured over 393 sessions, `subagent` accounted for 0.26% of tool calls, and only
7% of sessions used one at all. Part of that is the outage described in 1.0.3 — a
prompt only reaches conversations started after a change, and 1.0.2 was broken for
about a day, so the rule had almost no exposure. But the rule was also too
abstract: "use subagents for independent subtasks" asks you to reason about
dependencies before you are allowed to split, which is easy to skip under time
pressure.

Rule ④ now names mechanical triggers instead: ≥2 unrelated objects to inspect, ≥2
groups of independent commands, ≥2 independent deliverables — fan them out. When
unsure, prefer splitting: a wrong split costs seconds of startup, a skipped split
costs minutes of serial wall clock.

### New signal: `subagent 闲置`

A session that ran ≥60 minutes with ≥100 tool calls and never delegated. `sev` is
fixed at 0 and it stays out of `SPEED_KINDS` — it is not wall clock already
wasted, so counting it as reclaimable would inflate the total. Suppressed when
`串行未并行` already reported the same session.

It is the lowest-priority signal, so the default `--top 5` can cut it off; pass
`--top 10` on a long session. On the 500-minute session that produced this release
it fires with:

```
会话活跃 502 分钟、1616 次工具调用、1601 步，全程 0 次 subagent；
主要工具 ops_bash 84min, pwsh 26min, blackhole_batch_review 2min, plugin_manager 1min
```

### Tests

603 engine tests (15 new), 128 plugin assertions.
## 1.0.3

### Fixed: the plugin failed to load on DSH 0.2.2-rc.3 ("异常" in the plugin list)

DSH 0.2.2-rc.3 requires every tool to declare `output: { schema, render }`.
`velocity_speedup`, added in 1.0.2, did not — and one tool violating that contract
fails the whole plugin's fiber:

```
fiberPhase: failed
diagnostic: tool "velocity_speedup" must declare output { schema, render, presentationMeta? }
```

Because the bundle fails as a unit, none of the four tools registered — including
`blackhole_audit`. So 1.0.2 was unusable on this host version even though its
other three tools were correct. The plugin list showed the card with "异常".

Fix: `velocity_speedup` declares `output` (string schema plus `render`) and returns
a plain string instead of the legacy `{ content: [{ type: 'text' }] }` shape, which
is what the other three tools already did.

Verified live: after toggling the entry off and on, `fiberPhase` moved to
`active`, all four tool schemas registered, and both `list` and the A/B mode
returned real results through the DSH tool executor.

### Tests

The self-test now checks, for every registered tool, that `output.schema` exists,
`output.render` is callable, and `isConcurrencySafe` is declared. One bad tool
failing a whole bundle is cheap to guard against; 128 assertions.
## 1.0.2

### New signal: `subagent 串行`

A subagent call is fire-and-forget — it returns `started subagent <id>` in about
0.1 s and the work runs in a child session. That means the parent transcript
cannot see the wall-clock cost: `tool_interval` on the call is 0.1 s, not the
minutes the child actually took. So starting N independent subagents one per
turn (wall clock `sum`) instead of in one message (wall clock `max`) was
previously invisible.

The detector now reads the child id out of the result text (it is the child's
session id), looks that session up, and computes the loss as `sum − max`. It is
deliberately conservative:

- only **adjacent steps in the same turn** count — a gap or a turn change is more
  likely a real dependency (you read the previous result before deciding)
- two or more subagents in the *same* step means they were already fanned out,
  so no loss is recorded
- unreadable child sessions are skipped rather than guessed
- at most 8 child sessions are read per analysis, and the lookup never recurses
  into a child's own analysis

Its `sev` is that `sum − max`, so the signal is counted in `SPEED_KINDS` and
appears in the reclaimable-time total alongside the four existing speed signals.

On the current corpus it fires on 0 of 39 sessions: subagents are already being
fanned out when used. The guidance and the measurement are there for when they
are not.

### Fixed: two scripts emitted GBK instead of UTF-8

`verify_speedup.py` and `batch_review.py` never reconfigured stdout, unlike
`blackhole.py`. On a Chinese Windows console (code page 936) their output was
GBK while the plugin decodes UTF-8 — Chinese came out as mojibake and
`UnicodeDecodeError` broke the CLI tests. Both now call the same `_out()` helper
`blackhole.py` uses.

### Tests

588 engine tests (21 new for the signal), 116 plugin self-test assertions.
## 1.0.1

Prompt guidance only — no detector or API change.

The resident speed rules covered three of the four ways to buy wall-clock time:
backgrounding a slow command, not sleeping blindly, and merging independent
commands. **Fanned-out subagents were missing entirely** — the word "subagent"
never appeared in the injected prompt, so the model had no reason to reach for it.

That gap is worth closing because a `subagent` call is fire-and-forget: it returns
`started subagent <id>` in about 0.1 s and the work runs asynchronously in a child
session. Starting N independent subagents in one message makes wall clock `max`
instead of `sum`. Measured on 29 real calls, child sessions accumulated 332
minutes of activity — run serially, that would have been 5.5 hours of wall clock.

Note this is why subagents are *not* in SPEED_KINDS: those signals measure wasted
time already spent in the parent transcript, whereas subagent fan-out is an
accelerant whose payoff lives in other sessions. What the parent can be blamed
for is starting them one per turn; that is what 串行未并行 flags.

Self-test now guards both facts: the prompt must mention `subagent` and must
explain that the call is non-blocking.
## 1.0.0

First public release.

### What it does

Measures how much of a DSH session is **pure wait** and reports the speedup in
percent, so "is this task actually getting faster?" has a number instead of a
feeling.

Four *speed* signals, whose durations add up to net savings:

| Signal | Meaning |
|---|---|
| `起后台即阻塞等` | started a background job, then blocked on it — the background gave nothing |
| `盲等` | `sleep`-style wait with nothing else running |
| `命令可合并` | independent commands split across separate LLM turns |
| `超时转后台` | slow commands run in the foreground until they hit the timeout |

Eight *correctness* signals: `失败循环` `重复调用` `反复编辑同处` `无产出长段`
`任务轮询` `串行长调用` `盲改缺验证` `串行未并行`.

Twelve total. Speed-signal durations sum to one figure (`--trend` prints it);
the other eight report affected-step time and must not be added to it.

### Tools

| Tool | Purpose |
|---|---|
| `blackhole_audit` | audit a session: `since` / `recent` / `trend`, five output modes |
| `blackhole_lessons` | verified-lesson library: `query` / `list` / `record` / `feedback` |
| `blackhole_batch_review` | cross-session retrospective: `quick` preview, or `extract → groups → attribute → write` |
| `velocity_speedup` | **new** — A/B a new conversation against an old one over the same window |

### Verification that the change landed

Prompt and skill edits only reach conversations **started after** the change; a
session already running keeps its old behaviour. So the comparison has to be
new-vs-old over the same window, which is what `velocity_speedup` measures.

Measured on 24 sessions (1 h window each):

| Conversation | Loaded new prompt | Waste rate |
|---|---|---|
| new | yes | **0.85%** |
| old | no | **15.61%** |

### Token cost

Trading fewer turns for time, not spending more context. Resident cost, paid
every turn whether or not the tools are called:

| Item | tokens |
|---|---|
| prompt section | ≈570 |
| four tool schemas | ≈3180 |
| **total** | **≈3750** |

The 12-signal list is deliberately *not* repeated in the prompt: the `kind`
enum on `blackhole_lessons` is the authoritative copy, and duplicating it billed
twice. Two self-test guards keep that true.

### Requirements

- Node ≥ 20
- DSH `>=0.2.2-rc.1 <0.2.3-0` (declared as an optional peer)
- Python 3 on `PATH` (the audit engine is Python)

### Install

```bash
plugin_manager action=install_bundle target="<path-to-this-repo>"
```

Restart DSH afterwards so the bundle patch and prompt section take effect.
