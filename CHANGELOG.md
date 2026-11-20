# Changelog

Notable changes to `dsh-velocity`. This is the first public release; earlier
internal iterations are not versioned here.

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
