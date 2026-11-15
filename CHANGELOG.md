# Changelog

Notable changes to `dsh-velocity`. This is the first public release; earlier
internal iterations are not versioned here.

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
