---
name: time-blackhole-audit
description: Audit DSH session logs for repeated failures, repeated operations, long polling, and potentially unproductive stretches. Use when troubleshooting stalled work or reviewing task efficiency. Reports timestamped evidence and scoped lessons; signals require task-level verification.
license: MIT
allowed-tools: Bash Read
metadata:
  user-invocable: "true"
  argument-hint: "[--session ID_OR_PATH | --recent N | --trend N | --since MIN | --brief | --json | --review | --lessons | --record | --feedback EVENT | --query --tool NAME --error TEXT]"
---

# 时间黑洞审计

运行环境为 DSH 会话日志及 Python 3；压缩日志需要 `zstandard`。

从日志中的时间戳、调用参数和结果寻找低效线索，再结合任务证据决定下一步。写入、输出长度和耗时都是代理指标，不能直接证明任务成功、失败或浪费时间。

## 何时使用

- 连续出现同类失败，或准备重复已经试过的操作。
- 多次轮询同一个任务，却没有新的状态或输出。
- 长时间探索后，需要检查获得了哪些可验证结论。
- 任务结束后复盘，提炼下一次可复用的做法。
- **长任务的中途**：距上次审计已过 100+ 次工具调用、或刚完成一个可交付节点、或单会话已超 2 小时。

不要每步都审计。只读分析、排除假设、等待必须完成的计算，都可能是合理工作。

### 为什么「中途」这一条重要（实测）

用 `audit_timing_probe.py` 把已结束会话按 25%/50%/75% 切开重放，量「如果当时就审计，能提前多久发现问题」：

| 会话 | 跨度 | 25% 处已能检出 | 提前量 |
|---|---|---|---|
| `e63ad746` | 319h | 7/7（100%） | 约 239h |
| `7968f378` | 125h | 3/6（50%）→ 75% 处 6/6 | 约 31h |
| `1f5f1160` | — | 4/4（100%） | — |
| `78943bed` | — | 4/4（100%） | — |

批量跑 5 个大会话，**5/5 都能在 25% 处检出信号**。而实际使用中：一个 319h 的会话，7 次审计全部发生在最后的 7%；另一个 18.2h 的会话**一次都没审计**。

结论：规则再多，跑得太晚也等于零。检测能力不是瓶颈，**时机才是**。

验证方法（只读，不改日志）：

```bash
python "$DSH_HOME/skills/time-blackhole-audit/audit_timing_probe.py" --recent 10
python "$DSH_HOME/skills/time-blackhole-audit/audit_timing_probe.py" --session <id> --cuts 0.1,0.25,0.5
```

## 运行与范围

```bash
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" --since 20 --brief
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" --session <会话ID或日志路径> --json
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" --recent 3
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" --trend 5
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" --session <会话ID或日志路径> --review
```

- 未指定 `--session` 时，优先使用 `DSH_SESSION_ID`；已设置但找不到时报告错误，不切到别的任务。未设置时使用最新会话；跨任务复盘宜明确指定会话。
- 支持 `.jsonl` 和 `.jsonl.zstd`；同一会话目录的多个格式版本不重复计入趋势。
- 日志按流式逐行读取，10 万事件规模的完整解析与检测在秒级完成；压缩日志不再整份驻留内存。
- `--since 20` 以日志**最后一条事件的时间**为终点回看20分钟，适用于历史复盘；不表示"现在之前20分钟"。所有检测共用窗口，跨边界区间只计窗口内时长。
- 超过20分钟的事件间隔切分活动段。跨活动段或单次超过30分钟的工具区间不参与工具计时，真实长任务的耗时可能被低估。
- 未结束的步骤不估算耗时。空日志、没有完整步骤或解析不完整时，不能宣称健康。
- 普通审计、`--review` 和 `--lessons` 只读。只有 `--record`、`--feedback` 写经验库；写入有锁及原子替换。持有进程崩溃遗留的 `.lock`（超过60秒未清理）会被下次写入自动恢复，无需手动处理；60秒内的锁视为真实并发写入，等待后报错。

### 数据不完整与截断

- 末行被截断、字段缺失、时间戳无效的行会跳过并计入警告；状态为 `partial`。
- 事件缺 `turn`/`step` 字段时按未知步骤单独聚合，并警告——这种聚合可能失真，不得当作完整数据。
- **步骤缺 `step/start` 事件但带调用的**（日志起点截断、撕裂写）不再静默丢弃：按零时长纳入失败/重复检测并警告"N 个步骤缺少 step/start 事件"；不给任何耗时口径贡献。仅有此类内容、没有完整计时段时状态为 `partial`（内容级证据照常展示），只有日志里没有任何可判读调用/结果时才是 `insufficient_data`。
- **压缩日志不完整**（截断或仍在写入）时，恢复可读前缀分析并警告"仅分析已读部分"；此时即使没有完整步骤，状态也是 `partial`（数据确实存在），而不是 `insufficient_data`。
- **多帧压缩日志中部帧损坏**（逐帧拼接的日志中某一帧损坏）时，自动跳过损坏帧继续读取其后帧，警告注明"跳过 N 个损坏帧"；数据仍按不完整对待（`partial` 语义）。
- **帧头声明大小的多帧日志末帧截断**（如逐块压缩拼接的日志被切短）时，从最后帧起点重新解压验证帧边界，发现不完整即警告"仅分析已读部分"，不会静默当成"没有数据"；完整多帧文件不受影响（不产生多余警告）。
- 文件为空或纯粹不可解压时分别为 `insufficient_data` / `error`。

## 解读结果

JSON `status`：

| 值 | 含义 |
|---|---|
| `ok` | 可分析记录没有触发规则，不代表已经证明高效 |
| `review` | 存在待核查信号，优先看失败循环，再看其他信号 |
| `partial` | 数据不完整（含截断、缺字段），现有记录没有触发规则，不能判断整体健康 |
| `insufficient_data` | 没有可计时的完整步骤，也没有可判读的调用/结果内容 |
| `error` | 输入或经验库不可读取，审计未完成 |

退出码：`0` 为可用结果（包括发现问题）；`2` 为数据不足、无信号但数据不完整、输入或参数错误。部分记录中发现信号时为 `review`，仍须检查 `warnings`。

| 信号 | 当前规则 | 应核对什么 |
|---|---|---|
| 失败循环 | 连续3步有工具失败，或失败步至少20且占比至少12%，或**同一报错模板出现至少3次**（URL/盘符路径/含斜杠 token 归一后逐字相同即视为同模板；数字不归一——行号/时间戳/计数器差异是内容差异；同类失败散布） | 完整错误、是否同一原因、预期与实际结果 |
| 重复调用 | 相同完整参数跨至少3步，**或单一步骤内出现至少3次**，完成调用中存在相同文本结果（仅首尾空白差异视为相同） | 是否取得新信息，是否为必要的状态复查 |
| 反复编辑同处 | 同文件至少5次成功编辑，`old_string` 不同值占比不超过60% | 是局部反复修补还是合理迭代 |
| 无产出长段 | 至少6步连续未记录成功写入，累计至少5分钟；探索段守卫：≥4个不同读取目标、最重复调用占比≤0.3、输出≥1000字符时不触发 | 是否产生新结论；规则名沿用旧版，不能等同"没产出" |
| 任务轮询 | 至少3次轮询，窗口内累计等待超过120秒 | 状态是否变化、能否降低频率、有无独立工作 |
| 超时转后台 | 结果包含 `still running after`，累计 ≥2 次才报（单次是偶发，全量标定过）。**若 ≥40% 的超时在之后 2 次调用内出现 `job_output`/`job_kill`，action 会改写成针对性建议**（说明命令实际没结束，本该一开始就起后台） | 正常转后台还是范围不当；转后台不等同失败 |
| 起后台即阻塞等 | `wait=true` 的 `job_output`/`job_list`，且其**前 3 次调用内**有 `run_in_background: true`，累计 ≥30 秒 | 后台的唯一价值是等待窗口内做别的事；起了就等等于同步调用。换成 `wait=false` 探一次，然后去推进会独立的步 |
| 盲等 | shell 类命令的 `command` 含 `Start-Sleep`/`sleep N`，**声明 N≥10 秒**，累计 ≥20 秒。更短的常是给刚启动进程留余量，不报 | 这条 sleep 在等什么？等状态就轮询状态（`wait=false`）、等资源就起后台去干别的、给进程留余量就缩到 1-3 秒并检查就绪、什么都不等就删掉 |
| 命令可合并 | **≥3 段连续的单调用命令步**（每步只有一条 `ops_bash`/`pwsh`/`bash`），且段内命令不全相同（重跑同一命令是必要验证，不算），合并可省 ≥5 步 | 这些命令之间有数据依赖吗？没有就合并成一条（`cmd1; cmd2 && cmd3`）或同一消息里并发发出。**省的是 LLM 轮次不是命令时间**——实测每步固定约 8 秒，与输出量关系很小 |
| 串行长调用 | **两种形态**：①长调用型——连续 ≥4 个完整步各只有一次同工具调用、每次 ≥10 秒、累计 ≥60 秒；②短调用型——连续 ≥15 次、每次 1~10 秒、累计 ≥180 秒。都要求区间互不重叠（真串行） | 这些调用之间有没有数据依赖；串行是任务必需还是写法习惯（严格依赖链也会命中，只作线索）。短调用型单次很快，正是它躲过旧阈值的原因 |
| 盲改缺验证 | 同一文件 ≥3 次成功 edit/write，覆盖窗口（末次编辑 +5 分钟）内没有重读该文件、也没有跑测试 | 改动之间为什么没验证；若本次没生效，能否从输出判断卡在哪一步 |
| 串行未并行 | 看整个窗口的并行度：`subagent`/后台作业占比 <2% **且** 单步多调用占比 <6%（条件一，需 ≥40 次调用）；或最长连续单工具步 ≥20 次、≥180 秒、并发步占比 <5% 且该段占全部步骤 ≥40%（条件二）。两个条件都要求并行入口绝对次数 ≤20——超大会话里 2% 可能是几十次，不该判它不会并行 | 这串调用里是否有互不依赖的项？有就并发（`asyncio.gather` / 后台作业 / 同一消息多工具 / 多个 subagent）；确属依赖链（改代码→编译→测试→重启）保持串行，不必处理 |
| subagent 串行 | 同一轮内**紧邻**的连续单 `subagent` 步（同一步 ≥2 个视为已并起，不计；跨轮或跳跃不计，那更可能是真依赖）。反查子会话的 active 算 `sum − max`，≥60 秒才报。`subagent` 调用约 0.1 秒就返回子会话 id，墙钟成本在子会话本身，父会话的调用时长量不到 | 这些子任务是不是要看上一步的产出才决定起下一个？不需要就该在**同一条消息里并起** N 个，墙钟取 max；确有依赖（A 的结论是 B 的输入）就保持串行 |
| subagent 闲置 | 会话活跃 ≥60 分钟、工具调用 ≥100 次、且全程 **0 次** `subagent`；`串行未并行` 已报时不重复报。`sev` 固定 0，**不计入**可回收总时长——它不是已浪费的墙钟，而是「规模没换成速度」的结构性提示 | 这段长会话里有没有彼此无数据依赖的独立块（多文件/多会话/多 URL、多组独立命令、多份产出）？有就下次在同一条消息里并起 subagent；单点排查或严格依赖链不拆是对的 |

同参数但每次返回不同文本，不作为重复空转（单步内同样豁免）；轮询由专门规则处理。失败写入不算成功写入，缺少 `old_string` 的编辑不推断为同一位置。错误文本聚合按报错模板：URL/路径 token 归一后相同即为同一条（只差路径的同模板报错合并，§21）；数字不归一，错误里行号/时间戳/计数器等数字差异属内容差异、各自计数不虚增。

步内工具时长按区间并集计算；各类工具的累计时长可能因并行重叠。涉及某个信号的整段耗时不能当作可节省时间，各信号之间也不能直接相加。

报告给出核查建议。先读证据，再决定继续、缩小范围或改变方法；不要仅因耗时就打断有进展的任务。

## 导出复盘材料

```bash
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" --session <会话ID或日志路径> --review > review.md
```

`--review` 输出结构化 Markdown 复盘材料（只读）：数据范围与状态、工具耗时分布（区间并集口径）、每个信号的证据与细节、匹配到的经验及其适用边界、需要人工/模型判断的核查问题、一个下一步动作。信号是粗筛线索——材料中的"需要人工/模型判断"一节把因果判断显式留给人，脚本不做因果结论。可与 `--since`、`--json` 组合。损坏日志的异常时间戳不会使导出失败（降级显示原始毫秒值）。

## 记录候选经验

包含具体动作、匹配条件、来源和适用边界：

```bash
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" \
  --record --kind "失败循环" \
  --fix "先读取完整错误，再按错误代码确定排查的服务" \
  --match "agent-preset/not-found" \
  --boundary "DSH 新建会话失败；其他错误需重新定位" \
  --evidence "session-xxx T10.S2"
```

`--kind` 为上表九个名称之一。`--match` 以逗号分隔，用于**召回排序**，不是硬门槛：

- **同类型信号**：`kind` 对上即可参与召回。`--match` 关键词命中越多，排序越靠前（按命中率，1/1 优于 1/3）；一个关键词都没命中则不召回，避免无关旧经验干扰。
- **跨类型**：仅当 `--match` 关键词**全部**命中时才带出（精确匹配优先）。
- **`--scope general`**：明确声明适用于整个类型，不要求关键词命中，作为同类型的通用兜底。

（历史背景：旧实现要求同类型也「全部命中」，实测 40 会话 33 个信号只有 12% 能召回；改为分层召回后达 94%。）

明确适用于整个类型的通用办法用 `--scope general`，并写清边界。

未给关键词也未声明通用范围时仍保存候选，但不自动匹配。旧经验原样保留；旧 `hits` 仅表示记录次数，不证明复用成功。旧经验没有匹配词时不默认扩展为通用规则。

查看经验及稳定 ID：

```bash
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" --lessons
```

只看「还没被真实结果验证过」的规则（按影响面排序）：

```bash
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" --lessons --pending
```

规则越多越该用它：库里 30+ 条时，先验证被召回/采用次数最多的那些——
它们错了会误导更多次。`--pending` 是只读视图，不会改动经验库，
也不会伪造验证数据（`--feedback` 的 success/failure 必须附 `--evidence`）。

再配 `--session`，只列「这次会话触发了对应信号」的规则——刚跑完审计的会话
正好提供了验证素材，把「可验证的机会」和「待验证的规则」直接接上：

```bash
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" \
  --lessons --pending --session "$DSH_SESSION_ID"
```

实测：32 条规则里全量待验证 28 条，按本会话信号过滤后只剩 15 条。

候选经验可以作为线索显示，但不覆盖通用核查动作。至少有一个独立成功反馈、没有已记录失败反馈的经验，才可在匹配范围内成为优先建议。适用边界是给模型核查的文字条件，脚本不理解其全部语义。

## 报错查经验（query）

工具报错第一次出现时主动查一次经验；输入工具名+报错摘要，输出至多一条已验证经验（经验 ID、下一步动作、验证方法），附带把实际结果回填的指引：

```bash
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" \
  --query --tool edit \
  --error 'Error: cannot edit "D:\proj\report.md": file changed since it was read — re-read the file, then retry' \
  --query-session session-xxx
```

- 只召回**已验证**经验：至少一个独立成功反馈、无已记录失败反馈、非示例。当前库若全部是候选，回答"未命中"是正确行为——先用「记录采用后的结果」把验证证据补进库，报错召回才会生效。
- 匹配口径：报错文本先做路径/URL 归一化（与失败循环聚合同一 `norm_err_text`，`D:\proj\report.md` → `PATH`），再要求经验的 `--match` 关键词全部命中"工具名+归一化报错"。相似但缺关键词的报错不会命中；没有关键词的经验不参与报错召回（无法判定适用范围）。
- 会话去重：给了 `--query-session` 时，同一会话中同一报错（工具名+归一化指纹）只提示一次；重复查询返回简短提示与首次提示的经验 ID，不再重复全文。状态存经验库同目录 `.query_state/`（sha16 会话名，7 天过期），**不是经验库文件**；不传 `--query-session` 则不去重且零写入。多关键词比关键词少的具体者优先，其余按验证成功案例数、经验 ID 稳定排序。
- `--lessons-path` 可把库与状态重定向到隔离副本（测试/演练用）；`--json` 输出结构化结果供程序判定。
- DSH 内触发方式：DSH 0.2.0-rc.2 无报错钩子入口（插件系统只提供工具+提示注入），因此由插件提示语约定——Agent 在工具报错第一次出现时调用 `blackhole_lessons` 的 `query` 动作（`tool`/`error` 参数；`error` 必须逐字传报错原文整行，不要改写摘要或省略 `Error:` 前缀——pattern 关键词按原文归一化设计，摘要会失配；会话身份自动取当前会话），命中后按「下一步」行动，任务结束后把是否采用、验证成败及证据 `feedback` 回填同一条经验；证据不足保持待验证，不记成功。

## 记录采用后的结果

```bash
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" \
  --feedback adopted --lesson-id <ID> --case <独立任务ID>
python "$DSH_HOME/skills/time-blackhole-audit/blackhole.py" \
  --feedback success --lesson-id <ID> --case <独立任务ID> \
  --evidence "实际验证结果及可回查的步骤/文件"
```

`--feedback` 支持：`recommended`（确实推荐过）、`adopted`（确实采用过）、`success`（采用后验证成功）、`failure`（采用后验证失败）。成功或失败必须有证据，同时算作已采用。

按独立 `--case` 去重，同任务重复反馈不增加案例数；同案例纠正结果时，以最后一次结果为准并保留历史。不要把模型口头声称修好直接记录为验证成功；日志、测试、界面状态或用户确认应支持结论。普通审计不会自动增加推荐、采用或成功计数。

至少3个独立成功案例且没有已记录反例时，报告提示**人工审核**是否提炼为通用规则；不会自动写入 SKILL.md 或 AGENTS.md。跨会话同类型频繁出现只是线索，仍需核实是否同一原因。

## 批量复盘（多会话）

对最近 20 个已结束会话做批量证据提取、跨会话模式聚合、模型归因，并把可避免的低效结论写入经验库。五步入口（`batch_review.py` 与 `blackhole.py` 同目录）：

```bash
python "$DSH_HOME/skills/time-blackhole-audit/batch_review.py"                  # 1 提取：最近20已结束会话→四类片段（只读）
python "$DSH_HOME/skills/time-blackhole-audit/batch_review.py" --groups         # 2 聚合：跨会话合并、优先级排序
python "$DSH_HOME/skills/time-blackhole-audit/batch_review.py" --context        # 3 上下文：目标/用户消息预提取
python "$DSH_HOME/skills/time-blackhole-audit/batch_review.py" --attribute --gids G001,G002   # 4 归因：headless 真实模型
python "$DSH_HOME/skills/time-blackhole-audit/batch_review.py" --write-lessons  # 5 写入：候选经验→知识库
```

写入只接受归因为「可避免低效」的组；写入前自动备份 `<库>.bak-batchreview-<时间戳>`（`lessons_backup` 留痕）；同模式再次出现合并证据而非新增条目（`hits` 计数）。开发副本场景对正式安装目录的库零写入（内置哈希断言）；部署位上写入目标即该目录下的库（同样先备份）。模型归因按组调用、有真实耗时与成本，用 `--gids` 分批控制预算；证据未变的组增量复用既有归因结果（不重复调模型，degraded 条目除外）。详细参数、防重语义与脱敏演示见 `BATCH_REVIEW_USAGE.md`（与脚本同目录）。

## 机器可读输出

`--json` 的顶层对象新增 `window_min`（`--since` 的分钟数，未指定为 `null`）；每个 hole 新增 `lessons` 数组（匹配经验的 `id`/`tag`/`boundary`，最多2条）。均为新增字段，旧字段名、结构与退出码不变；`--brief` 在指定 `--since` 时会在句首注明窗口。

## 回归验证

测试使用临时日志和经验库，不触碰用户会话：

```bash
python -m unittest discover -s "$DSH_HOME/skills/time-blackhole-audit/tests" -v
```

当前 245 项（含 `test_parallel.py` 并行度检测、`test_recall.py` 分层召回、
`test_timing_probe.py` 审计时机探针）。
