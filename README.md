# dsh-velocity

**会话速度审计**：量化你的任务里有多少等待是白等，并给出可执行的消除方式。

它不是"找茬工具"，而是**加速仪表盘**：4 类速度型信号（起后台即阻塞等 / 盲等 / 命令可合并 / 超时转后台）
的时长可直接相加，就是**能净省的时间**。实测 24 个会话 11.2 小时。

```
可直接回收的等待时间：11.2h（4 类速度型信号）
    命令可合并   4.75h     盲等   4.36h     超时转后台   2.65h
    这些都是纯等待/多余轮次，不是干活的时间——改掉就是净省。
```

外加 8 类正确性信号（失败循环、重复调用、串行长调用、盲改缺验证等），共 12 个信号，
以及「记录 → 推荐 → 采用 → 验证」的经验库闭环。

## Token 成本：省时间但不加 token

本插件的价值是**用更少的轮次换时间**，不是靠塞更多上下文换速度。常驻开销已压到：

| 项 | tokens |
|---|---|
| 提示词段 | ≈570 |
| 四个工具 schema | ≈3180 |
| **常驻合计** | **≈3750**（每轮固定） |

压缩过程中删掉的是**重复内容**，不是约束：
- 12 个信号的清单不再写进提示词——`blackhole_lessons` 的 `kind` 枚举就是权威清单，写两遍等于每轮多付一次钱
- `batch_review` 的用法说明从 970 字符压到 ~430 字符，保留了链路顺序、gids 批量、写库前置条件
- `lessons` 各参数说明去掉可推断的重复，保留了硬约束（如 `error` 必须逐字复制、`match` 需全部命中）

自测里有两条守卫防止回退：**所有信号必须能通过工具 schema 发现**，**提示词不得复述信号表**（超过 4 个信号名即失败）。

> 这是一个**事后审计工具**，不做 token 压缩、不改你的模型调用。它读会话转录，
> 告诉你时间花在哪；只有你主动调用时才会运行——不调用时只有上面那 ≈3750 tokens 的常驻成本。

## 量化的加速效果（实测）

提示词/skill 的改动**只对改完之后新开的对话生效**——已开始的对话沿用旧提示词。
所以对比必须「新对话 vs 旧对话、同一时间窗」：

| 会话 | 加载新提示词 | 近 60 分钟浪费率 |
|---|---|---|
| 新对话 | 是 | **0.85%** |
| 旧对话 | 否 | **15.61%** |

**相差 18.3 倍。** 用 `velocity_speedup` 一条命令即可复现，不用凭感觉估"快了百分之几"。

引擎与 `time-blackhole-audit` skill 是同一份，所以两条路径共用同一个经验库：
插件里记录的经验，skill 的 `python blackhole.py` 也能读到，反之亦然。

## 提供的能力

| 工具 | 作用 |
|---|---|
| `blackhole_audit` | 审计会话：默认审计**当前会话**，支持 `session` / `since` / `recent` / `trend` 与 `summary` `brief` `review` `full` `json` 五种输出 |
| `blackhole_lessons` | 经验库：`query` 报错查经验（工具名+报错摘要→至多一条已验证经验，同会话同一错误只提示一次）、`list` 查看、`record` 沉淀、`feedback` 记录推荐/采用/验证结果 |
| `blackhole_batch_review` | 批量复盘：`quick` 一键预览（选最近已结束任务 → 提取 → 聚合 → 归因最有价值的 ≤3 组，返回行动清单，**不写库**，单次 1–3 分钟）或分步 `extract` 选会话提取片段 → `groups` 跨会话聚合 → `attribute` 真实模型逐组归因（必须传 `gids`）→ `write` 把可避免结论写入经验库（必须传 `gids`；真写还需 `confirm`，测试用 `lessons_path`/`dry_run`）；`context` 附目标上下文。分步链路单次调用正常耗时以分钟计 |
| `velocity_speedup` | **速度 A/B 验证**：同时间窗对比「新对话 vs 旧对话」的浪费率，直接给出下降几个百分点、相对加速几倍、是否达标 ≥1%。`list:true` 列最近活跃会话。改完提示词或每轮优化收尾时跑一次，用它的数字回答「快了百分之几」 |

另注册一个 system prompt 章节，说明什么时候值得跑一次自查（连续同类失败、准备重复试过的操作、
多轮轮询没有新状态、长时间探索后说不清拿到了什么可验证结论），以及**报错触发的查询约定**：
工具报错第一次出现时调用 `blackhole_lessons` 的 `query`（`tool`/`error`，会话身份自动取当前会话），
命中按「下一步」行动并把实际结果 `feedback` 回填同一条经验。DSH 无报错钩子入口，触发即靠这段
提示约定 + Agent 主动调用。信号是待核实的线索，不是结论。

### 报错查经验（query）的约定

- 只召回**已验证**经验（有独立成功反馈、无失败反馈）；库中全是候选时回答"未命中"是正确行为。
- 匹配 = 报错文本路径/URL 归一化（与引擎失败循环聚合同一口径）后，经验 `match` 关键词全部命中
  「工具名+归一化报错」；相似但缺关键词的报错不会误召回。
- 会话去重状态存**经验库同目录** `.query_state/`（7 天过期），不是经验库文件；不传会话则零写入。
- `query` / `feedback` / `list` 可传 `lessons_path` 指向隔离副本演练（正本零写入）；`record` 不接受
  `lessons_path`——沉淀是面向正式库的确认动作，测试种子用 CLI `--lessons-path`。

### 批量复盘入口的约定

- `attribute` / `write` 必须带 `gids`（先 `groups` 看清单再分批，每批 3–10 组）——不带 gids 的
  全量归因是 20–30 分钟的运行。工具会直接拒绝，不会放行。
- `write` 默认写引擎所在目录的正式经验库（写入前自动备份 `<库>.bak-batchreview-<时间戳>`）；
  必须显式 `confirm: true` 才会真写。测试/演练传 `lessons_path` 指向临时库（正本与 official
  保持零写入），或先 `dry_run: true` 看合并/新建预览。
- 只写归因 `avoidable` 且非降级的组；`necessary` 与证据不足永不写库。同批重跑、跨批同模式
  都走合并（hits+1、证据追加），不重复新增条目。
- `groups` 动作会在输出末尾附上按优先级的组清单摘要（前 15 组），完整产物见 `OUT` 路径。

### 一键复盘（quick）的约定

- `quick` 是单次调用跑完整条链（选取 → 提取 → 聚合 → 上下文 → 归因，候选上限 3 组），返回最多
  3 个有证据的卡点行动清单，**全程零写入**：不碰经验库，行动清单只附「经确认写入」所需的精确命令。
- 产物落在脚本目录的 `eval/quick/`：`quick_select.json`、`quick_evidence.json`、`quick_groups.json`、
  `quick_context.json`、`quick_attribution.json`、`quick_report.json`；stdout 只有 `OUT <report.json>` 一行。
- 归因缓存键 = 提示词全文 + 版本 + 模型标签，同批重跑零新增模型调用，追加证据只重算受影响组。
- 已对齐既有经验条目的组不进候选（经验库已覆盖）；全部候选都被覆盖时给 `no_new_evidence` 短结果。
  短结果五态：`empty_input` / `no_evidence` / 只剩必要耗时 / 证据不足 / 全部已有经验覆盖。
- 诚实口径：`observed_time_s` 是观测耗时（区间并集，机械事实）；`saveable_time_s` 只在确有复跑
  数据时给数字，默认 `null` 并明注，不拿观测耗时冒充可节省耗时。
- 要把 quick 的结论写进经验库，必须同时传 `attrib_path`（`…/eval/quick/quick_attribution.json`）和
  `groups_path`（`…/eval/quick/quick_groups.json`）——quick 的 gid 编号是它自己的一套，漏传会静默
  消费分步链路的旧产物。

## 审计引擎与经验库

插件自带 `assets/quick_review.py`（一键复盘入口，与 `batch_review.py` 同目录并 import 它），
以及 `assets/blackhole.py`、`assets/batch_review.py`、`assets/eval/batch_scan_select.py`
（前三者与 skill 同一份，逐字节相同；`quick_review.py` 是 B7 产物，skill 侧尚未收录，由插件自带）
和一个空的 `assets/lessons.jsonl`（skill 缺失时的自有经验库；
批量复盘的选择脚本在启动时会读取它做零写入断言，缺了会直接报错，所以打包时带上）。运行时按顺序解析脚本：

1. 环境变量 `BLACKHOLE_SCRIPT`（批量复盘默认用其同目录的 `batch_review.py`，可用
   `BLACKHOLE_BATCH_SCRIPT` 单独覆盖；一键复盘默认用其同目录的 `quick_review.py`，可用
   `BLACKHOLE_QUICK_SCRIPT` 单独覆盖）
2. `$DSH_HOME/skills/time-blackhole-audit/blackhole.py`（**已装 skill 时默认走这里**）
3. 插件自带的 `assets/` 副本

引擎把 `lessons.jsonl` 放在脚本所在目录，所以第 2 条路径意味着：**插件与 skill 共用同一个经验库**，
两边的 `record` / `feedback` 落在同一份文件。删掉 skill 后插件仍可用，但经验库会回落到插件目录。
需要迁移时，把旧的 `lessons.jsonl` 复制到脚本旁边即可。

## 行配置

插件不声明 `Config` schema（这样它不依赖任何 DSH 包即可加载），但仍读取行上的 `config`。
在 profile 的 `cordis.patch.yml` 里覆盖 `blackhole` 这一行的字段即可，改完重启生效：

```yaml
- id: blackhole
  name: 'dsh-velocity'
  config:
    scriptPath: ""      # 审计脚本绝对路径；空 = 自动探测
    pythonPath: ""      # Python 解释器；空 = Windows `python` / 其他 `python3`
    timeoutMs: 120000   # 单次审计超时
    batchTimeoutMs: 900000  # 批量复盘单次动作超时（提取/归因以分钟计）
    promptGuide: true   # 是否注入"何时值得自查"的 system prompt 章节
```

注意匹配到的覆盖会**整体替换**该行的 `config`，不是逐字段合并，所以示例给了全部字段。

字段缺失或类型不对时回退默认值，不会让插件加载失败。注意 Plugin Manager 的配置表单只对有
schema 的行显示；这一行需要直接编辑 YAML。

## 环境变量

| 变量 | 作用 |
|---|---|
| `BLACKHOLE_SCRIPT` | 覆盖审计脚本路径 |
| `BLACKHOLE_BATCH_SCRIPT` | 覆盖批量复盘脚本路径（默认取审计脚本同目录的 `batch_review.py`） |
| `BLACKHOLE_QUICK_SCRIPT` | 覆盖一键复盘脚本路径（默认取审计脚本同目录的 `quick_review.py`，缺失时回落到插件自带副本） |
| `BLACKHOLE_PYTHON` | 覆盖 Python 解释器（默认 Windows `python`，其他平台 `python3`） |
| `DSH_HOME` | 定位 `sessions/` 与 skill 目录（默认 `~/.dsh`） |

依赖：Python 3；审计 `.jsonl.zstd` 会话另需 `zstandard`。

## 实现要点

- 参数以 argv 数组传给引擎，不经过 shell，会话 ID 与经验文本无法注入命令片段。
- 审计只读、并发安全；经验库写入声明为非并发安全。
- 引擎以 `status: "error"` 退出时，工具调用失败而不是把错误当报告返回。
- 工具调用被取消或超过 120 秒会终止子进程。
- 当前会话 ID 取自调用 Agent，省略 `session` 即审计自己。

## 安装与卸载

```bash
# 安装（在 DSH 会话内）
plugin_manager action=install_bundle target="D:\working area\dsh-velocity-plugin"
```

卸载用 `plugin_manager action=remove_bundle target=dsh-velocity`。

## 自测

`bh-selftest.mjs`：mock Cordis ctx 后直接驱动四个工具（默认 117 项；语料产物齐全时 125 项，
覆盖 audit 五种输出、lessons query/list/record/feedback 与去重、batch groups/write/dry_run、
quick 空语料短结果、velocity_speedup 的 list 与 A/B 端到端、取消与行配置），只读用例打真实
skill 脚本，写入用例打临时副本（不污染真实经验库）。

`groups`/`write` 一组用例会回放本地语料产物（`eval/batch_evidence*.json`，不入库）。
仓库不带这些文件，缺失时自动跳过并用 `skip` 标注；想跑全量就把
`BLACKHOLE_CORPUS` 指向含 `eval/` 产物的目录。

```bash
node bh-selftest.mjs
```
