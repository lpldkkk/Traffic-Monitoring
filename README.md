# 流量监测（Traffic Monitoring）

基于本机抓包、连接行为证据和大模型原生 Function Calling 的网络安全分析工具。实时采集、规则评估和事件生成独立于 LLM 运行；模型通过只读工具查询证据，不能执行任意命令、封禁网络或终止进程。

当前分支为 **阶段 1C 功能重建版**：在现有源码上隔离 Dashboard 后重新验证，不声称是历史验收时的逐字节快照。入口为 `python app.py`，界面为 Tkinter。数据库版本仍为 **4**。

## 版本范围

- **1A**：独立 `connection_id`、五元组复用处理、TCP 观察边界与不确定性、应用身份持久化、版本化迁移。
- **1B**：异常线索、安全事件关联、去重、revision、成员、证据与时间线。
- **1C**：持久化调查队列、固定事件范围、原生 Function Calling、步骤恢复、预算、重试、取消、结构化报告及 Tkinter 任务入口。
- 保留实时抓包、CSV、PCAP 回放、正常基线、相似历史、检测评估及原课程 C++ 源码。
- FastAPI、React、TypeScript Dashboard 保存在 `dev/dashboard`，不属于本分支，也不需要 Node.js。

`traffic_agent/` 是内部 Python 包，不是项目整体名称。启动入口、包导入和数据库默认位置没有改名。

## Agent 框架是什么

这是自行实现的 Python Agent 循环，使用 OpenAI 兼容的 Chat Completions API 和原生 Function Calling，没有 MCP、LangChain 或 LangGraph。

一次普通工具分析是：程序把问题和 JSON Schema 工具定义交给模型；模型返回工具名称与参数；本地程序校验白名单、参数、范围和预算后执行 Python 查询；结构化结果作为工具消息回传给模型，继续下一轮，最后校验证据并显示回答。模型本身不能直接读取数据库或控制网卡。

普通对话可以让模型选择工具；高风险连接调查要求完成规定的取证步骤；1C 事件调查则限定在入队时冻结的事件 revision 和证据清单中。因此，它是**受约束的工具调用 Agent 与确定性调查流程的组合**，不等于完全自主规划的安全分析员。

检测和调查分工：规则模块提出异常线索，事件模块关联线索，LLM 查询证据并尝试解释。没有训练自己的检测模型，也没有让 LLM 逐包判断。接入 MCP 只会改变工具如何标准化对外提供，不会自动改善检测准确率；本项目无需 MCP 也能调用本地工具。

## 安装与启动

建议 Windows 10/11、Python 3.11 或更高版本（含 Tkinter）。真实抓包需要用户另行安装 [Npcap](https://npcap.com/#download)，权限取决于驱动安装选项；离线回放、合成测试不要求进行实时抓包。不要未经授权将 Npcap 安装程序随项目再分发。

在项目根目录的 PowerShell 中执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

如果使用已有 Python 环境，也可以执行 `python -m pip install -r requirements.txt` 后运行 `python app.py`。`流量监测启动.bat` 使用系统 Python 启动；虚拟环境用户应先激活环境或使用上面的完整解释器路径。

首次启动在 `data/traffic.db` 初始化数据库。旧库会先备份，再事务迁移；已有当前版本的库不会重复迁移。同一数据目录只允许一个交互程序实例。测试不要直接打开真实用户库。

## 使用实时采集与历史

1. 首页点击“检测当前网络”，按当前路由选择网卡。手动网卡覆盖在设置中。开始采集不需要 API Key。
2. 列表按用量显示所有观测连接，每页 10 条；可以搜索、翻页并点击查看属性。实时列表为近 5 分钟窗口，完整采集保存在历史中。
3. 停止后保存编号会话，最多保留 10 次；达到上限后需要用户选择删除。可单独保留某次采集中的指定连接。
4. 红色感叹号表示需要核实的行为线索，不代表已确认攻击。大流量、单个 SYN/RST 不单独证明恶意。
5. 历史连接使用 `(session_id, connection_id)` 精确引用。进程身份来自采集时的快照匹配；短连接、共享 UDP、代理复用和权限限制可能导致身份未知。

代理视角只在有可验证的本机代理关联信息时显示原始应用，不能把代理出口隧道任意归属到浏览器。进程名相同不代表同一进程实例，IP 相同也不代表同一安全事件。

## 模型与费用

在“设置”选择现有 OpenAI 或 DeepSeek 预设并保存 API Key。预设名称和预算单价来自 `traffic_agent/config.py`，实际可用模型、服务商价格和账户权限应以服务商为准；本版本没有增加模型。

也可在尚未保存本地配置时使用环境变量：

```powershell
$env:DEEPSEEK_API_KEY = "填入你的密钥"
$env:LLM_BASE_URL = "https://api.deepseek.com"
$env:LLM_MODEL = "deepseek-flash"
python app.py
```

OpenAI 使用 `OPENAI_API_KEY`，通用备用变量为 `LLM_API_KEY`。不要把真实值写入源码、提交或问题反馈。界面配置优先于旧环境变量；保存的服务商密钥优先于环境变量。

- 非密钥配置：`config.local.json`。
- 密钥：`credentials.local.json`，由当前 Windows 用户的 DPAPI 加密；更换机器或用户需要重新输入。
- 共享费用账本持久化在数据库；费用预算不是服务商账单硬封顶。
- 事件任务默认最多 3 次尝试，每次最多 8 次模型请求、180 秒软时间预算；整个任务最多 16 次工具调用、0.25 USD 预留，并受当前配置和共享余额约束。
- 默认工具预算最多深入调查 2 条连接，大事件可能为 `partial`。重试不清零费用和工具计数。
- 时间限制在操作之间检查；HTTP 等待不能立即中断。超时或取消不保证服务商没有处理请求或计费。

## 安全事件与自动调查

在“事件调查”页面选择事件并点击“调查所选事件”；按需开启“自动调查新高风险事件”。自动发现默认关闭，已入队的未完成任务按恢复规则继续。

任务绑定 `event_id + revision + 数据截止范围`，冻结事件、成员及历史参考。事件产生新 revision 后可以入队新任务，不覆盖旧报告。单工作线程共享现有 Agent 锁和费用账本；采集不用等待 API。

任务状态包括 `queued`、`running`、`completed`、`partial`、`retry_wait`、`blocked_budget`、`failed`、`cancelled`。界面可以筛选、查看步骤/报告、取消及对符合条件的任务重试或恢复预算。

- 已成功保存的只读查询在重启后复用。
- 可确定安全重试的错误按退避与最大尝试次数处理。
- 结果未知的模型请求标为部分完成，不自动无限重发；手动重试需要确认重复计费风险。
- 取消后不再主动开始新工具调用，已发出的 HTTP 请求可能仍在处理。
- 调查完成不等于事件已解决，事件严重程度不等于恶意概率。

调查报告区分：已验证事实、可能解释、异常证据、基线对比、缺失证据、未调查范围和人工复核建议。事实引用会核对来源、字段类型和数值；不能把高频说成高并发、把出站流量直接说成数据外传，或把观察到握手说成应用连接成功。

## 架构和目录

```text
Npcap / Scapy → 包头元数据 → 有界队列 → SQLite 会话与连接实例
                                              ↓
                               异常证据 / 正常基线 / 事件关联
                                              ↓
                     持久化任务 → 单工作线程 → Function Calling → 报告
                                              ↑
                                Tkinter（后台查询，主线程更新界面）
CSV / PCAP → 离线分析路径，共用现有解析、评估和查询模块
```

| 路径 | 职责 |
| --- | --- |
| `app.py` | 桌面、模拟、回放、评估和实验命令入口 |
| `traffic_agent/capture.py`、`connection_instances.py` | 实时解析、实例边界、TCP 观察状态 |
| `traffic_agent/store.py`、`migrations.py` | SQLite 存储、版本迁移、备份恢复 |
| `traffic_agent/applications.py`、`connections.py`、`proxy.py` | 应用身份、连接视图及代理关联 |
| `traffic_agent/anomaly.py`、`baseline.py` | 不变的规则评分、证据和正常范围 |
| `traffic_agent/incidents.py`、`incident_store.py` | 确定性事件关联、成员、revision、证据与时间线 |
| `traffic_agent/jobs.py`、`runtime.py` | 持久任务、预算预留、恢复和调度 |
| `traffic_agent/agent.py`、`tools.py`、`investigation.py` | 原生 Function Calling、参数白名单、冻结只读工具、报告校验 |
| `traffic_agent/ui.py`、`local_lock.py` | Tkinter 和同数据目录单实例保护 |
| `traffic_agent/replay.py`、`evaluation.py`、`lab.py` | PCAP、检测指标及可选本机回环实验 |
| `tests/` | 自动化回归与明确标注的合成夹具生成器 |
| `1源代码/` | 个人开发的原 C++ 课程源码，保留参考，不参与 Python 构建 |
| `data/`、`datasets/`、`2可执行程序/` | 本地资料，忽略提交；数据库、真实 PCAP、原 CSV 和 EXE 不随源码发布 |

## 数据库与恢复

版本 4 包含会话、实例、应用身份、事件等原表，以及 `investigation_jobs`、`investigation_steps`、`investigation_reports`、`investigation_sources`、`investigation_worker`。

历史已聚合连接保持 `legacy_aggregate` 等标识，不伪装成精确实例。TCP 实例区分 SYN 重传、关闭后重建和五元组复用，乱序、缺包及中途开始抓包仍保留不确定性。旧数据不能补出未保存的报文内容或握手证据。

迁移前使用 SQLite 在线备份包含已提交的 WAL 内容，写入数据库旁的 `backups/`；完整性检查失败不会继续迁移，DDL 失败事务回滚。恢复时应关闭程序并恢复到新路径，保留原库及 WAL 以便核对：

```python
from traffic_agent.migrations import restore_copy
restore_copy("备份文件.sqlite", "新的恢复文件.db")  # 目标必须不存在
```

不会在重建本版本或运行常规测试时自动迁移用户原库。用户随后正常启动程序时，程序仍按实际版本执行备份/迁移。删除或筛选采集会清理依赖它的派生事件证据及调查记录，操作前应确认保留范围。

## PCAP、CSV 与检测评估

```powershell
python app.py --simulate
python app.py --replay "你的记录.pcap" --output "data/replay-example"
python app.py --evaluate "你的带标签数据.jsonl" --output "data/evaluation.json"
```

默认回放不发送报文、不调用 LLM，在独立内存库解析。同一 PCAP、代码和配置得到一致的逻辑实例、规则结果和本地报告；新增 LLM 回答的文字不保证确定性。只有加 `--agent` 才使用已有模型配置，可能计费。完整成功报告按输入和配置指纹缓存。

评估数据使用 `session_id`、`timestamp`、`features`、`label`，其中 0 为正常、1 为异常。报告包含 TP/TN/FP/FN、Precision、Recall、F1、FPR、FNR 和评估覆盖；分母为零返回 null，不能制造满分。

CSV 字段：`Source,Destination,Protocol,SrcPort,DstPort,DataSize,Duration`。没有包数、握手、采集时间或恶意标签时会明确标记未知，不能把未触发 TCP 规则解释为安全。

可选实验命令 `python app.py --collect-dataset "data/my-lab" --repeats 3` 会实际创建本机回环流量并保存 PCAP；需要 Npcap，SSH 场景另需 `paramiko`。应使用空目录，仅在明确需要采集实验数据时执行。实验标签是场景设计标签，不能替代独立人工标注。

## 测试与验证范围

```powershell
python -m unittest discover -s tests -v
python -m unittest discover -s tests -p test_jobs.py -v
python -m unittest discover -s tests -p test_runtime.py -v
```

默认不启用实时抓包集成测试或真实代理读取，不调用收费 LLM。测试使用内存/临时数据库和脚本模型。

源码版本不包含私有 PCAP/CSV：`tests/sample_data.py` 在缺少私有文件时生成临时、确定性的合成回放/CSV夹具，保留原评分、实例、事件和调查链断言。单独的真实实验语料评估在未提供 `datasets/` 时明确跳过；它没有被替换为合成准确率报告。本机有原实验数据时继续执行原断言。

需要真实回环采集及 Tk 集成验证时显式启用：

```powershell
$env:RUN_LOCAL_INTEGRATION = '1'
python -m unittest discover -s tests -v
# 可选真实代理：另设 RUN_LOCAL_PROXY_TEST=1
```

这会生成本机 HTTP/TCP/UDP 流量并可能显示短暂测试窗口，需要 Npcap 权限。默认测试跳过这些用例不代表它们已经验证通过。

历史 1C 验收记录为 235 项、234 通过、0 失败、1 跳过，仅代表当时环境；本次重建结果单独记录于 `CHANGELOG.md`。真实模型自主选工具、解释质量和实际账单行为尚未验证。受控本机样本、相关重复实验和合成规则用例均不能证明公网攻击检测准确率。

## 隐私、安全与已知限制

- 普通实时监测不保存或上传原始载荷；显式实验/回放的 PCAP 留在本地。发给模型的是用户问题与脱敏元数据，用户输入也不应含密码和报文。
- 工具禁止任意文件/SQL/shell/阻断操作；流量和工具返回是证据，不是可执行指令。
- 本工具只看到选定接口可见的流量，不能解密 TLS，也不能保证看到全网活动。代理复用、抓包丢失和快照延迟会限制归属与结论。
- 规则阈值未完成广泛真实标注数据校准；正常轮询可能误报，恶意语义外联可能漏报，UDP/DNS 规则覆盖有限。
- 没有足够人工正常历史时，基线和类似历史会返回证据不足。
- 长期高吞吐、超大事件拆分、全部平台兼容性和真实模型调查质量仍需验证。

## 开发、贡献与项目范围

修改前先运行适用测试。规则变更应记录版本、证据字段和误报/漏报影响；不能放宽断言掩盖回归。问题反馈请提供版本、复现步骤和脱敏日志，不附 API Key、用户数据库或真实 PCAP。安全问题应先通过维护者认可的私密渠道反馈，当前未指定公开接收邮箱。

项目交付范围截止阶段 1C。`dev/dashboard` 仅保留已经产生的开发成果，不继续进行 UI 迁移或后续阶段开发。本版本的长期压力测试、独立人工标注与真实模型质量验证仍属于已披露的限制，不能作为已交付能力宣传。

项目自有代码采用 **GNU GPL version 2 only（SPDX: GPL-2.0-only）**，见 [LICENSE](LICENSE)；维护者已确认自有代码权属并选择此许可。该声明不重新许可任何第三方依赖。本版本仅建立本地提交，未发布 GitHub。

| 依赖 | 自身许可 |
| --- | --- |
| Scapy 2.6.1 | GPL-2.0-only |
| httpx、psutil | BSD-3-Clause |
| jsonschema | MIT |
| Paramiko（可选 SSH 实验） | LGPL-2.1 |

依赖由安装工具单独获取，不把本机 `.runtime` 打入源码提交。依赖版本范围内的实际版本及传递依赖应在再分发时复核并保留其许可和版权通知。Npcap 使用自身许可，不随 GPL 项目源码附送驱动安装程序。
