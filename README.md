# Wukong (悟空) — DAG-based Code Vulnerability Scanner

Wukong 是一个基于 DAG（有向无环图）调度的代码安全审计工具，结合 LLM Agent 的语义理解能力，通过原生污点分析（taint analysis）与多维度安全审计，实现对 Java/Go/Python 项目的自动化漏洞扫描。

## 整体架构

```
                    CLI (python -m code_audit)
                            │
                      AuditConfig (Pydantic)
                            │
                    ┌───────┴───────┐
                    │  AgentRegistry │  ←── @register_agent 装饰器注册
                    └───────┬───────┘
                            │
                      build_dag()
                            │
                    ┌───────┴───────┐
                    │  DAGScheduler  │  ←── Kahn 拓扑排序 + asyncio 并行执行
                    └───────┬───────┘
                            │
         ┌──────────────────┼────────────────────┐
         ▼                  ▼                    ▼
    LLM Agent        taint_analyzer         Template Renderer
   (AuditAgent)     (Coordinator)          (report_generator)
         │                  │
    ┌────┴─────┐      ┌────┴─────────────────────┐
    │ToolRegistry│      │  Route-Group Parallelism  │
    └────┬─────┘      │  ┌─────┐ ┌─────┐ ┌─────┐ │
         │            │  │Grp 1│ │Grp 2│ │Grp 3│ │  ←── asyncio.gather + Semaphore
         │            │  └──┬──┘ └──┬──┘ └──┬──┘ │
         │            │     │       │       │     │
         │            │  AuditAgent sessions      │
         │            └───────────────────────────┘
         │
    ┌────┴─────┐
    │CodeResolver│  ←── grep (default) / tree-sitter / LSP
    └──────────┘
```

### DAG 执行流程

```
Layer 0:  route_mapper                         (提取 HTTP 路由)
              │
              ├─────────────┬──────────────┬─────────────────────┐
              ▼             ▼              ▼                     ▼
Layer 1:  auth_auditor  taint_analyzer  hardcoded_auditor  path_traversal_auditor
          (认证审计)    (污点分析)       (硬编码检测)        (路径穿越检测)
              │             │              │                     │
              └─────────────┼──────────────┼─────────────────────┘
                            ▼
Layer 2:              vuln_verifier                  (独立验证)
                            │
                            ▼
Layer 3:            report_generator                 (报告生成)
```

同一 Layer 内的 Agent 并行执行，跨 Layer 串行执行。上游 Agent 失败时，依赖它的下游 Agent 会被自动跳过。

## 目录结构

```
wukong/
├── requirements.txt              # 依赖: anthropic, openai, pydantic, loguru, aiofiles
├── code_audit/
│   ├── __init__.py
│   ├── __main__.py               # python -m code_audit 入口
│   ├── main.py                   # CLI 参数解析 + 流水线执行
│   ├── config.py                 # AuditConfig (Pydantic BaseModel)
│   ├── schemas/
│   │   ├── route.py              # RouteEntry, ParamEntry
│   │   ├── finding.py            # Finding, CallChainNode
│   │   ├── auth.py               # AuthRouteUpdate
│   │   ├── verification.py       # VerificationResult
│   │   └── report.py             # AuditReport
│   ├── tools/
│   │   ├── registry.py           # ToolRegistry — 管理 Agent 可调用的工具 + 代码解析工具
│   │   ├── file_tools.py         # read_file, glob_files, grep_content, write_file, append_file
│   │   ├── bash_tools.py         # run_command (shell 执行)
│   │   ├── code_resolver.py      # CodeResolver ABC + GrepResolver + create_resolver()
│   │   ├── tree_sitter_resolver.py   # TreeSitterResolver (AST 级解析, 需 tree-sitter)
│   │   └── lsp_resolver.py       # LSPResolver (编译器级解析, 需 LSP 服务器)
│   ├── pipeline/
│   │   ├── stage.py              # Stage 数据类
│   │   └── dag.py                # DAGScheduler — Kahn 拓扑排序 + asyncio.gather
│   └── agents/
│       ├── registry.py           # AgentRegistry + @register_agent 装饰器
│       ├── base.py               # AuditAgent — 双 Provider 工具调用循环 + 滑动窗口上下文压缩
│       ├── route_mapper.py       # Layer 0: HTTP 路由提取
│       ├── auth_auditor.py       # Layer 1: 认证/授权漏洞审计
│       ├── hardcoded_auditor.py  # Layer 1: 硬编码密钥/凭据检测
│       ├── path_traversal_auditor.py  # Layer 1: 路径穿越漏洞检测
│       ├── taint_analyzer.py     # Layer 1: 协调器 + 路由分组并行污点分析
│       ├── vuln_verifier.py      # Layer 2: 独立源码验证
│       └── report_generator.py   # Layer 3: Markdown/JSON 报告生成
```

## 核心组件

### 1. AuditConfig

基于 Pydantic 的全局配置，支持从 CLI 参数和环境变量获取值：

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `project_path` | 待审计项目路径 | (必填) |
| `provider` | LLM 提供商 | `"anthropic"` |
| `model` | 模型名称 | `claude-sonnet-4-20250514` / `gpt-4o` |
| `api_key` | API 密钥 | 从环境变量读取 |
| `base_url` | API 端点 | 从环境变量读取 |
| `output_dir` | 输出目录 | `/tmp/{project}-audit` |
| `max_concurrent_agents` | 同层最大并发数 | 3 |
| `agent_max_turns` | 每个 Agent 最大对话轮次 | 0 (不限) |
| `agent_timeout` | 每个 Agent 超时 (秒) | 0 (使用 Agent 默认值) |
| `taint_group_size` | 污点分析每组路由数 | 10 |
| `taint_max_concurrent` | 污点分析最大并发组数 | 3 |
| `resolver` | 代码解析后端 | `"grep"` |
| `lsp_cmd` | LSP 服务器启动命令 | `None` |

### 2. @register_agent 装饰器

所有 Agent 通过装饰器自注册到全局 `AgentRegistry`，无需手动修改流水线代码：

```python
@register_agent(
    name="path_traversal_auditor",
    layer=1,
    depends_on=["route_mapper"],
    timeout=1800,
    description="Find path traversal vulnerabilities (CWE-22)",
)
async def run_path_traversal_auditor(config: AuditConfig, inputs: dict) -> dict:
    ...
```

添加新 Agent 的步骤：
1. 在 `agents/` 目录下新建 `.py` 文件
2. 用 `@register_agent` 装饰 `async def run_xxx(config, inputs) -> dict` 函数
3. 在 `main.py` 的 `_import_agents()` 中添加 import
4. 如果下游 Agent（如 `vuln_verifier`）需要消费其输出，更新 `depends_on`

### 3. AuditAgent — 双 Provider 智能体循环

`AuditAgent` 驱动 LLM 的工具调用循环，支持两种 Provider：

- **Anthropic**: 使用 `AsyncAnthropic` + `client.messages.stream()`
- **OpenAI**: 使用 `AsyncOpenAI` + `client.chat.completions.create()`（兼容阿里云百炼等 OpenAI 兼容接口）

工作流程：
1. 向 LLM 发送系统提示词 + 用户消息
2. LLM 返回工具调用请求（如 `grep_content`、`read_file`）
3. 执行工具，将结果返回 LLM
4. 循环直到 LLM 调用虚拟提交工具（`submit_findings` / `submit_result`）
5. 从提交的 JSON 中提取结构化结果

容错机制：
- 工具返回结果截断至 30000 字符，防止上下文溢出
- 连续 3 次提交失败后，回退到从 LLM 文本输出中提取 JSON
- 达到最大轮次时，尝试从最后文本提取 JSON

**滑动窗口上下文压缩** (`context_window_turns` 参数)：
- 对话轮次过多时，自动压缩旧消息以控制上下文窗口
- 保留策略：系统提示词 + 首条用户消息 + 最后 N×3 条消息（N = `context_window_turns`）
- 中间的旧消息被替换为 `[Earlier conversation compressed — N turns removed]`
- taint_analyzer 的分组 Agent 默认 `context_window_turns=20`，防止大型代码库分析时上下文溢出

### 4. ToolRegistry

管理 Agent 可调用的工具集，以 Anthropic tool 格式存储，运行时自动转换为 OpenAI 格式：

**基础工具（所有 Agent 均可使用）：**

| 工具 | 说明 |
|------|------|
| `read_file(path, offset, limit)` | 读取文件，返回带行号的内容 |
| `glob_files(pattern, path)` | 递归文件模式匹配，最多 200 条 |
| `grep_content(pattern, path, file_type)` | 正则搜索文件内容，最多 500 条 |
| `write_file(path, content)` | 写入文件 |
| `append_file(path, content)` | 追加文件 |
| `run_command(command)` | 执行 shell 命令 |

**代码解析工具（通过 `--resolver` 启用，仅 taint_analyzer 使用）：**

| 工具 | 说明 |
|------|------|
| `find_definition(symbol, context_file?)` | 查找方法/类/字段的定义位置 |
| `find_references(symbol, context_file?)` | 查找符号的所有引用位置 |
| `extract_function_calls(file_path, method_name)` | 提取方法体中的所有函数调用（含 internal/external 分类） |
| `get_type_info(symbol, context_file)` | 获取变量的类型信息（数值/字符串/集合） |

代码解析工具通过 `ToolRegistry.for_llm_agent(resolver=resolver)` 注册，底层由 `CodeResolver` 实现。使用线程池 Executor 桥接异步调用，避免事件循环冲突。

### 5. CodeResolver — 多后端代码解析

`CodeResolver` 是代码符号解析的抽象层，支持三种后端实现：

| 后端 | CLI 参数 | 依赖 | 精度 | 说明 |
|------|----------|------|------|------|
| **GrepResolver** | `--resolver grep` (默认) | 无 | 基础 | 正则匹配，零依赖，适合快速扫描 |
| **TreeSitterResolver** | `--resolver tree-sitter` | `tree-sitter`, `tree-sitter-java` | AST 级 | 使用 tree-sitter 解析 AST，精确提取函数定义和调用，支持 Sink 预过滤 |
| **LSPResolver** | `--resolver lsp` | LSP 服务器 | 编译器级 | 通过 JSON-RPC stdio 与 LSP 服务器通信，提供最精确的类型信息和定义跳转 |

工厂函数 `create_resolver(project_path, resolver_type, **kwargs)` 自动创建对应实现。tree-sitter 和 LSP 后端在依赖不可用时会优雅降级到 GrepResolver。

### 6. DAGScheduler

基于 Kahn 拓扑排序算法的调度器：

1. 将所有 Stage 按依赖关系拓扑排序，分成多个 Layer
2. 同一 Layer 内的 Stage 通过 `asyncio.gather` 并行执行
3. 每个 Stage 执行时收集上游依赖的输出作为输入
4. 上游失败则下游自动跳过
5. 支持 per-stage 超时（`asyncio.wait_for`）

## Agent 详细说明

### route_mapper (Layer 0)

提取项目中所有 HTTP 路由和 API 端点。

- 通过 `grep_content` 搜索多种框架的路由定义模式（Spark Java、Spring MVC、JAX-RS、Servlet）
- 识别静态文件服务配置和过滤器注册
- 输出: `{"routes": [RouteEntry...]}`

### auth_auditor (Layer 1)

分析认证和授权机制，发现认证绕过漏洞。

- 识别 Shiro / Spring Security / JWT / Filter 等认证框架
- 检查每个路由的认证状态
- 发现路径穿越绕过、HTTP 方法不匹配、缺失认证等问题
- 输出: `{"findings": [Finding...], "route_updates": [AuthRouteUpdate...]}`

### hardcoded_auditor (Layer 1)

检测硬编码的敏感信息。

- 搜索密码、API 密钥、数据库连接串、加密密钥、AWS 凭据等
- 检查配置文件中的明文敏感信息
- 区分真实凭据与占位符
- 输出: `{"findings": [Finding...]}`

### path_traversal_auditor (Layer 1)

检测路径穿越 / 目录遍历漏洞 (CWE-22/CWE-23)。

- 搜索 7 类危险 Sink：File 构造器、NIO 操作、静态文件服务、路径操作、Servlet 文件访问、URL 解码、已有防御
- 逆向追踪 Source（HTTP 请求参数、URI 路径、请求头等）到 Sink 的数据流
- 评估缓解措施的有效性（路径规范化 + 边界检查、白名单、编码处理）
- 检查框架版本的已知 CVE（如 CVE-2018-9159）
- 输出: `{"findings": [Finding...]}`

### taint_analyzer (Layer 1)

LLM 驱动的原生污点分析，覆盖 SQLI / RCE / XXE / SSRF 四类漏洞。

此 Agent 取代了之前基于子进程调用的 Pecker 扫描器，将污点分析逻辑以原生 LLM Agent 形式重新实现。核心方法论来自 Pecker 的 **正向追踪（Source→Sink）生产者/消费者** 架构。

#### 协调器架构

taint_analyzer 采用 **协调器 + 分组并行** 模式，无需额外 LLM 调用即可拆分工作：

```
taint_analyzer (协调器, 非 LLM)
        │
        ├── Step 1: Pre-scan (grep, 零 LLM 成本)
        │   └── 在代码库中搜索 4 类 Sink 模式 (SQLI/RCE/XXE/SSRF)
        │       并记录文件位置，作为优先级参考
        │
        ├── Step 2: 路由分组 (taint_group_size=10)
        │   └── 57 routes → 6 groups
        │
        ├── Step 3: 并行分析 (asyncio.gather + Semaphore)
        │   ┌───────────┬───────────┬───────────┐
        │   │  Group 1  │  Group 2  │  Group 3  │  ← max_concurrent=3
        │   │ AuditAgent│ AuditAgent│ AuditAgent│
        │   │ 10 routes │ 10 routes │ 10 routes │
        │   └─────┬─────┴─────┬─────┴─────┬─────┘
        │         │           │           │
        │   ┌─────┴─────┬─────┘           │
        │   │  Group 4  │  Group 5  Group 6│  ← Semaphore 释放后启动
        │   └───────────┴─────────────────┘
        │
        └── Step 4: 合并去重 (file_path + line_number + type)
            └── 写入 taint-findings.json
```

每个分组 Agent 是一个独立的 `AuditAgent` 会话，具备：
- 完整的方法论提示词（5 阶段分析流程）
- 自己的 Sink 模式库（54+ SQL、6+ RCE、51+ XXE、SSRF）
- 自己分配的路由子集 + 预扫描的 Sink 位置
- CodeResolver 工具（find_definition、find_references 等）
- 滑动窗口上下文压缩（`context_window_turns=20`）

#### 分析流程（每个分组 Agent 内部）

1. **Phase 1 — 构建初始工作队列**
   - 读取每个 handler 的源码，作为初始工作队列
   - 参考预扫描 Sink 位置优先排序分析目标

2. **Phase 2 — 正向追踪（Sink Check + Next-Call 展开）**
   - 对每个方法执行两个任务：
     - **Task A — Sink Check**（等价于 Pecker 的 `first_sink_chat()`）：检查当前方法是否包含危险 Sink 调用
     - **Task B — Next-Call 展开**（等价于 Pecker 的 `second_vulnerability_chat()`）：识别值得深入追踪的子函数调用
   - 递归追踪子函数，最多 6 层深度
   - 重复检测：同一调用链中已分析的方法不会重复分析
   - **关键**：无论是否找到 Sink，都要执行 Next-Call 展开

3. **Phase 3 — Multi-Judge 多维验证**
   - 对每个潜在漏洞执行多维度判定（借鉴 Pecker 的 multi-judge chain，早期终止）：
     - **SQLI**: sink_check → input_check → sanitizer_check → taint_check
     - **RCE**: sink_check → input_check → sanitizer_check → taint_check
     - **XXE**: sink_check → feature_check → input_check → taint_check
     - **SSRF**: sink_check → input_check → sanitizer_check → taint_check
   - 任意一个 check 返回 True（安全），则判定为误报并丢弃

4. **Phase 4 — XML/MyBatis 逆向污点验证（可选）**
   - 仅针对 MyBatis XML mapper 中的 `${}` 动态 SQL Sink
   - 提取 XML 中的污点变量，逆向遍历调用链验证污点传播
   - 基于类型过滤（数值类型视为安全）和类型敏感性分析（Map key / Class field / List index）

5. **Phase 5 — 结构化报告**
   - 每条发现包含完整的 source→sink 调用链、代码片段、POC 和修复建议

- 输出: `{"findings": [Finding...]}`

### vuln_verifier (Layer 2)

独立验证上游所有 Agent 的发现。

- 合并上游 4 个 Agent（auth_auditor、taint_analyzer、hardcoded_auditor、path_traversal_auditor）的 findings
- 按严重性排序，最多验证 30 条
- 对每条 finding 执行 5 步验证：确认 Source、确认 Sink、追踪数据流、检查净化措施、分配状态
- 不信任上游声明，独立阅读源码验证
- 输出: `{"verifications": [VerificationResult...]}`

### report_generator (Layer 3)

汇总生成最终审计报告（纯模板渲染，无 LLM 调用）。

- 合并所有 findings 和 verifications
- 按验证状态分类：confirmed / false_positive / downgraded / needs_review
- 生成 Markdown 报告和结构化 JSON
- 输出文件: `security-audit-report.md`, `report.json`, `routes.json`, `findings.json`, `verified.json`

## 使用方法

### 安装依赖

```bash
cd wukong
pip install -r requirements.txt
```

### 基本用法

```bash
# 使用 Anthropic Claude
python -m code_audit /path/to/project -o /tmp/output -v

# 使用 OpenAI 兼容接口（如阿里云百炼 Qwen）
python -m code_audit /path/to/project \
  --provider openai \
  --api-key "$QWEN_BAILIAN" \
  --base-url "https://dashscope.aliyuncs.com/compatible-mode/v1" \
  --model qwen-plus \
  -o /tmp/output -v
```

### CLI 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `project_path` | 待审计项目根路径 | (必填) |
| `-o, --output-dir` | 输出目录 | `/tmp/{project}-audit` |
| `--provider` | `anthropic` 或 `openai` | `anthropic` |
| `-m, --model` | 模型名称 | 自动选择 |
| `--api-key` | API 密钥 | 从环境变量读取 |
| `--base-url` | API 端点 URL | 从环境变量读取 |
| `--max-turns` | 每个 Agent 最大对话轮次 | 0 (不限) |
| `--timeout` | 每个 Agent 超时秒数 | 0 (使用默认) |
| `--max-concurrent` | 同层最大并发 Agent 数 | 3 |
| `--resolver` | 代码解析后端: `grep`, `tree-sitter`, `lsp` | `grep` |
| `--taint-group-size` | 污点分析每组路由数量 | 10 |
| `--taint-max-concurrent` | 污点分析最大并发组数 | 3 |
| `--lsp-cmd` | LSP 服务器启动命令 (仅 `--resolver lsp`) | 无 |
| `-v, --verbose` | 启用 DEBUG 日志 | 关闭 |

## 扩展新 Agent

以添加一个 SSRF 检测 Agent 为例：

```python
# code_audit/agents/ssrf_auditor.py

from ..config import AuditConfig
from ..tools.registry import ToolRegistry
from .base import AuditAgent, create_llm_client
from .registry import register_agent

SSRF_PROMPT = """\
You are an SSRF vulnerability detection expert...
## Project path
{project_path}
...
"""

@register_agent(
    name="ssrf_auditor",
    layer=1,
    depends_on=["route_mapper"],
    timeout=1800,
    description="Detect SSRF vulnerabilities",
)
async def run_ssrf_auditor(config: AuditConfig, inputs: dict) -> dict:
    client = create_llm_client(config.provider, config.api_key, config.base_url)
    registry = ToolRegistry.for_llm_agent()
    prompt = SSRF_PROMPT.format(project_path=config.project_path, ...)
    agent = AuditAgent(
        client=client, model=config.model,
        system_prompt=prompt, tool_registry=registry,
        name="ssrf_auditor", provider=config.provider,
    )
    result = await agent.run("Analyse the project for SSRF vulnerabilities.")
    if "findings" not in result:
        result["findings"] = []
    return result
```

然后在 `main.py` 中添加 `import code_audit.agents.ssrf_auditor`，并将 `"ssrf_auditor"` 加入 `vuln_verifier` 和 `report_generator` 的 `depends_on` 列表。

---

## 实战案例：扫描 SparkJava 2.7.1 (CVE-2018-9159)

### 目标项目

[SparkJava](http://sparkjava.com/) 2.7.1 — 一个轻量级 Java Web 框架（注意不是 Apache Spark），包含已知的路径穿越漏洞 CVE-2018-9159。

- 语言: Java 8
- 构建工具: Maven
- 规模: ~179 个 Java 文件，~20K 行代码
- 已知漏洞: CVE-2018-9159（CWE-022 路径穿越，在静态文件服务中通过 URL 编码字符绕过目录遍历防护）

### 执行命令

```bash
cd wukong
python -m code_audit ../project_for_detect/spark \
  --provider openai \
  --api-key "$QWEN_BAILIAN" \
  --base-url "https://dashscope.aliyuncs.com/compatible-mode/v1" \
  --model qwen-plus \
  -o /tmp/spark-audit-v6 -v
```

### 执行过程

Pipeline 共 7 个 Stage，按 DAG 拓扑序执行。taint_analyzer 自动将 57 条路由拆分为 6 组并行分析：

```
00:18:28 [INFO] Wukong (悟空) Code Audit
00:18:28 [INFO] Project:  .../project_for_detect/spark
00:18:28 [INFO] Provider: openai (qwen-plus via 阿里云百炼)
00:18:28 [INFO] Starting pipeline with 7 stages

00:18:28 [STAGE] route_mapper              >>> RUNNING
00:24:16 [STAGE] route_mapper              >>> SUCCESS      (57 routes)

00:24:16 [STAGE] auth_auditor              >>> RUNNING  ─┐
00:24:16 [STAGE] taint_analyzer            >>> RUNNING   │
00:24:16 [STAGE] hardcoded_auditor         >>> RUNNING   ├─ 并行执行 (Layer 1)
00:24:16 [STAGE] path_traversal_auditor    >>> RUNNING  ─┘

00:24:16 [taint_analyzer] split into 6 groups (size=10, max_concurrent=3)
00:24:16 [taint_analyzer] group 1 starting — 10 routes  ─┐
00:24:16 [taint_analyzer] group 2 starting — 10 routes   ├─ 前 3 组并行
00:24:16 [taint_analyzer] group 3 starting — 10 routes  ─┘
00:25:25 [STAGE] auth_auditor              >>> SUCCESS      (3 findings)
00:25:42 [taint_analyzer] group 4 starting — 10 routes     ← Semaphore 释放
00:25:44 [STAGE] hardcoded_auditor         >>> SUCCESS      (4 findings)
00:26:58 [taint_analyzer] group 5 starting — 10 routes
00:27:03 [taint_analyzer] group 6 starting — 7 routes
00:30:18 [STAGE] path_traversal_auditor    >>> SUCCESS
00:31:03 [STAGE] taint_analyzer            >>> SUCCESS      (0 findings)

00:31:03 [STAGE] vuln_verifier             >>> RUNNING
00:31:40 [STAGE] vuln_verifier             >>> SUCCESS      (7 verifications)

00:31:40 [STAGE] report_generator          >>> RUNNING
00:31:40 [STAGE] report_generator          >>> SUCCESS

00:31:40 [INFO] Pipeline finished in ~793s — 7 success, 0 failed, 0 skipped
```

> taint_analyzer 对 SparkJava 返回 0 findings 是正确的 — SparkJava 本身是一个 Web 框架库，不包含 SQL/RCE/XXE/SSRF 的应用层 Sink。taint_analyzer 的价值在于扫描使用数据库、命令执行或 XML 解析的应用代码时。

### 扫描结果总览

| 指标 | 数值 |
|------|------|
| 发现路由数 | 57 |
| 总发现数 | 7 |
| 确认漏洞 | 7 |
| 误报 | 0 |
| 总耗时 | ~793 秒 |

#### 严重性分布

| 严重性 | 数量 |
|--------|------|
| High | 2 |
| Medium | 4 |
| Low | 1 |

#### 漏洞类型分布

| 类型 | 数量 |
|------|------|
| auth_bypass | 3 |
| hardcoded | 4 |

### 发现详情

#### AUTH-001 [High] — Book API 缺少认证

- **文件**: `Books.java:44`
- **问题**: `/books` 的 POST/GET/PUT/DELETE 端点未配置任何认证过滤器

#### AUTH-002 [Medium] — 工具端点缺少认证

- **文件**: `GenericIntegrationTest.java:150`
- **问题**: `/ip`、`/session_reset`、`/throwexception` 等端点公开可访问，无认证保护

#### AUTH-003 [High] — 路由认证保护不一致

- **文件**: `GenericIntegrationTest.java:79`
- **问题**: `/protected/*` 和 `/secretcontent/*` 有认证过滤器，但 `/hi`、`/binaryhi` 等路由未保护

#### HC-001~004 — 硬编码凭据

| ID | 严重性 | 文件 | 内容 |
|----|--------|------|------|
| HC-001 | Medium | SparkTestUtil.java:277 | 默认 keystore 密码 `password` |
| HC-002 | Medium | FilterExample.java:51 | 硬编码认证凭据 `foo/bar`, `admin/admin` |
| HC-003 | Medium | ServiceTest.java:184 | SSL 凭据 `keypassword`, `truststorepassword` |
| HC-004 | Low | README.md:245 | 示例 URL 中的凭据 |

### 输出文件

扫描完成后在输出目录 `/tmp/spark-audit-v6/` 生成以下文件：

| 文件 | 说明 |
|------|------|
| `security-audit-report.md` | 完整 Markdown 审计报告 |
| `report.json` | 结构化 JSON 报告（含所有数据） |
| `routes.json` | 提取的路由列表 (57 条) |
| `findings.json` | 所有发现 (7 条) |
| `verified.json` | 验证结果 (7 条，全部 confirmed) |
| `verifications.json` | 详细验证过程 |
| `taint-findings.json` | 污点分析发现 (本次为空) |
