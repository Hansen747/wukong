# Wukong (悟空) — DAG-based Code Vulnerability Scanner

Wukong 是一个基于 DAG（有向无环图）调度的代码安全审计工具，结合 LLM Agent 的语义理解能力与传统静态分析工具 Pecker 的污点追踪能力，实现对 Java/Go/Python 项目的自动化漏洞扫描。

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
        ┌───────────────────┼───────────────────────────┐
        ▼                   ▼                           ▼
   LLM Agent          Pecker (subprocess)         Template Renderer
  (AuditAgent)        (pecker_scanner)           (report_generator)
        │
   ┌────┴────┐
   │ToolRegistry │  ←── read_file / glob_files / grep_content / write_file
   └─────────┘
```

### DAG 执行流程

```
Layer 0:  route_mapper                         (提取 HTTP 路由)
              │
              ├─────────────┬──────────────┬─────────────────────┐
              ▼             ▼              ▼                     ▼
Layer 1:  auth_auditor  pecker_scanner  hardcoded_auditor  path_traversal_auditor
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
│   │   ├── registry.py           # ToolRegistry — 管理 Agent 可调用的工具
│   │   ├── file_tools.py         # read_file, glob_files, grep_content, write_file, append_file
│   │   └── bash_tools.py         # run_command (shell 执行)
│   ├── pipeline/
│   │   ├── stage.py              # Stage 数据类
│   │   └── dag.py                # DAGScheduler — Kahn 拓扑排序 + asyncio.gather
│   └── agents/
│       ├── registry.py           # AgentRegistry + @register_agent 装饰器
│       ├── base.py               # AuditAgent — 双 Provider 流式工具调用循环
│       ├── route_mapper.py       # Layer 0: HTTP 路由提取
│       ├── auth_auditor.py       # Layer 1: 认证/授权漏洞审计
│       ├── hardcoded_auditor.py  # Layer 1: 硬编码密钥/凭据检测
│       ├── path_traversal_auditor.py  # Layer 1: 路径穿越漏洞检测
│       ├── pecker_scanner.py     # Layer 1: Pecker 污点分析 (subprocess)
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
| `pecker_path` | Pecker 工具路径 | 空 (不启用) |
| `output_dir` | 输出目录 | `/tmp/{project}-audit` |
| `max_concurrent_agents` | 同层最大并发数 | 3 |
| `agent_max_turns` | 每个 Agent 最大对话轮次 | 0 (不限) |
| `agent_timeout` | 每个 Agent 超时 (秒) | 0 (使用 Agent 默认值) |

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

`AuditAgent` 驱动 LLM 的流式工具调用循环，支持两种 Provider：

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

### 4. ToolRegistry

管理 Agent 可调用的工具集，以 Anthropic tool 格式存储，运行时自动转换为 OpenAI 格式：

| 工具 | 说明 |
|------|------|
| `read_file(path, offset, limit)` | 读取文件，返回带行号的内容 |
| `glob_files(pattern, path)` | 递归文件模式匹配，最多 200 条 |
| `grep_content(pattern, path, file_type)` | 正则搜索文件内容，最多 500 条 |
| `write_file(path, content)` | 写入文件 |
| `append_file(path, content)` | 追加文件 |
| `run_command(command)` | 执行 shell 命令 (仅 scanner agent) |

### 5. DAGScheduler

基于 Kahn 拓扑排序算法的调度器：

1. 将所有 Stage 按依赖关系拓扑排序，分成多个 Layer
2. 同一 Layer 内的 Stage 通过 `asyncio.gather` 并行执行
3. 每个 Stage 执行时收集上游依赖的输出作为输入
4. 上游失败则下游自动跳过
5. 支持 per-stage 超时（`asyncio.wait_for`）

### 6. Pecker 集成

Pecker 作为外部子进程调用（非 Python import），支持两种入口：

- **entry.py 模式**: `python3 entry.py --input input.json --output output.json`
- **main.py 模式**: 通过完整 CLI 参数调用

Pecker 输出的 `re_judge_result == "False"` 的结果（Pecker 自判误报）会被自动过滤。

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

### pecker_scanner (Layer 1)

调用 Pecker 静态分析工具进行污点追踪。

- 通过子进程调用 Pecker
- 转换 Pecker 的 VulnDetail 为统一的 Finding 格式
- 过滤 Pecker 自判的误报
- 输出: `{"findings": [Finding...]}`

### vuln_verifier (Layer 2)

独立验证上游所有 Agent 的发现。

- 合并上游 4 个 Agent 的 findings
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

# 启用 Pecker 扫描器
python -m code_audit /path/to/project \
  --pecker-path /path/to/pecker-3.0-out \
  -o /tmp/output -v
```

### CLI 参数

| 参数 | 说明 |
|------|------|
| `project_path` | 待审计项目根路径 |
| `-o, --output-dir` | 输出目录 |
| `--provider` | `anthropic` 或 `openai` |
| `-m, --model` | 模型名称 |
| `--api-key` | API 密钥 |
| `--base-url` | API 端点 URL |
| `--pecker-path` | Pecker 工具路径（省略则跳过 Pecker） |
| `--max-turns` | 每个 Agent 最大对话轮次 |
| `--timeout` | 每个 Agent 超时秒数 |
| `--max-concurrent` | 同层最大并发 Agent 数 |
| `-v, --verbose` | 启用 DEBUG 日志 |

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
  -o /tmp/spark-audit-v2 -v
```

### 执行过程

Pipeline 共 6 个 Stage，按 DAG 拓扑序执行（Pecker 因未配置路径而跳过）：

```
20:06:10 [INFO] Wukong (悟空) Code Audit
20:06:10 [INFO] Project:  .../project_for_detect/spark
20:06:10 [INFO] Provider: openai (qwen-plus via 阿里云百炼)
20:06:10 [INFO] Pecker:   (disabled)
20:06:10 [INFO] Skipped agents (not configured): pecker_scanner
20:06:10 [INFO] Starting pipeline with 6 stages

20:06:10 [STAGE] route_mapper         >>> RUNNING
20:07:28 [STAGE] route_mapper         >>> SUCCESS      (70 routes, 78s)

20:07:28 [STAGE] auth_auditor         >>> RUNNING  ─┐
20:07:28 [STAGE] hardcoded_auditor    >>> RUNNING   ├─ 并行执行
20:07:28 [STAGE] path_traversal_auditor >>> RUNNING ─┘

20:09:45 [STAGE] auth_auditor         >>> SUCCESS      (3 findings)
20:10:12 [STAGE] hardcoded_auditor    >>> SUCCESS      (4 findings)
20:10:30 [STAGE] path_traversal_auditor >>> SUCCESS    (3 findings)

20:10:30 [STAGE] vuln_verifier        >>> RUNNING
20:13:39 [STAGE] vuln_verifier        >>> SUCCESS      (10 verifications)

20:13:39 [STAGE] report_generator     >>> RUNNING
20:13:39 [STAGE] report_generator     >>> SUCCESS

20:13:39 [INFO] Pipeline finished in 448.5s — 6 success, 0 failed, 0 skipped
```

### 扫描结果总览

| 指标 | 数值 |
|------|------|
| 发现路由数 | 70 |
| 总发现数 | 10 |
| 确认漏洞 | 10 |
| 误报 | 0 |
| 总耗时 | 448.5 秒 |

#### 严重性分布

| 严重性 | 数量 |
|--------|------|
| Critical | 1 |
| High | 3 |
| Medium | 6 |

#### 漏洞类型分布

| 类型 | 数量 |
|------|------|
| path_traversal | 3 |
| auth_bypass | 3 |
| hardcoded | 4 |

### 发现详情

#### PT-001 [Critical] — CVE-2018-9159 路径穿越

这是本次扫描的核心目标漏洞，被 `path_traversal_auditor` 成功检出。

- **文件**: `spark/staticfiles/DirectoryTraversal.java:19`
- **Source**: HTTP 请求 URI 路径
- **Sink**: `new File(file.getPath())` (ExternalResourceHandler)
- **调用链**:
  1. `ExternalResourceHandler.getResource(String path)` — 接收用户请求路径
  2. `DirectoryTraversal.protectAgainstForExternal(String path)` — 尝试检测路径穿越

**漏洞原理**: `DirectoryTraversal.protectAgainstForExternal()` 使用 `Paths.get(path).toAbsolutePath()` 对路径进行规范化，然后检查结果是否以配置的静态文件目录开头。但 URL 编码的穿越序列（如 `%2e%2e%2f` 即 `../`）在安全检查之后才被解码，导致防护被绕过。

**漏洞代码**:
```java
public static void protectAgainstForExternal(String path) {
    String nixLikePath = Paths.get(path).toAbsolutePath()
                              .toString().replace("\\", "/");
    if (!removeLeadingAndTrailingSlashesFrom(nixLikePath)
            .startsWith(StaticFilesFolder.external())) {
        throw new DirectoryTraversalDetection("external");
    }
}
```

**POC**:
```http
GET /static/..%2f..%2f..%2fetc/passwd HTTP/1.1
Host: target:4567
```

**验证结果**: vuln_verifier 独立确认 — _"Verified: DirectoryTraversal.java uses Paths.get(path).toAbsolutePath() after URL decoding, making it vulnerable to CVE-2018-9159 encoded path traversal attacks."_

**修复建议**: 升级至 SparkJava 2.7.2 或更高版本。若无法升级，在安全检查前先进行 URL 解码和路径规范化，并采用白名单方式限制可访问的文件扩展名。

#### PT-002 [High] — UriPath.canonical() 路径规范化不足

- **文件**: `spark/resource/UriPath.java:32`
- **问题**: `UriPath.canonical()` 方法仅处理字面量的 `.` 和 `..`，不处理 URL 编码变体（`%2e`、`%2e%2e`）
- **POC**: `GET /static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd`

#### PT-003 [Medium] — 外部静态文件路径配置缺少验证

- **文件**: `spark/staticfiles/StaticFilesConfiguration.java:161`
- **问题**: `configureExternal(String folder)` 接受任意文件夹路径，未验证是否在安全范围内

#### AUTH-001 [High] — Book API 缺少认证

- **文件**: `Books.java:44`
- **问题**: `/books` 的 POST/GET/PUT/DELETE 端点未配置任何认证过滤器

#### AUTH-002 [Medium] — 测试端点暴露

- **文件**: `GenericIntegrationTest.java:91`
- **问题**: `/hi`、`/hello`、`/throwexception` 等测试端点无认证保护

#### AUTH-003 [High] — 端点保护不一致

- **文件**: `GenericIntegrationTest.java:79`
- **问题**: `/protected/*` 和 `/secretcontent/*` 有认证过滤器，但功能相似的 `/books/*` 没有

#### HC-001~004 [Medium] — 硬编码凭据

| ID | 文件 | 内容 |
|----|------|------|
| HC-001 | FilterExample.java:51 | 硬编码认证凭据 `foo/bar`, `admin/admin` |
| HC-002 | SparkTestUtil.java:277 | 默认 keystore 密码 `password` |
| HC-003 | ServiceTest.java:184 | SSL 凭据 `keypassword`, `truststorepassword` |
| HC-004 | SocketConnectorFactoryTest.java:108 | SSL 凭据 `keystorePassword`, `trustStorePassword` |

### 输出文件

扫描完成后在输出目录 `/tmp/spark-audit-v2/` 生成以下文件：

| 文件 | 说明 |
|------|------|
| `security-audit-report.md` | 完整 Markdown 审计报告 |
| `report.json` | 结构化 JSON 报告（含所有数据） |
| `routes.json` | 提取的路由列表 (70 条) |
| `findings.json` | 所有发现 (10 条) |
| `verified.json` | 验证结果 (10 条，全部 confirmed) |
