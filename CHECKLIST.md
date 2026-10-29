# 交付前核对清单

核对日期：2026-10-29　范围：本仓库全部文件（4 个项目、文档、合规声明）

## 1. 代码可运行性

| 检查项 | 结果 | 说明 |
| --- | --- | --- |
| report-lint 单元测试 | 通过 | 9 个用例全绿，覆盖分级、结构、编号、声明 |
| sec-tools-mcp 单元测试 | 通过 | 15 个用例全绿，覆盖范围校验、字典预估、表单解析、tamper 容差 |
| 依赖声明 | 通过 | report-lint 仅 `python-docx` 必需，PDF 支持为可选；sec-tools-mcp 零三方依赖 |
| 命令行入口 | 通过 | `python -m report_lint.cli` 与 `python -m sec_tools_mcp.server` 均可直接启动 |

## 2. MCP 协议

| 检查项 | 结果 | 说明 |
| --- | --- | --- |
| initialize 握手 | 通过 | 两个 server 均返回 protocolVersion、capabilities、serverInfo |
| tools/list | 通过 | report-lint 3 个、sec-tools-mcp 4 个，schema 完整 |
| tools/call | 通过 | report-lint 实测脱敏报告返回 0 命中；sec-tools 对公网目标返回范围错误 |
| 通知与错误处理 | 通过 | 无 id 的通知不回包；未知方法返回 -32601；工具异常不导致进程退出 |
| 日志通道 | 通过 | 日志写 stderr，stdout 仅协议消息 |

## 3. 脱敏与合规

| 检查项 | 结果 | 说明 |
| --- | --- | --- |
| 全仓库 high 项 | 通过 | 0 项（扫描 35 个文件） |
| medium 项 | 通过（需知悉） | 26 项，全部为保留网段与回环地址（10.0.0.0/8、192.168.x、127.0.0.1），属合规占位 |
| 真实报告是否入库 | 通过 | 未提交任何原始报告、截图、抓包、扫描结果 |
| 测试数据 | 通过 | 假邮箱、假手机号、假密钥均在运行时拼接，源码无字面量 |
| 工具名提及 | 通过 | 仅检测规则与红线说明中出现，无工具本体、无安装包 |
| 授权声明 | 通过 | README、LEGAL.md、两个子 README 均有边界说明 |

## 4. 文档一致性

| 检查项 | 结果 | 说明 |
| --- | --- | --- |
| README 目录树 ↔ 实际文件 | 通过 | 逐级核对，无死链 |
| 测试数量表述 | 通过 | README 写 8+15，实际为 9+15，已按实测更正为 24 |
| 工具数量表述 | 通过 | 3 + 4，与 `TOOLS` 常量一致 |
| LEGAL ↔ README ↔ 各子 README | 通过 | 均声明「只读、默认拒绝、不做爆破执行」 |
| 项目落地状态 | 通过 | `docs/01` 逐项标注实现与差异，未完成项已写明 |

## 5. 命名与结构

| 检查项 | 结果 | 说明 |
| --- | --- | --- |
| Skill 命名 | 通过 | 小写连字符，与目录名一致，≤64 字符 |
| Skill frontmatter | 通过 | 含 name/description/domain/subdomain/tags/version/author/license/agent_created |
| description 四要素 | 通过 | 做什么、何时触发、关键词、不用于什么，四个都有 |
| MCP 包名 | 通过 | `report-lint` / `sec-tools-mcp`，与 import 名 `report_lint` / `sec_tools_mcp` 对应 |
| 目录层级 | 通过 | skills/ 与 mcp/ 两类分开，各项目自包含 |

## 6. 已知差异与遗留

| 项 | 状态 | 说明 |
| --- | --- | --- |
| lab-pdf-digest 的模板抽取脚本 | 未实现 | 只交付 SKILL.md 与方法文档；自动识别可跳过的分节页需要按批次材料调参，暂不做 |
| MCP 官方 SDK | 未使用 | 环境装不上 `mcp` 包，改为手写 stdio JSON-RPC。已兼容 initialize 与 server/discover 两种入口 |
| form_analyze 依赖 | 有调整 | 原计划用 requests + BeautifulSoup，改为标准库 urllib + html.parser，保持零依赖 |
| GitHub 历史 | 需注意 | 若后续误提交敏感内容，普通 commit 无法彻底清除，需改写历史；因此提交前必须跑扫描 |

复检结论：24 个测试通过，7 个 MCP 工具可用，high 项 0，文档与实现一致，未完成项已标注。
