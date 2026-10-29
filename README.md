# sec-agent-toolkit · 安全智能体工具箱

四个面向安全日常工作的 Skill 与 MCP。都能离线跑，默认只读，不主动发包。

做的不是「工具数量」，是四件反复发生的事：写笔记、交报告、做发现、读材料。

## 目录

```
sec-agent-toolkit/
├── README.md
├── LEGAL.md                    合规声明与使用边界
├── CHECKLIST.md                交付前核对记录
├── skills/
│   ├── web-vuln-writeup/       靶场笔记写作（SKILL.md + 框架 + 红线 + 模板 + 检查脚本）
│   └── lab-pdf-digest/         讲义精讲（SKILL.md + 方法）
├── mcp/
│   ├── report-lint/            报告自检 MCP（3 个工具）
│   └── sec-tools-mcp/          安全工具 MCP（4 个工具）
└── docs/
    ├── 01-项目清单与落地状态.md
    └── 02-脱敏与合规说明.md
```

## 四个项目

| 项目 | 形态 | 解决什么 | 入口 |
| --- | --- | --- | --- |
| web-vuln-writeup | Agent Skill | 笔记写成流水账、结构每次重搭、发布前踩红线 | `skills/web-vuln-writeup/SKILL.md` |
| lab-pdf-digest | Agent Skill | 几百页培训材料读不完、过时结论照背 | `skills/lab-pdf-digest/SKILL.md` |
| report-lint | MCP Server | 报告结构缺失、敏感信息漏脱、对外口径与实物对不上 | `mcp/report-lint/` |
| sec-tools-mcp | MCP Server | 自研工具只能在终端跑，结果要手工贴回对话 | `mcp/sec-tools-mcp/` |

## 快速开始

```bash
# 1. 报告自检（不需要 AI 客户端）
cd mcp/report-lint && pip install -e .
report-lint lint <你的报告.docx>

# 2. 跑测试
PYTHONPATH=src python -m unittest discover -s tests -t . -v

# 3. 起 MCP server（stdio）
PYTHONPATH=src python -m report_lint.server
PYTHONPATH=../sec-tools-mcp/src python -m sec_tools_mcp.server
```

客户端的 `mcpServers` 配置写法见各子目录 README。

Skill 的用法：把 `skills/<name>/` 整个目录放进客户端的 skills 目录，或直接引用 `SKILL.md`。

## 设计原则

**只读优先。** report-lint 只解析不修改；sec-tools-mcp 只做发现、生成、解析、验证，不发利用载荷。四个工具里没有一个是「拿字典跑登录」。

**默认拒绝。** 端口扫描默认只允许回环与私有网段，测公网要显式放开。这个默认值决定了仓库的性质：是授权测试工具，不是扫描器。

**零依赖。** 两个 MCP 的协议层都是手写 stdio JSON-RPC，只用标准库。report-lint 读 docx 需要 `python-docx`，读 PDF 才需要 `pymupdf`，都列为可选。

**脱敏先于提交。** 示例、测试数据、README 里的目标信息全部用代号与保留网段。检查规则与结果见 `docs/02-脱敏与合规说明.md`。

## 验证记录

| 项 | 结果 |
| --- | --- |
| 单元测试 | report-lint 9 个、sec-tools-mcp 15 个，共 24 个通过 |
| MCP 协议 | 两个 server 的 `initialize` / `tools/list` / `tools/call` 均验证通过 |
| 越界拦截 | `port_scan` 对 `198.51.100.7`（RFC 5737 文档地址）默认拒绝，返回范围校验提示 |
| 报告实测 | 45 页、22 条发现的脱敏报告：结构 22/22，敏感信息 0 命中 |
| 红线脚本 | 模板零命中；含敏感信息的样例报出 4 项 high |
| 仓库脱敏 | 全文扫描无公网 IP、域名、邮箱、密钥、绝对路径 |

## 与 pentest-report-lab 的关系

那个仓库是一份完整的脱敏渗透测试报告，22 条发现、45 页、22 张重绘示意图。report-lint 拿它当验证样本：结构检查跑出 22/22，脱敏扫描 0 命中。

两个仓库分开：报告是交付物，工具是方法。混在一起，读者分不清哪个是展示、哪个是能力。

## 许可

MIT。见 [LEGAL.md](./LEGAL.md)。
