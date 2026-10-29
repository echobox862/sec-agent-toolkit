# sec-tools-mcp

把四个自研安全工具接进 AI 客户端：端口扫描、字典生成、表单解析、tamper 语义验证。

零第三方依赖，只用标准库。

## 设计边界：不做爆破执行

仓库里没有「拿字典跑登录」这个工具。不是没写完，是刻意不做。

工具一旦能自己跑字典，误用的成本不可控；仓库一旦被当成开箱即用的爆破器，性质就变了。执行留在人工确认之后，这里只做发现、生成、解析、验证四件只读的事。

同样的理由，`port_scan` 默认只允许回环与私有网段。要测公网资产，必须显式传 `allow_external=true`，并由调用方自己确认授权。

## 安装

```bash
cd mcp/sec-tools-mcp
pip install -e .
```

无外部依赖。

## 接到 MCP 客户端

```json
{
  "mcpServers": {
    "sec-tools": {
      "command": "python",
      "args": ["-m", "sec_tools_mcp.server"],
      "env": { "PYTHONPATH": "<仓库路径>/mcp/sec-tools-mcp/src" }
    }
  }
}
```

## 四个工具

### port_scan

TCP 全连接扫描。用 `connect_ex` 而不是 `connect`：前者返回错误码、不抛异常，批量扫描时不用给每次尝试套 `try/except`。

```json
{"host": "127.0.0.1", "ports": "22,80,8000-8010", "timeout": 1.0, "workers": 100}
```

只做全连接，不做 SYN。原始套接字要管理员权限，跨平台行为也不一致，学习收益不抵成本。短超时可能把慢响应端口判成关闭，返回值里带了这条说明。

### dict_generate

按「基础词 × 连接符 × 年份 × 数字」生成候选，先算总量再生成。

```json
{"bases": ["admin", "test"], "seps": ["", "_"], "years": ["2024"], "tails": ["", "1"]}
```

预计 8 条。超过 `limit`（默认 10 万）会返回 `E_OVER_LIMIT` 并给出预估，确认后才用 `force=true`。不加这道闸，几个参数一配就能把磁盘写满。

结果去重，返回条数受 `max_return` 限制。

### form_analyze

读取登录页，解析全部 input 字段，包括 hidden token。

```json
{"url": "http://127.0.0.1/login"}
```

返回用户名候选、密码候选、隐藏字段、是否带 CSRF token。自适应解析的意义是不写死字段名——不同系统的用户名框可能叫 `user`、`username`、`login`。

只发一次 GET，不提交任何凭据。遇到验证码不猜，直接说明超出范围。

### tamper_verify

对比 raw 基线与各变体的响应长度，判断 tamper 有没有破坏 SQL 语义。

```json
{"baseline_length": 5120, "variants": [{"name": "double_keywords", "length": 5200}]}
```

基线为 0 时直接报 `E_EMPTY_BASELINE`，提示先确认注入点可用——这是原实现里踩过的坑：基线没建立时，所有变体都会被判失败，排查方向会被带偏。

只比对长度，不发包。

## 测试

```bash
PYTHONPATH=src python -m unittest discover -s tests -t . -v
```

15 个用例：公网拒绝、回环放行、端口表达式解析、字典预估与超限、表单字段识别、基线为零、容差内外判定。不依赖外部网络与靶场。

## 和 sec-tools-lab 的关系

逻辑来自同一批工具（需求分析、边界条件、取舍理由都在那边），这一版重写为可安装的包，并剥掉了所有会主动发包的执行路径。两边的取舍结论一致：不引入 asyncio（I/O 密集型任务，线程够用）、一切网络操作显式设超时、报告前先脱敏。

## 局限

- 端口扫描只有全连接一种模式，没有服务指纹识别。
- 字典生成不内置任何真实字典，示例最多几条演示词。
- 表单解析不处理 JS 渲染页面，也不识别验证码。
