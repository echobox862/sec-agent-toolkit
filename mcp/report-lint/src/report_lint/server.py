"""MCP server：零依赖的 stdio 实现。

协议按 JSON-RPC 2.0 逐行传输（MCP stdio transport 的约定）。
同时支持 initialize 握手与 2026-07-28 的 server/discover，方便不同客户端接入。
日志一律写 stderr，stdout 只留给协议。
"""
from __future__ import annotations

import json
import sys
import traceback

from . import __version__
from .extract import ExtractError, load
from .rules import check_claims, lint, scan_sensitive

SERVER_NAME = "report-lint"

TOOLS = [
    {
        "name": "lint_report",
        "description": (
            "检查一份渗透测试报告：22 类结构维度是否齐全、VULN 编号是否连续、"
            "有无未脱敏信息、对外声明能否在报告中找到对应。"
            "支持 .docx / .pdf / .md。只读，不修改文件。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "报告文件的绝对路径"},
                "claims": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "需要核对的声明，例如「22 个风险点」「9 类」",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_sensitive",
        "description": "只扫敏感信息：IP、域名、邮箱、手机号、密钥、绝对路径，按 high/medium 分级。",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "文件绝对路径"}},
            "required": ["path"],
        },
    },
    {
        "name": "check_claims",
        "description": "核对一组对外声明是否能在报告正文中找到对应表述。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "claims": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["path", "claims"],
        },
    },
]


def _text_result(payload: object, is_error: bool = False) -> dict:
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _call_tool(name: str, args: dict) -> dict:
    path = args.get("path")
    if not path:
        return _text_result("缺少参数 path", True)
    try:
        doc = load(path)
    except ExtractError as exc:
        return _text_result(f"[{exc.code}] {exc}。建议：{exc.hint}", True)

    if name == "lint_report":
        result = lint(doc, args.get("claims") or [])
        return _text_result(result, result["verdict"] == "fail")
    if name == "scan_sensitive":
        hits = scan_sensitive(doc)
        high = [h for h in hits if h["severity"] == "high"]
        return _text_result({"counts": {"high": len(high), "total": len(hits)}, "hits": hits}, bool(high))
    if name == "check_claims":
        return _text_result(check_claims(doc, args.get("claims") or []))
    return _text_result(f"未知工具：{name}", True)


def handle(message: dict) -> dict | None:
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}

    # 通知不带 id，不回包
    if msg_id is None:
        return None

    if method == "initialize":
        client_version = params.get("protocolVersion") or "2024-11-05"
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": client_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": __version__},
            },
        }

    if method == "server/discover":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "serverInfo": {"name": SERVER_NAME, "version": __version__},
                "protocolVersions": ["2026-07-28", "2025-11-25", "2024-11-05"],
                "capabilities": {"tools": {}},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            return {"jsonrpc": "2.0", "id": msg_id, "result": _call_tool(name, args)}
        except Exception as exc:  # 工具内部异常不外抛，避免整个 server 退出
            print(traceback.format_exc(), file=sys.stderr)
            return {"jsonrpc": "2.0", "id": msg_id, "result": _text_result(f"工具执行失败：{exc}", True)}

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main() -> int:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            print(f"invalid json: {line[:120]}", file=sys.stderr)
            continue
        response = handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
