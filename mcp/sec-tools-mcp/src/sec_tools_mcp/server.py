"""MCP server：零依赖 stdio 实现，暴露四个只读工具。

日志写 stderr，stdout 只走协议。不做爆破执行，不发利用载荷。
"""
from __future__ import annotations

import json
import sys
import traceback

from . import __version__
from .scope import ScopeError
from .tools import dict_gen, form_analyze, port_scan, tamper_verify

SERVER_NAME = "sec-tools-mcp"

TOOLS = [
    {
        "name": "port_scan",
        "description": (
            "TCP 全连接扫描指定主机的端口，返回开放端口与耗时。"
            "默认只允许回环与私有网段；测公网需显式 allow_external=true。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "主机名或 IP"},
                "ports": {"type": "string", "description": "端口表达式，如 22,80,8000-8010"},
                "timeout": {"type": "number", "default": 1.0},
                "workers": {"type": "integer", "default": 100, "maximum": 200},
                "allow_external": {"type": "boolean", "default": False},
            },
            "required": ["host"],
        },
    },
    {
        "name": "dict_generate",
        "description": (
            "按「基础词 × 连接符 × 年份 × 数字」生成候选字典，先返回总量预估。"
            "超过 limit 会拒绝，需显式 force=true。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "bases": {"type": "array", "items": {"type": "string"}},
                "seps": {"type": "array", "items": {"type": "string"}},
                "years": {"type": "array", "items": {"type": "string"}},
                "tails": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "default": 100000},
                "force": {"type": "boolean", "default": False},
                "max_return": {"type": "integer", "default": 2000},
            },
            "required": ["bases"],
        },
    },
    {
        "name": "form_analyze",
        "description": "读取登录页，解析全部 input 字段（含 hidden token），返回表单结构。只读，不提交。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "timeout": {"type": "number", "default": 5.0},
            },
            "required": ["url"],
        },
    },
    {
        "name": "tamper_verify",
        "description": (
            "对比 raw 基线与 tamper 变体的响应长度，判断变体有没有破坏 SQL 语义。"
            "只做比较，不发包。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "baseline_length": {"type": "integer"},
                "variants": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "length": {"type": "integer"},
                            "status": {"type": "integer"},
                        },
                        "required": ["name", "length"],
                    },
                },
                "tolerance": {"type": "number", "default": 0.05},
            },
            "required": ["baseline_length", "variants"],
        },
    },
]


def _result(payload: object, is_error: bool = False) -> dict:
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _call_tool(name: str, args: dict) -> dict:
    try:
        if name == "port_scan":
            data = port_scan.scan(
                host=args["host"],
                ports=args.get("ports", "22,80,443"),
                timeout=float(args.get("timeout", 1.0)),
                workers=int(args.get("workers", 100)),
                allow_external=bool(args.get("allow_external", False)),
            )
            return _result(data)
        if name == "dict_generate":
            data = dict_gen.generate(
                bases=args["bases"],
                seps=args.get("seps"),
                years=args.get("years"),
                tails=args.get("tails"),
                limit=int(args.get("limit", dict_gen.DEFAULT_LIMIT)),
                force=bool(args.get("force", False)),
                max_return=int(args.get("max_return", 2000)),
            )
            return _result(data, not data.get("ok", False))
        if name == "form_analyze":
            return _result(form_analyze.analyze(args["url"], float(args.get("timeout", 5.0))))
        if name == "tamper_verify":
            data = tamper_verify.verify(
                int(args["baseline_length"]),
                args["variants"],
                float(args.get("tolerance", 0.05)),
            )
            return _result(data, not data.get("ok", False))
    except ScopeError as exc:
        return _result(f"目标范围校验未通过：{exc}", True)
    except KeyError as exc:
        return _result(f"缺少必填参数：{exc}", True)
    except Exception as exc:
        print(traceback.format_exc(), file=sys.stderr)
        return _result(f"工具执行失败：{exc}", True)
    return _result(f"未知工具：{name}", True)


def handle(message: dict) -> dict | None:
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}
    if msg_id is None:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": params.get("protocolVersion") or "2024-11-05",
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
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": _call_tool(params.get("name", ""), params.get("arguments") or {}),
        }
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
