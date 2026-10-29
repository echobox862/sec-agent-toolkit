#!/usr/bin/env python3
"""发布前红线检查：扫一篇 markdown 笔记里的敏感信息与越界内容。

零依赖，直接跑：

    python scripts/check_redlines.py writeups/01-file-upload.md

退出码：0 无 high；1 有 high；2 参数或读取错误。
只做文本匹配，不联网，不上传，不改文件。
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

HIGH: list[tuple[str, re.Pattern]] = [
    ("邮箱", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("手机号", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Windows 绝对路径", re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|]{2,}")),
    ("Unix 用户目录", re.compile(r"(?<![\w.])/(?:home|root|Users)/[^\s\"'<>|]{1,}")),
    ("脚本文件内容", re.compile(r"<\?php|eval\s*\(\s*\$_(?:POST|GET|REQUEST)")),
    ("命令执行调用", re.compile(r"\b(?:system|exec|shell_exec|passthru)\s*\(\s*\$_(?:POST|GET|REQUEST)")),
]

MEDIUM: list[tuple[str, re.Pattern]] = [
    # 负向后行断言：跳过邮箱里 @ 后面的域名，避免一次泄露报两条
    ("域名", re.compile(
        r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|cn|net|org|io|top|xyz|cc|info|biz|me|dev|app)\b",
        re.IGNORECASE,
    )),
]

INFO: list[tuple[str, re.Pattern]] = [
    ("webshell 工具名", re.compile(r"菜刀|蚁剑|冰蝎|哥斯拉|Behinder|Godzilla")),
    ("真实靶场平台名", re.compile(r"云演|i春秋|攻防世界|BUUCTF")),
]

ALLOW_DOMAIN = {"example.com", "example.org", "example.net", "localhost"}
# RFC 5737 文档专用地址，示例里出现是合规写法
DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def scan(text: str) -> list[dict]:
    hits: list[dict] = []
    lines = text.splitlines()

    for lineno, line in enumerate(lines, 1):
        for match in IPV4.finditer(line):
            try:
                ip = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if any(ip in net for net in DOC_NETS):
                continue
            severity = "medium" if (ip.is_private or ip.is_loopback) else "high"
            hits.append({"severity": severity, "type": "IP 地址", "line": lineno, "value": match.group(0)})

        for label, pattern in HIGH:
            for match in pattern.finditer(line):
                hits.append({"severity": "high", "type": label, "line": lineno, "value": match.group(0)})

        for label, pattern in MEDIUM:
            for match in pattern.finditer(line):
                if match.group(0).lower() in ALLOW_DOMAIN:
                    continue
                hits.append({"severity": "medium", "type": label, "line": lineno, "value": match.group(0)})

        for label, pattern in INFO:
            for match in pattern.finditer(line):
                hits.append({"severity": "info", "type": label, "line": lineno, "value": match.group(0)})

    if "授权" not in text:
        hits.append({"severity": "info", "type": "缺少授权说明", "line": 0, "value": "文中未见「授权」字样"})
    return hits


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("用法：python check_redlines.py <笔记.md>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    if not path.exists():
        print(f"文件不存在：{path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    hits = scan(text)

    order = {"high": 0, "medium": 1, "info": 2}
    for hit in sorted(hits, key=lambda h: (order[h["severity"]], h["line"])):
        location = f"第 {hit['line']} 行" if hit["line"] else "全文"
        print(f"[{hit['severity']}] {location} {hit['type']}：{hit['value']}")

    high = sum(1 for h in hits if h["severity"] == "high")
    if not hits:
        print("未发现问题")
    print(f"\n合计：high {high} / 共 {len(hits)} 项", file=sys.stderr)
    return 1 if high else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
