"""命令行入口：不接 AI 客户端也能直接跑。

    python -m report_lint.cli lint 报告.docx
    python -m report_lint.cli lint 报告.docx --claims "22 个风险点" "9 类" --json
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .extract import ExtractError, load
from .rules import lint, scan_sensitive


def _print_human(result: dict) -> None:
    print(f"文件：{result['file']}（{result['kind']}）")
    print(f"结论：{result['verdict'].upper()}")
    findings = result["findings"]
    print(f"漏洞条目：{findings['count']} 条，编号 {findings['numbering'].get('range', '-')}")
    print(f"结构完整：{findings['structure_complete']}/{findings['count']}")
    for item in findings["incomplete"]:
        print(f"  - VULN-{item['number']:02d} 缺：{'、'.join(item['missing'])}")

    counts = result["sensitive"]["counts"]
    print(f"敏感信息：high {counts['high']} / medium {counts['medium']}")
    for level in ("high", "medium"):
        for hit in result["sensitive"][level][:10]:
            print(f"  [{level}] 第 {hit['line']} 行 {hit['type']}：{hit['value']}")

    for claim in result["claims"]:
        mark = "OK" if claim["found"] else "冲突"
        print(f"声明「{claim['claim']}」：{mark}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="report-lint", description="渗透测试报告交付前自检")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_lint = sub.add_parser("lint", help="完整检查")
    p_lint.add_argument("path")
    p_lint.add_argument("--claims", nargs="*", default=[], help="需要核对的对外声明")
    p_lint.add_argument("--json", action="store_true", help="输出 JSON")

    p_scan = sub.add_parser("scan", help="只扫敏感信息")
    p_scan.add_argument("path")
    p_scan.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    try:
        doc = load(args.path)
    except ExtractError as exc:
        print(f"[{exc.code}] {exc}", file=sys.stderr)
        if exc.hint:
            print(f"建议：{exc.hint}", file=sys.stderr)
        return 2

    if args.command == "lint":
        result = lint(doc, args.claims)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            _print_human(result)
        return 0 if result["verdict"] == "pass" else 1

    hits = scan_sensitive(doc)
    if args.json:
        print(json.dumps(hits, ensure_ascii=False, indent=2))
    else:
        if not hits:
            print("未发现敏感信息")
        for hit in hits:
            print(f"[{hit['severity']}] 第 {hit['line']} 行 {hit['type']}：{hit['value']}")
    return 0 if not any(h["severity"] == "high" for h in hits) else 1


if __name__ == "__main__":
    raise SystemExit(main())
