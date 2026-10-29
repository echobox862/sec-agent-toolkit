"""tamper 语义验证。

判断一个 tamper 变体有没有破坏 SQL 语义：拿原始响应长度当基线，
变体长度落在容差内，说明数据库仍然接受了这个表达式。

这里只做比较，不发包。发包与 payload 构造留在人工环节，
避免仓库变成「一键打点」工具。
"""
from __future__ import annotations

DEFAULT_TOLERANCE = 0.05


def verify(
    baseline_length: int,
    variants: list[dict],
    tolerance: float = DEFAULT_TOLERANCE,
) -> dict:
    """baseline_length: 原始 payload 的响应长度。

    variants: [{"name": "double_keywords", "length": 5120, "status": 200}, ...]
    """
    if baseline_length <= 0:
        return {
            "ok": False,
            "error": "E_EMPTY_BASELINE",
            "hint": "raw 基线长度为 0，注入点可能不可用。先用恒真/恒假条件确认基线有差异。",
            "results": [],
        }

    results = []
    for item in variants:
        length = int(item.get("length", 0))
        drift = abs(length - baseline_length) / baseline_length
        results.append(
            {
                "name": item.get("name", "unnamed"),
                "length": length,
                "status": item.get("status"),
                "drift": round(drift, 4),
                "db_accepts": drift <= tolerance,
            }
        )

    failed = [r["name"] for r in results if not r["db_accepts"]]
    return {
        "ok": not failed,
        "baseline_length": baseline_length,
        "tolerance": tolerance,
        "results": results,
        "failed": failed,
        "note": "只做长度语义比对，不代表漏洞可利用性结论。",
    }
