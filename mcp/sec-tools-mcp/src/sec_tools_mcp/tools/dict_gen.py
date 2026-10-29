"""字典生成：模板规则引擎 + 总量预估。

先算总量再生成。不加这道闸，`--seps a,b,c` 配几个年份就能把磁盘写满。
这是资料里明确要求的防爆设计。
"""
from __future__ import annotations

import itertools

DEFAULT_LIMIT = 100_000


def plan(
    bases: list[str],
    seps: list[str] | None = None,
    years: list[str] | None = None,
    tails: list[str] | None = None,
) -> int:
    seps = seps or [""]
    years = years or [""]
    tails = tails or [""]
    if not bases:
        raise ValueError("bases 不能为空")
    return len(bases) * len(seps) * len(years) * len(tails)


def generate(
    bases: list[str],
    seps: list[str] | None = None,
    years: list[str] | None = None,
    tails: list[str] | None = None,
    limit: int = DEFAULT_LIMIT,
    force: bool = False,
    max_return: int = 2000,
) -> dict:
    seps = seps or [""]
    years = years or [""]
    tails = tails or [""]
    total = plan(bases, seps, years, tails)

    if total > limit and not force:
        return {
            "ok": False,
            "error": "E_OVER_LIMIT",
            "estimated": total,
            "limit": limit,
            "hint": f"预计生成 {total} 条，超过上限 {limit}。确认后传 force=true。",
            "words": [],
        }

    words: list[str] = []
    seen: set[str] = set()
    for base, sep, year, tail in itertools.product(bases, seps, years, tails):
        word = f"{base}{sep}{year}{tail}"
        if word and word not in seen:
            seen.add(word)
            words.append(word)
            if len(words) >= max_return:
                break

    return {
        "ok": True,
        "estimated": total,
        "returned": len(words),
        "truncated": len(words) < total,
        "words": words,
        "note": "结果已去重；返回条数受 max_return 限制，完整列表请用 CLI 落盘。",
    }
