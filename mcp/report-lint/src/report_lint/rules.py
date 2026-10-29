"""规则引擎：结构、编号、脱敏、声明一致性。

所有规则只读文本，不改文件。规则命中都带位置（字符偏移）与命中片段，
方便回到原文核对。
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .extract import Document

# ---------------------------------------------------------------- 结构规则

# 四个维度用同义词组匹配。报告里字段名可能叫「修复建议」也可能叫「整改建议」，
# 不能只认一种写法。
DIMENSIONS: dict[str, list[str]] = {
    "复现步骤": ["复现步骤", "复现过程", "复现路径"],
    "影响": ["影响", "危害", "业务影响"],
    "风险等级": ["风险等级", "CVSS", "等级"],
    "修复建议": ["修复建议", "整改建议", "修复方案", "加固建议"],
}

_VULN_HEADING = re.compile(r"VULN[-\s]?(\d{1,3})")


@dataclass
class Finding:
    number: int
    title: str
    start: int
    missing: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.missing


def split_findings(doc: Document) -> list[Finding]:
    """按 VULN 标题切分正文，得到每一条的覆盖范围。

    只认标题，不认表格里的编号——风险矩阵表会先列出全部编号，
    用全文首次出现定位会导致所有条目挤在表格区。
    """
    marks: list[tuple[int, str]] = []
    for heading in doc.headings:
        match = _VULN_HEADING.search(heading["title"])
        if match:
            marks.append((int(match.group(1)), heading["title"]))

    if not marks:
        # PDF 或纯文本没有标题层级时，退化为按行首编号识别
        for line in doc.text.splitlines():
            bare = line.strip()
            if re.match(r"^\d+(\.\d+)*\s*VULN", bare):
                match = _VULN_HEADING.search(bare)
                if match:
                    marks.append((int(match.group(1)), bare))

    dedup: dict[int, str] = {}
    for number, title in marks:
        dedup.setdefault(number, title)

    positions: dict[int, int] = {}
    cursor = 0
    for number in sorted(dedup):
        idx = doc.text.find(dedup[number], cursor)
        if idx < 0:
            idx = doc.text.find(dedup[number])
        if idx >= 0:
            positions[number] = idx
            cursor = idx + 1

    ordered = sorted(positions.items(), key=lambda kv: kv[1])
    findings: list[Finding] = []
    for i, (number, start) in enumerate(ordered):
        end = ordered[i + 1][1] if i + 1 < len(ordered) else len(doc.text)
        body = doc.text[start:end]
        missing = [
            name
            for name, keywords in DIMENSIONS.items()
            if not any(kw in body for kw in keywords)
        ]
        findings.append(Finding(number, dedup[number], start, missing))
    return findings


def check_numbering(findings: list[Finding]) -> dict:
    numbers = sorted(f.number for f in findings)
    if not numbers:
        return {"ok": False, "count": 0, "gaps": [], "duplicates": []}
    expected = list(range(numbers[0], numbers[0] + len(numbers)))
    return {
        "ok": numbers == expected,
        "count": len(numbers),
        "range": f"VULN-{numbers[0]:02d} ~ VULN-{numbers[-1]:02d}",
        "gaps": [n for n in expected if n not in numbers],
        "duplicates": sorted({n for n in numbers if numbers.count(n) > 1}),
    }


# ---------------------------------------------------------------- 脱敏规则

_DOMAIN_ALLOW = {"example.com", "example.org", "example.net", "localhost"}
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|cn|net|org|io|top|xyz|cc|info|biz|me|dev|app)\b",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_SECRETS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("OpenAI/通用 sk-", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]
_PATHS = [
    ("Windows 绝对路径", re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|]{2,}")),
    ("Unix 用户目录", re.compile(r"(?<![\w.])/(?:home|root|Users)/[^\s\"'<>|]{1,}")),
]


# RFC 5737 文档专用地址，出现在示例里是合规写法，不算泄露
_DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def is_documentation_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip in net for net in _DOC_NETS)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(text: str, start: int, end: int, pad: int = 30) -> str:
    left = max(0, start - pad)
    right = min(len(text), end + pad)
    return text[left:right].replace("\n", " ").strip()


def scan_sensitive(doc: Document) -> list[dict]:
    hits: list[dict] = []
    text = doc.text

    for match in _IPV4.finditer(text):
        raw = match.group(0)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if is_documentation_ip(ip):
            continue
        severity = "medium" if (ip.is_private or ip.is_loopback) else "high"
        hits.append(
            {
                "type": "IP 地址",
                "severity": severity,
                "value": raw,
                "line": _line_of(text, match.start()),
                "snippet": _snippet(text, match.start(), match.end()),
                "suggestion": "替换为 TARGET-A / 10.0.0.0 等保留代号",
            }
        )

    for match in _DOMAIN.finditer(text):
        raw = match.group(0).lower()
        if raw in _DOMAIN_ALLOW or raw.endswith(".example.com"):
            continue
        hits.append(
            {
                "type": "域名",
                "severity": "high",
                "value": raw,
                "line": _line_of(text, match.start()),
                "snippet": _snippet(text, match.start(), match.end()),
                "suggestion": "替换为 TARGET-A 或 example.com",
            }
        )

    for label, pattern in [("邮箱", _EMAIL), ("手机号", _PHONE), *_SECRETS]:
        for match in pattern.finditer(text):
            hits.append(
                {
                    "type": label,
                    "severity": "high",
                    "value": match.group(0),
                    "line": _line_of(text, match.start()),
                    "snippet": _snippet(text, match.start(), match.end()),
                    "suggestion": "删除或替换为占位符",
                }
            )

    for label, pattern in _PATHS:
        for match in pattern.finditer(text):
            hits.append(
                {
                    "type": label,
                    "severity": "medium",
                    "value": match.group(0),
                    "line": _line_of(text, match.start()),
                    "snippet": _snippet(text, match.start(), match.end()),
                    "suggestion": "改为相对路径或 <安装目录>",
                }
            )

    return hits


# ---------------------------------------------------------------- 声明一致性


def check_claims(doc: Document, claims: list[str]) -> list[dict]:
    results = []
    for claim in claims:
        found = claim in doc.text
        results.append(
            {
                "claim": claim,
                "found": found,
                "status": "ok" if found else "conflict",
                "hint": "" if found else "报告中找不到该表述，需修改文案或补充报告",
            }
        )
    return results


# ---------------------------------------------------------------- 汇总


def lint(doc: Document, claims: list[str] | None = None) -> dict:
    findings = split_findings(doc)
    numbering = check_numbering(findings)
    sensitive = scan_sensitive(doc)
    claims_result = check_claims(doc, claims or [])

    high = [h for h in sensitive if h["severity"] == "high"]
    medium = [h for h in sensitive if h["severity"] == "medium"]
    incomplete = [
        {"number": f.number, "title": f.title, "missing": f.missing}
        for f in findings
        if not f.complete
    ]
    conflicts = [c for c in claims_result if c["status"] == "conflict"]

    if high or incomplete or conflicts or not numbering["ok"]:
        verdict = "fail"
    elif medium:
        verdict = "warn"
    else:
        verdict = "pass"

    return {
        "file": doc.path,
        "kind": doc.kind,
        "pages": doc.pages,
        "verdict": verdict,
        "findings": {
            "count": len(findings),
            "numbering": numbering,
            "structure_complete": len(findings) - len(incomplete),
            "incomplete": incomplete,
        },
        "sensitive": {
            "high": high,
            "medium": medium,
            "counts": {"high": len(high), "medium": len(medium)},
        },
        "claims": claims_result,
    }
