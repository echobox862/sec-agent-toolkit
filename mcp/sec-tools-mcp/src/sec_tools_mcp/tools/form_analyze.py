"""登录表单结构解析。

只发一次 GET，只读页面，不提交任何凭据。
自适应解析的意义在于不写死字段名：不同系统的用户名框可能叫 user、username、login，
隐藏字段里还可能带一次性 token。
"""
from __future__ import annotations

import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin

USER_AGENT = "sec-tools-mcp/1.0 (authorized-testing-only)"


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {key: (value or "") for key, value in attrs}
        if tag == "form":
            self._current = {
                "action": data.get("action", ""),
                "method": (data.get("method") or "get").lower(),
                "fields": [],
            }
            self.forms.append(self._current)
        elif tag == "input" and self._current is not None:
            self._current["fields"].append(
                {
                    "name": data.get("name", ""),
                    "type": (data.get("type") or "text").lower(),
                    "value": data.get("value", ""),
                    "hidden": (data.get("type") or "").lower() == "hidden",
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def parse_form(html: str, base_url: str = "") -> dict:
    parser = _FormParser()
    parser.feed(html)
    forms = []
    for form in parser.forms:
        action = urljoin(base_url, form["action"]) if base_url else form["action"]
        username = [
            f["name"] for f in form["fields"] if f["type"] in {"text", "email", "tel"}
        ]
        password = [f["name"] for f in form["fields"] if f["type"] == "password"]
        hidden = [f["name"] for f in form["fields"] if f["hidden"]]
        forms.append(
            {
                "action": action,
                "method": form["method"],
                "field_count": len(form["fields"]),
                "username_candidates": username,
                "password_candidates": password,
                "hidden_fields": hidden,
                "has_csrf_token": any("token" in name.lower() for name in hidden),
                "fields": form["fields"],
            }
        )
    return {"forms": forms, "count": len(forms)}


def fetch(url: str, timeout: float = 5.0, max_bytes: int = 512_000) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - 仅授权环境
        raw = response.read(max_bytes)
        charset = response.headers.get_content_charset() or "utf-8"
        html = raw.decode(charset, errors="replace")
    return {"status": response.status, "url": response.geturl(), "html": html}


def analyze(url: str, timeout: float = 5.0) -> dict:
    page = fetch(url, timeout=timeout)
    parsed = parse_form(page["html"], page["url"])
    parsed.update({"status": page["status"], "url": page["url"]})
    parsed["note"] = "仅读取页面结构，未提交任何凭据。"
    return parsed
