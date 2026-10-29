"""规则引擎单测。全部用合成文本，不引用任何真实目标数据。"""
from __future__ import annotations

import unittest

from report_lint.extract import Document
from report_lint.rules import check_claims, check_numbering, lint, scan_sensitive, split_findings

# 测试需要构造一个非保留段地址来验证 high 分支。源码里不写死字面量，
# 避免仓库自身的脱敏扫描把它当成泄露。
PUBLIC_IP = ".".join(["1", "1", "1", "1"])
DOC_IP = "198.51.100.7"


def make_doc(text: str, headings: list[dict] | None = None) -> Document:
    return Document(
        path="inline",
        kind="md",
        headings=headings or [],
        paragraphs=[ln for ln in text.splitlines() if ln.strip()],
        text=text,
    )


class SensitiveTest(unittest.TestCase):
    def test_public_and_private_ip(self):
        doc = make_doc(f"公网 {PUBLIC_IP}，内网 192.168.1.10，回环 127.0.0.1")
        hits = scan_sensitive(doc)
        by_value = {h["value"]: h["severity"] for h in hits}
        self.assertEqual(by_value[PUBLIC_IP], "high")
        self.assertEqual(by_value["192.168.1.10"], "medium")
        self.assertEqual(by_value["127.0.0.1"], "medium")

    def test_documentation_ip_ignored(self):
        doc = make_doc(f"示例地址 {DOC_IP} 属于 RFC 5737 文档段")
        self.assertEqual(scan_sensitive(doc), [])

    def test_email_phone_secret_path(self):
        # 测试数据在运行时拼接，源码里不出现可直接匹配的字面量。
        # 一是避免仓库自己的脱敏扫描误报，二是不给「复制粘贴就能用」的假凭据。
        email = "user" + "@" + "example.invalid"
        phone = "1" + "3800138000"
        key = "AKIA" + "ABCDEFGHIJKLMNOP"
        sep = chr(92)
        path = f"C:{sep}Users{sep}tester{sep}report.docx"
        doc = make_doc(f"联系 {email}，手机 {phone}，key {key}，路径 {path}")
        hits = scan_sensitive(doc)
        types = {h["type"] for h in hits}
        self.assertIn("邮箱", types)
        self.assertIn("手机号", types)
        self.assertIn("AWS Access Key", types)
        self.assertIn("Windows 绝对路径", types)
        self.assertTrue(all(h["severity"] == "high" for h in hits if h["type"] == "邮箱"))

    def test_allowlisted_domain(self):
        doc = make_doc("示例 example.com 与 localhost 不算泄露")
        self.assertEqual(scan_sensitive(doc), [])

    def test_masked_phone_not_flagged(self):
        doc = make_doc("手机号 138****8000（已脱敏）")
        self.assertEqual(scan_sensitive(doc), [])


class StructureTest(unittest.TestCase):
    TEXT = (
        "3.1.1 VULN-01 第一条\n"
        "影响：数据泄露\n"
        "复现步骤：1) 访问 2) 提交 3) 观察\n"
        "风险等级：高危（CVSS 8.8）\n"
        "修复建议：参数化查询\n"
        "3.1.2 VULN-02 第二条\n"
        "影响：越权\n"
        "复现步骤：1) 登录 2) 改 id 3) 查看\n"
        "风险等级：中危（CVSS 6.5）\n"
    )

    def test_missing_dimension_detected(self):
        headings = [
            {"level": 4, "title": "3.1.1 VULN-01 第一条"},
            {"level": 4, "title": "3.1.2 VULN-02 第二条"},
        ]
        findings = split_findings(make_doc(self.TEXT, headings))
        self.assertEqual(len(findings), 2)
        self.assertTrue(findings[0].complete)
        self.assertEqual(findings[1].missing, ["修复建议"])

    def test_numbering_gap(self):
        text = "VULN-01 甲\n内容\nVULN-03 丙\n内容\n"
        headings = [
            {"level": 4, "title": "VULN-01 甲"},
            {"level": 4, "title": "VULN-03 丙"},
        ]
        findings = split_findings(make_doc(text, headings))
        result = check_numbering(findings)
        self.assertFalse(result["ok"])
        self.assertEqual(result["gaps"], [2])

    def test_lint_verdict_fail_on_missing(self):
        headings = [
            {"level": 4, "title": "3.1.1 VULN-01 第一条"},
            {"level": 4, "title": "3.1.2 VULN-02 第二条"},
        ]
        result = lint(make_doc(self.TEXT, headings))
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["findings"]["structure_complete"], 1)


class ClaimsTest(unittest.TestCase):
    def test_conflict_when_absent(self):
        doc = make_doc("本次共发现 22 条问题，归为 8 类。")
        result = check_claims(doc, ["22 个风险点", "22 条"])
        status = {r["claim"]: r["status"] for r in result}
        self.assertEqual(status["22 个风险点"], "conflict")
        self.assertEqual(status["22 条"], "ok")


if __name__ == "__main__":
    unittest.main()
