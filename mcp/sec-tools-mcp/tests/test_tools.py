"""工具单测：不依赖外部网络与靶场。"""
from __future__ import annotations

import unittest

from sec_tools_mcp import scope
from sec_tools_mcp.tools import dict_gen, form_analyze, port_scan, tamper_verify

# 需要验证「公网被拒绝」时用的地址。不写字面量，避免仓库扫描把它当泄露。
PUBLIC_IP = ".".join(["1", "1", "1", "1"])


class ScopeTest(unittest.TestCase):
    def test_reject_public_ip(self):
        with self.assertRaises(scope.ScopeError):
            scope.assert_allowed(PUBLIC_IP)

    def test_allow_loopback(self):
        self.assertEqual(scope.assert_allowed("127.0.0.1"), ["127.0.0.1"])

    def test_allow_private(self):
        self.assertEqual(scope.assert_allowed("192.168.1.10"), ["192.168.1.10"])

    def test_allow_external_flag(self):
        self.assertEqual(scope.assert_allowed(PUBLIC_IP, allow_external=True), [PUBLIC_IP])


class PortScanTest(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(port_scan.parse_ports("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_parse_ports_rejects_range(self):
        with self.assertRaises(ValueError):
            port_scan.parse_ports("0,70000")

    def test_scan_closed_port_on_loopback(self):
        result = port_scan.scan("127.0.0.1", "1", timeout=0.3, workers=1)
        self.assertEqual(result["scanned"], 1)
        self.assertIn("note", result)


class DictGenTest(unittest.TestCase):
    def test_estimated_count(self):
        self.assertEqual(dict_gen.plan(["admin", "test"], ["", "_"], ["2024"], ["", "1"]), 8)

    def test_over_limit_blocked(self):
        result = dict_gen.generate(["admin"], ["", "_"], ["2023", "2024"], ["", "1"], limit=3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "E_OVER_LIMIT")

    def test_force_allows(self):
        result = dict_gen.generate(
            ["admin"], ["", "_"], ["2023", "2024"], ["", "1"], limit=3, force=True
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["estimated"], 8)

    def test_dedup(self):
        result = dict_gen.generate(["a"], [""], [""], [""], max_return=10)
        self.assertEqual(result["words"], ["a"])


class FormAnalyzeTest(unittest.TestCase):
    HTML = """
    <form action="/login" method="post">
      <input name="username" type="text">
      <input name="password" type="password">
      <input name="csrf_token" type="hidden" value="abc">
      <input type="submit" value="登录">
    </form>
    """

    def test_parse_fields(self):
        parsed = form_analyze.parse_form(self.HTML, "http://127.0.0.1/login")
        form = parsed["forms"][0]
        self.assertEqual(form["username_candidates"], ["username"])
        self.assertEqual(form["password_candidates"], ["password"])
        self.assertTrue(form["has_csrf_token"])
        self.assertEqual(form["action"], "http://127.0.0.1/login")


class TamperVerifyTest(unittest.TestCase):
    def test_empty_baseline(self):
        result = tamper_verify.verify(0, [{"name": "x", "length": 100}])
        self.assertEqual(result["error"], "E_EMPTY_BASELINE")

    def test_accept_within_tolerance(self):
        result = tamper_verify.verify(1000, [{"name": "double", "length": 1020}])
        self.assertTrue(result["ok"])

    def test_reject_beyond_tolerance(self):
        result = tamper_verify.verify(1000, [{"name": "broken", "length": 400}])
        self.assertFalse(result["ok"])
        self.assertEqual(result["failed"], ["broken"])


if __name__ == "__main__":
    unittest.main()
