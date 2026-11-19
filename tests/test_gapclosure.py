"""缺口闭环测试：cve-intel 解析 / hashcrack 识别 / osint mock / SRC 报告 / multi 并行。"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from camty.adapters.hashcrack import detect_mode
from camty.agent.state import Engagement
from camty.modules import cve_intel
from camty.report import write_src_md


def make_eng(tmp: str, findings=None) -> Engagement:
    pack = {"name": "gc", "title": "t", "phases": [], "plan": []}
    root = Path(tmp)
    (root / "packs" / "gc").mkdir(parents=True, exist_ok=True)
    (root / "packs" / "gc" / "pack.yaml").write_text(
        yaml.safe_dump(pack), encoding="utf-8")
    (root / "engagements").mkdir(exist_ok=True)
    path = root / "engagements" / "gc-eng.yaml"
    path.write_text(yaml.safe_dump({
        "name": "gc-eng", "pack": "gc", "root_domain": "example.com",
        "scope": {"domains": ["example.com"], "min_interval_seconds": 0},
        "auto_confirm": True}), encoding="utf-8")
    eng = Engagement(path)
    for f in findings or []:
        eng.ledger.add(**f)
    return eng


SAMPLE_ENTRY = {
    "containers": {
        "cna": {
            "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
            "descriptions": [{"lang": "en", "value": "RCE in test component"}],
            "affected": [{"versions": ["1.0", "1.2"]}],
        }
    }
}


class TestCveIntel(unittest.TestCase):
    def test_severity_parse(self):
        self.assertEqual(cve_intel._severity_of(SAMPLE_ENTRY), "critical")

    def test_severity_missing(self):
        self.assertEqual(cve_intel._severity_of({"containers": {"cna": {}}}), "unknown")

    def test_resolve(self):
        self.assertEqual(cve_intel._resolve("Nginx"), ("nginx", "nginx"))
        self.assertEqual(cve_intel._resolve("OpenSSH 9.6"), ("openbsd", "openssh"))
        self.assertIsNone(cve_intel._resolve("gin"))

    def test_query_mock(self):
        fake_body = json.dumps({"results": {"cvelistv5": [
            ["cve-2026-1234", SAMPLE_ENTRY]]}})
        with mock.patch("camty.modules.cve_intel.http_fp.fetch",
                        return_value=(fake_body, 200)):
            r = cve_intel.query_component("nginx")
        self.assertEqual(r["source"], "circl")
        self.assertEqual(r["cves"][0]["id"], "cve-2026-1234")
        self.assertEqual(r["cves"][0]["severity"], "critical")
        self.assertIn("RCE", r["cves"][0]["desc"])

    def test_query_unreachable(self):
        with mock.patch("camty.modules.cve_intel.http_fp.fetch",
                        return_value=None):
            r = cve_intel.query_component("nginx")
        self.assertEqual(r["source"], "unreachable")
        self.assertEqual(r["cves"], [])


class TestHashcrackDetect(unittest.TestCase):
    def test_jwt(self):
        mode, name = detect_mode(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgOryF-"
            "upWj2AU4EqYj9ZvUO2jO_sJ0XBgaBqPa0")
        self.assertEqual((mode, name), (16500, "jwt"))

    def test_hex32_defaults_md5(self):
        mode, name = detect_mode("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertEqual((mode, name), (0, "md5"))

    def test_kerberoast(self):
        mode, name = detect_mode("$krb5tgs$23$*user$realm$")
        self.assertEqual((mode, name), (13100, "kerberoast"))

    def test_bcrypt(self):
        mode, name = detect_mode("$2y$12$K4nKKnQmOnPzZbDbE0Rf9eOqZTrO0p")
        self.assertEqual((mode, name), (3200, "bcrypt"))

    def test_unknown(self):
        self.assertIsNone(detect_mode("not-a-hash"))


class TestOsint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_run_mock(self):
        from camty.adapters.osint import OsintAdapter

        rdap_body = json.dumps({"events": [
            {"eventAction": "registration", "eventDate": "2025-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}]})
        crt_body = json.dumps([{"name_value": "a.example.com\nwww.example.com"}])
        with (
            mock.patch("camty.adapters.osint._rdap",
                       return_value={"available": True, "registered": "2025-01-01"}),
            mock.patch("camty.adapters.osint._crtsh_subdomains",
                       return_value=["a.example.com", "www.example.com"]),
            mock.patch("camty.adapters.osint.socket.getaddrinfo",
                       return_value=[(0, 0, 0, "", ("93.184.216.34", 443))]),
        ):
            eng = make_eng(self.tmp)
            r = OsintAdapter().run({"domain": "example.com"}, eng.ctx)
        self.assertIn("2 个历史子域", r.summary)
        kinds = [a["kind"] for a in eng.assets.all()]
        self.assertIn("root_domain", kinds)
        self.assertEqual(kinds.count("subdomain"), 2)
        self.assertIn("93.184.216.34", r.data["ips"])


class TestSrcReport(unittest.TestCase):
    def test_write_src_md(self):
        tmp = tempfile.mkdtemp()
        eng = make_eng(tmp, findings=[
            {"kind": "vuln", "target": "https://example.com/api/x",
             "detail": "authz/idor 越权访问他人订单", "severity": "high",
             "verified": True},
            {"kind": "recon", "target": "example.com", "detail": "信息",
             "severity": "info"},
        ])
        out = write_src_md(eng)
        text = Path(out).read_text(encoding="utf-8")
        self.assertIn("[HIGH] authz/idor", text)
        self.assertIn("资源访问校验属主", text)  # 修复建议映射
        self.assertIn("已验证", text)


class TestMultiCmd(unittest.TestCase):
    def test_multi_parallel(self):
        tmp = tempfile.mkdtemp()
        root = Path(tmp)
        (root / "packs" / "mp").mkdir(parents=True)
        (root / "packs" / "mp" / "pack.yaml").write_text(yaml.safe_dump({
            "name": "mp", "title": "t", "phases": [
                {"id": "p1", "title": "探测", "steps": []}], "plan": []}),
            encoding="utf-8")
        (root / "engagements").mkdir()
        yamls = []
        for name in ("m1", "m2"):
            path = root / "engagements" / f"{name}.yaml"
            path.write_text(yaml.safe_dump({
                "name": name, "pack": "mp", "root_domain": "example.com",
                "scope": {"domains": ["example.com"], "min_interval_seconds": 0}}),
                encoding="utf-8")
            yamls.append(str(path))
        proc = subprocess.run(
            [sys.executable, "-m", "camty", "--no-banner", "multi", *yamls,
             "--dry-run"],
            capture_output=True, text=True, timeout=120, cwd=Path.cwd())
        self.assertIn("[multi] 成功 2", proc.stdout, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
