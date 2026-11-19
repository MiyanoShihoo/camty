"""真实工具本地 E2E：httpx 探活 → nuclei 验证 → sqli-probe 注入（工具缺失时自动跳过）。

用真实二进制（E:\AI tools 里的 httpx/nuclei）打本地靶机，校准适配器解析与全链状态流转。
"""

from __future__ import annotations

import http.server
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import yaml

from camty.adapters.registry import REGISTRY
from camty.agent.runner import DeterministicRunner
from camty.agent.state import Engagement
from camty.tools import find_tool

PACK = {
    "name": "e2e-local",
    "title": "E2E 本地链",
    "phases": [
        {
            "id": "probe",
            "title": "存活探测",
            "steps": [{"adapter": "httpx", "args": {"hosts": "{targets}"}}],
        },
        {
            "id": "verify",
            "title": "已知漏洞验证",
            "steps": [{"adapter": "nuclei", "args": {"hosts": "{live_hosts}", "tags": "exposure"}}],
        },
        {
            "id": "inject",
            "title": "注入探测",
            "steps": [{"adapter": "sqli-probe", "args": {"targets": "{sqli_targets}", "delay": 0.05}}],
        },
        {
            "id": "exploit",
            "title": "注入利用",
            "gate": {"min_verified_findings": 1, "require_context": ["sqli_targets"]},
            "steps": [{"adapter": "sqli-exploit", "args": {"targets": "{sqli_targets}", "delay": 0.05}}],
        },
    ],
}

CFG = {
    "name": "e2e-eng",
    "pack": "e2e-local",
    "scope": {"ips": ["127.0.0.1"], "min_interval_seconds": 0},
    "auto_confirm": True,  # 本地靶机
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if parsed.path == "/vuln":
            q = qs.get("q", "")
            if "EXTRACTVALUE" in q:
                for fn, val in (("version()", "8.0.36-camty"),
                                ("user()", "root@localhost"),
                                ("database()", "target_db")):
                    if fn in q:
                        body, status = f"XPATH syntax error: '~{val}'", 500
                        break
                else:
                    body, status = "error", 500
            elif "'" in q:
                body, status = "You have an error in your SQL syntax near '' at line 1", 500
            else:
                body, status = "normal results page", 200
        elif parsed.path == "/extract":
            q = qs.get("q", "")
            if "EXTRACTVALUE" in q:
                for fn, val in (("version()", "8.0.36-camty"),
                                ("user()", "root@localhost"),
                                ("database()", "target_db")):
                    if fn in q:
                        body, status = f"XPATH syntax error: '~{val}'", 500
                        break
                else:
                    body, status = "error", 500
            else:
                body, status = "normal", 200
        elif parsed.path == "/bool":
            value = qs.get("v", "")
            if "'1'='1" in value:
                body, status = "A" * 600, 200
            elif "'1'='2" in value:
                body, status = "B", 200
            else:
                body, status = "normal", 200
        else:
            body, status = "safe page", 200
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def _build_project(tmp: str) -> Path:
    root = Path(tmp)
    (root / "packs" / "e2e-local").mkdir(parents=True)
    (root / "packs" / "e2e-local" / "pack.yaml").write_text(yaml.safe_dump(PACK), encoding="utf-8")
    (root / "engagements").mkdir()
    cfg_path = root / "engagements" / "e2e.yaml"
    cfg_path.write_text(yaml.safe_dump(CFG), encoding="utf-8")
    return cfg_path


class TestRealToolE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_httpx_sqli_chain(self):
        # 区分 Python httpx CLI 与 ProjectDiscovery Go httpx：名字碰撞须烟测
        import subprocess as _sp

        binary = find_tool("httpx")
        if not binary:
            self.skipTest("httpx 未安装")
        probe = _sp.run([binary, "-version"], capture_output=True, text=True, timeout=15)
        if "projectdiscovery" not in (probe.stdout + probe.stderr).lower():
            self.skipTest(f"找到的 httpx 不是 ProjectDiscovery 工具（名字碰撞：Python httpx CLI）")
        tmp = tempfile.TemporaryDirectory()
        eng = None
        try:
            eng = Engagement(_build_project(tmp.name))
            eng.context["targets"] = [f"http://127.0.0.1:{self.port}"]
            eng.context["sqli_targets"] = [f"http://127.0.0.1:{self.port}/vuln?q=test"]
            runner = DeterministicRunner(eng, REGISTRY)

            runner.run("probe")
            self.assertTrue(eng.context.get("live_hosts"), "真实 httpx 应探测到本地服务存活")
            self.assertTrue(any("127.0.0.1" in h for h in eng.context["live_hosts"]))

            runner.run("inject")
            templates = [f.detail for f in eng.ledger.findings]
            self.assertTrue(
                any("error-based" in t for t in templates),
                f"sqli-probe 应命中错误回显注入，台账: {templates}",
            )
            self.assertTrue(all(f.verified for f in eng.ledger.findings))
            ok, bad = eng.audit.verify()
            self.assertTrue(ok, "审计哈希链应完整")
        finally:
            if eng is not None:
                eng.close()
            tmp.cleanup()

    def test_nuclei_step(self):
        if not find_tool("nuclei"):
            self.skipTest("nuclei 未安装")
        tmp = tempfile.TemporaryDirectory()
        eng = None
        try:
            eng = Engagement(_build_project(tmp.name))
            eng.context["targets"] = [f"http://127.0.0.1:{self.port}"]
            runner = DeterministicRunner(eng, REGISTRY)
            runner.run("probe")
            runner.run("verify")
            adapters = [e["adapter"] for e in eng.audit.entries()]
            self.assertIn("nuclei", adapters, "nuclei 步骤应真实执行并留审计")
            evidence_files = list((eng.dir / "evidence").glob("*nuclei*"))
            self.assertTrue(evidence_files, "nuclei 原始输出应落证据文件")
        finally:
            if eng is not None:
                eng.close()
            tmp.cleanup()




class TestFullAutoExploitChain(unittest.TestCase):
    """全自动利用链验收：probe → 门控 → 注入验证 → 门控 → 数据提取 → 报告。"""

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_probe_gate_exploit_full_chain(self):
        if not find_tool("httpx"):
            self.skipTest("httpx 未安装")
        from camty.agent.orchestrator import Orchestrator

        tmp = tempfile.TemporaryDirectory()
        eng = None
        try:
            eng = Engagement(_build_project(tmp.name))
            eng.context["targets"] = [f"http://127.0.0.1:{self.port}"]
            eng.context["sqli_targets"] = [
                f"http://127.0.0.1:{self.port}/extract?q=test",
                f"http://127.0.0.1:{self.port}/vuln?q=test",
            ]
            ok = Orchestrator(eng, REGISTRY).run()
            self.assertTrue(ok, "全链应跑通（含门控）")

            details = [(f.detail, f.severity) for f in eng.ledger.findings]
            self.assertTrue(any("error-based" in d for d, _ in details), "注入验证应产出 finding")
            self.assertTrue(
                any("data-access" in d and s == "critical" for d, s in details),
                f"利用提取应产出 critical finding，台账: {details}",
            )
            self.assertTrue(eng.context.get("access_proof"), "提取成功应置 access_proof")
            extracted = eng.context.get("extracted", {})
            vuln_url = f"http://127.0.0.1:{self.port}/vuln?q=test"
            self.assertIn(vuln_url, extracted)
            self.assertEqual(extracted[vuln_url]["version"], "8.0.36-camty")
            self.assertEqual(extracted[vuln_url]["database"], "target_db")
            reports = list(eng.dir.glob("report-*.html"))
            self.assertTrue(reports, "全自动结束应出报告")
            ok_chain, _ = eng.audit.verify()
            self.assertTrue(ok_chain, "审计哈希链应完整")
        finally:
            if eng is not None:
                eng.close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
