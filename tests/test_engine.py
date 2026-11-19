"""引擎核心回归测试：护栏、存储、断点续跑、并发、确认流、工具解析。"""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qsl, urlparse

import yaml

from camty.adapters.base import ToolAdapter, ToolResult, RunContext
from camty.adapters.mock import MockConfirm, MockGated, MockHttpx, MockSleep, MockSubfinder
from camty.agent.runner import DeterministicRunner, _resolve_args
from camty.agent.state import Engagement, Ledger
from camty.guardrail.audit import Audit
from camty.guardrail.scope import Scope, ScopeError
from camty.tools import find_tool

PACK = {
    "name": "test-pack",
    "title": "测试包",
    "phases": [
        {"id": "p1", "title": "链路", "steps": [
            {"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"}},
            {"adapter": "mock-httpx", "args": {"hosts": "{subdomains}"}},
        ]},
        {"id": "p2", "title": "并发", "steps": [
            {"parallel": [
                {"adapter": "mock-sleep", "args": {"seconds": 0.6}},
                {"adapter": "mock-sleep", "args": {"seconds": 0.6}},
            ]},
        ]},
        {"id": "p3", "title": "确认", "steps": [
            {"adapter": "mock-confirm", "confirm": True},
            {"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"}},
        ]},
        {"id": "p4", "title": "利用级门控", "steps": [
            {"adapter": "mock-gated"},
        ]},
    ],
}

CFG = {
    "name": "unit-test-eng",
    "pack": "test-pack",
    "root_domain": "example.com",
    "scope": {"domains": ["example.com"], "ips": ["127.0.0.1"], "min_interval_seconds": 0},
}


class TempProjectMixin:
    def setUp(self) -> None:
        self._engs: list = []
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "packs" / "test-pack").mkdir(parents=True)
        (root / "packs" / "test-pack" / "pack.yaml").write_text(
            yaml.safe_dump(PACK), encoding="utf-8"
        )
        (root / "engagements").mkdir()
        cfg_path = root / "engagements" / "unit-test-eng.yaml"
        cfg_path.write_text(yaml.safe_dump(CFG), encoding="utf-8")
        self.cfg_path = cfg_path

    def tearDown(self) -> None:
        for eng in self._engs:
            try:
                eng.close()
            except Exception:  # noqa: BLE001 - 清理阶段尽力而为
                pass
        self.tmp.cleanup()

    def make_eng(self):
        from camty.agent.state import Engagement

        eng = Engagement(self.cfg_path)
        self._engs.append(eng)
        return eng


class CountingSubfinder(MockSubfinder):
    calls = 0

    def run(self, args, ctx):
        type(self).calls += 1
        return super().run(args, ctx)


def build_registry():
    return {
        "mock-subfinder": CountingSubfinder(),
        "mock-httpx": MockHttpx(),
        "mock-sleep": MockSleep(),
        "mock-confirm": MockConfirm(),
        "mock-gated": MockGated(),
    }


class TestScope(unittest.TestCase):
    def test_allowed_cases(self):
        s = Scope({"domains": ["example.com"], "cidrs": ["192.168.100.0/24"], "min_interval_seconds": 0})
        s.require("www.example.com")
        s.require("EXAMPLE.COM")
        s.require("192.168.100.5")

    def test_out_of_scope_ip_blocked(self):
        s = Scope({"cidrs": ["192.168.100.0/24"], "min_interval_seconds": 0})
        with self.assertRaises(ScopeError):
            s.require("192.168.200.5")

    def test_suffix_spoof_blocked(self):
        s = Scope({"domains": ["example.com"], "min_interval_seconds": 0})
        fake_info = [(2, 1, 6, "", ("93.184.216.34", 0))]
        with mock.patch("camty.guardrail.scope.socket.getaddrinfo", return_value=fake_info):
            with self.assertRaises(ScopeError):
                s.require("sub.example.com.evil.net")

    def test_cidr_subset_check(self):
        s = Scope({"cidrs": ["10.0.0.0/8"], "min_interval_seconds": 0})
        s.require_cidr("10.1.2.0/24")
        with self.assertRaises(ScopeError):
            s.require_cidr("192.168.1.0/24")


class TestAudit(unittest.TestCase):
    def test_jsonl_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Audit(Path(tmp) / "a.jsonl")
            audit.record("t", {"x": 1}, ok=True, note="n")
            audit.record("t2", {}, ok=False)
            entries = audit.entries()
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0]["adapter"], "t")
            self.assertFalse(entries[1]["ok"])


class TestResolveArgs(unittest.TestCase):
    def test_full_ref(self):
        self.assertEqual(_resolve_args({"hosts": "{subdomains}"}, {"subdomains": [1, 2]}), {"hosts": [1, 2]})

    def test_format(self):
        self.assertEqual(_resolve_args({"q": "id={page}"}, {"page": 3}), {"q": "id=3"})

    def test_missing_var(self):
        with self.assertRaises(RuntimeError):
            _resolve_args({"hosts": "{nope}"}, {})


class TestRunnerFlow(TempProjectMixin, unittest.TestCase):
    def test_chain_context_and_ledger(self):
        eng = self.make_eng()
        DeterministicRunner(eng, build_registry()).run("p1")
        self.assertEqual(eng.context["subdomains"], ["www.example.com", "api.example.com", "mail.example.com"])
        self.assertTrue(eng.context["live_hosts"])

    def test_resume_skips_done_steps(self):
        eng = self.make_eng()
        runner = DeterministicRunner(eng, build_registry())
        CountingSubfinder.calls = 0
        runner.run("p1")
        self.assertEqual(CountingSubfinder.calls, 1)
        runner.run("p1")  # 断点续跑：全部跳过
        self.assertEqual(CountingSubfinder.calls, 1)

    def test_rerun_clears_progress(self):
        eng = self.make_eng()
        runner = DeterministicRunner(eng, build_registry())
        CountingSubfinder.calls = 0
        runner.run("p1")
        runner.run("p1", rerun=True)
        self.assertEqual(CountingSubfinder.calls, 2)

    def test_parallel_concurrency(self):
        eng = self.make_eng()
        runner = DeterministicRunner(eng, build_registry())
        start = time.monotonic()
        runner.run("p2")
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.0, "两个 0.6s 步骤应并发执行（串行需 >1.2s）")

    def test_confirm_accept_and_reject(self):
        eng = self.make_eng()
        registry = build_registry()
        CountingSubfinder.calls = 0
        runner = DeterministicRunner(eng, registry)
        with mock.patch("builtins.input", return_value="y"):
            runner.run("p3")
        self.assertEqual(CountingSubfinder.calls, 1)
        eng2 = self.make_eng()
        CountingSubfinder.calls = 0
        runner2 = DeterministicRunner(eng2, build_registry())
        with mock.patch("builtins.input", return_value="n"):
            runner2.run("p3", rerun=True)
        self.assertEqual(CountingSubfinder.calls, 0, "operator 拒绝后不应执行任何步骤")

    def test_auto_confirm_flag(self):
        eng = self.make_eng()
        eng.cfg["auto_confirm"] = True
        CountingSubfinder.calls = 0
        with mock.patch("builtins.input", side_effect=AssertionError("不应弹出确认")):
            DeterministicRunner(eng, build_registry()).run("p3")
        self.assertEqual(CountingSubfinder.calls, 1)


class TestEngagementState(TempProjectMixin, unittest.TestCase):
    def test_ledger_persist(self):
        eng = self.make_eng()
        eng.ledger.add("vuln", "https://x", "test-detail", severity="high", verified=True)
        eng.save_state()
        reloaded = self.make_eng()
        self.assertEqual(len(reloaded.ledger.findings), 1)
        self.assertEqual(reloaded.ledger.findings[0].detail, "test-detail")
        self.assertTrue(reloaded.ledger.findings[0].verified)


class TestToolResolution(unittest.TestCase):
    def test_find_tool_in_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            subdir = Path(tmp) / "faketool"
            subdir.mkdir()
            exe = subdir / ("faketool.exe" if __import__("os").name == "nt" else "faketool")
            exe.write_text("#!/bin/sh\n", encoding="utf-8")
            with mock.patch.dict("os.environ", {"CAMTY_TOOLS_DIR": tmp}):
                self.assertEqual(Path(find_tool("faketool")).name, exe.name)

    def test_missing_tool(self):
        self.assertIsNone(find_tool("definitely-not-a-real-tool-xyz"))


if __name__ == "__main__":
    unittest.main()


class TestFindingGate(TempProjectMixin, unittest.TestCase):
    def test_gate_function(self):
        from camty.agent.runner import _gate_finding

        ledger = Ledger()
        fid = ledger.add("vuln", "https://x", "d", verified=True)
        adapter = MockGated()
        self.assertIsNone(_gate_finding(adapter, {"finding_id": fid}, ledger))
        self.assertIn("门控拒绝", _gate_finding(adapter, {}, ledger))
        self.assertIn("门控拒绝", _gate_finding(adapter, {"finding_id": "F-999"}, ledger))
        self.assertIsNone(_gate_finding(MockSubfinder(), {}, ledger))  # 非利用级不受限

    def test_deterministic_abort_without_finding(self):
        eng = self.make_eng()
        DeterministicRunner(eng, build_registry()).run("p4")
        self.assertEqual(eng.completed_steps("p4"), {}, "无证据时不应标记完成")
        self.assertNotIn("gated", eng.context)

    def test_deterministic_autofill(self):
        eng = self.make_eng()
        eng.ledger.add("vuln", "192.168.100.10", "kerberoastable-spn", severity="high", verified=True)
        eng.save_state()
        DeterministicRunner(eng, build_registry()).run("p4")
        self.assertEqual(eng.context.get("gated"), "F-001", "应自动引用最新 verified finding")
        self.assertEqual(eng.completed_steps("p4"), {0: "done"})

    def test_agent_gate_end_to_end(self):
        from camty.agent.runner import AgentRunner
        from camty.llm.router import ROLE_DECIDE

        class _FakeRouter:
            def __init__(self, responses):
                self.responses = list(responses)

            def chat(self, role, messages, tools=None):
                assert role == ROLE_DECIDE
                return self.responses.pop(0)

        eng = self.make_eng()
        eng.ledger.add("vuln", "192.168.100.10", "valid-credential", severity="high", verified=True)
        responses = [
            {"content": "", "tool_calls": [{"id": "c1", "name": "mock-gated", "arguments": {}}]},
            {"content": "", "tool_calls": [{"id": "c2", "name": "mock-gated", "arguments": {"finding_id": "F-999"}}]},
            {"content": "", "tool_calls": [{"id": "c3", "name": "mock-gated", "arguments": {"finding_id": "F-001"}}]},
            {"content": "阶段完成", "tool_calls": []},
        ]
        AgentRunner(eng, _FakeRouter(responses), build_registry()).run("p4")
        self.assertEqual(eng.context.get("gated"), "F-001", "合法 finding_id 才放行")
        notes = [e.get("note", "") for e in eng.audit.entries()]
        self.assertEqual(sum(1 for n in notes if "finding-gate" in n), 2, "前两次应被门控拒绝并留痕")
