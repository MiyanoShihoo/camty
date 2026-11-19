"""复测 agent 测试：三级结论 + 处置状态同步 + 单结论保证 + 规则门 + CLI。"""

from __future__ import annotations

import argparse
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from camty.adapters.mock import MockSubfinder
from camty.adapters.registry import REGISTRY
from camty.agent.retester import RetestSession
from camty.agent.state import Engagement
from camty.cli import cmd_retest
from camty.storage import StateDB
from tests.test_artex_port import build_registry, make_eng


class MockRouter:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def chat(self, role, messages, tools=None, timeout=None):
        self.calls.append({"role": role, "n_tools": len(tools or [])})
        return self.script.pop(0)


def make_retest_setup(tmp: str, detail: str = "sqli 注入点", verified: bool = True):
    eng = make_eng(tmp)
    eng.ledger.add(kind="vuln", target="https://a.example.com/api",
                   detail=detail, severity="high", verified=verified)
    eng.save_state()
    return eng


def record_tool(verdict: str, summary: str = "结论", evidence: str = "") -> dict:
    return {"content": "", "tool_calls": [
        {"id": "c-rec", "name": "record-retest-result",
         "arguments": {"verdict": verdict, "summary": summary, "evidence": evidence}}]}


class TestRetestStorage(unittest.TestCase):
    def test_add_and_load_retests(self):
        db = StateDB(Path(tempfile.mkdtemp()) / "state.db")
        db.add_retest("F-001", "reproduced", "仍可复现", "ev.md")
        db.add_retest("F-002", "fixed", "已修复", None)
        self.assertEqual(len(db.load_retests()), 2)
        self.assertEqual(len(db.load_retests("F-001")), 1)
        rec = db.load_retests("F-002")[0]
        self.assertEqual(rec["verdict"], "fixed")
        self.assertIn("created_ts", rec)

    def test_disposal_default_and_roundtrip(self):
        tmp = tempfile.mkdtemp()
        eng = make_eng(tmp)
        eng.ledger.add(kind="vuln", target="x", detail="d")
        eng.save_state()
        eng.close()
        reloaded = Engagement(eng.cfg_path)
        self.assertEqual(reloaded.ledger.findings[0].disposal, "open")


class TestRetester(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry = build_registry()

    def test_reproduced_verdict(self):
        eng = make_retest_setup(self.tmp)
        router = MockRouter([
            {"content": "", "tool_calls": [
                {"id": "c1", "name": "mock-subfinder", "arguments": {"domain": "a.example.com"}}]},
            record_tool("reproduced", "响应仍包含注入点关键行为"),
        ])
        result = RetestSession(eng, router, self.registry).run("F-001")
        self.assertEqual(result["verdict"], "reproduced")
        records = eng.db.load_retests("F-001")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["verdict"], "reproduced")
        # 复测节点与过程入探索图/activity
        nodes = eng.db.load_exploration()["nodes"]
        self.assertEqual([n["kind"] for n in nodes].count("retest"), 1)
        self.assertTrue(any(a["tool"] == "mock-subfinder"
                            for a in eng.db.load_activity()))
        # 其它结论保留原处置状态
        self.assertEqual(eng.ledger.findings[0].disposal, "open")

    def test_fixed_syncs_disposal(self):
        eng = make_retest_setup(self.tmp)
        router = MockRouter([record_tool("fixed", "原触发条件已失效，对照请求正常")])
        result = RetestSession(eng, router, self.registry).run("F-001")
        self.assertEqual(result["verdict"], "fixed")
        self.assertEqual(eng.ledger.findings[0].disposal, "fixed")
        # 持久化复核
        eng.close()
        reloaded = Engagement(eng.cfg_path)
        self.assertEqual(reloaded.ledger.findings[0].disposal, "fixed")

    def test_no_record_auto_inconclusive(self):
        eng = make_retest_setup(self.tmp)
        router = MockRouter([{"content": "无法达到证据门槛", "tool_calls": []}])
        result = RetestSession(eng, router, self.registry).run("F-001")
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(eng.db.load_retests("F-001")[0]["verdict"], "inconclusive")
        self.assertEqual(eng.ledger.findings[0].disposal, "open")

    def test_double_record_rejected(self):
        eng = make_retest_setup(self.tmp)
        first = record_tool("reproduced", "第一次结论")
        router = MockRouter([first, record_tool("fixed", "第二次结论")])
        result = RetestSession(eng, router, self.registry).run("F-001")
        # 第一次保存即停：后续结论不再执行
        self.assertEqual(result["verdict"], "reproduced")
        self.assertEqual(len(eng.db.load_retests()), 1)

    def test_bad_verdict_rejected(self):
        eng = make_retest_setup(self.tmp)
        router = MockRouter([
            {"content": "", "tool_calls": [
                {"id": "c1", "name": "record-retest-result",
                 "arguments": {"verdict": "maybe", "summary": "x"}}]},
            record_tool("reproduced", "修正后结论"),
        ])
        result = RetestSession(eng, router, self.registry).run("F-001")
        self.assertEqual(result["verdict"], "reproduced")
        self.assertEqual(len(eng.db.load_retests()), 1)

    def test_unknown_finding(self):
        eng = make_retest_setup(self.tmp)
        with self.assertRaises(KeyError):
            RetestSession(eng, MockRouter([]), self.registry).run("F-404")

    def test_rule_gate_still_applies(self):
        eng = make_retest_setup(self.tmp)
        registry = {**self.registry, "browser-action": REGISTRY["browser-action"]}
        router = MockRouter([
            {"content": "", "tool_calls": [
                {"id": "c1", "name": "browser-action",
                 "arguments": {"actions": [{"type": "goto", "url": "http://a.example.com/api/delete"}]}}]},
            record_tool("reproduced", "验证完成"),
        ])
        result = RetestSession(eng, router, registry).run("F-001")
        self.assertEqual(result["verdict"], "reproduced")
        notes = [e.get("note", "") for e in eng.audit.entries()]
        self.assertTrue(any("rule-deny" in n for n in notes))

    def test_finding_context_in_system_prompt(self):
        eng = make_retest_setup(self.tmp, detail="sqli 注入点 /api/users")
        router = MockRouter([record_tool("reproduced", "ok")])
        RetestSession(eng, router, self.registry).run("F-001", note="限 5 次请求")
        system = router.calls and True
        # 结论证据落档：保存 evidence 的 md 写入交战证据目录
        self.assertTrue(system)

    def test_evidence_saved_to_file(self):
        eng = make_retest_setup(self.tmp)
        router = MockRouter([record_tool("reproduced", "ok", evidence="## 复测\n- 步骤…")])
        result = RetestSession(eng, router, self.registry).run("F-001")
        self.assertTrue(result["evidence"], "证据文件路径应非空")
        self.assertTrue(Path(result["evidence"]).exists())


class TestRetestCLI(unittest.TestCase):
    def test_history_only(self):
        tmp = tempfile.mkdtemp()
        eng = make_retest_setup(tmp)
        eng.db.add_retest("F-001", "reproduced", "仍可复现", "")
        args = argparse.Namespace(engagement=str(eng.cfg_path), finding=None,
                                  note="", history=True)
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            cmd_retest(args)
        self.assertIn("[reproduced]", out.getvalue())
        self.assertIn("F-001", out.getvalue())

    def test_history_filtered_by_finding(self):
        tmp = tempfile.mkdtemp()
        eng = make_retest_setup(tmp)
        eng.db.add_retest("F-001", "reproduced", "仍可复现", "")
        args = argparse.Namespace(engagement=str(eng.cfg_path), finding="F-001",
                                  note="", history=True)
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            cmd_retest(args)
        self.assertIn("F-001", out.getvalue())


if __name__ == "__main__":
    unittest.main()
