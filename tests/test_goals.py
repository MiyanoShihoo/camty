"""goals NL 分解测试：目标/约束提取 → 规则门硬执行 → 提示词注入 → CLI 落盘。"""

from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from camty.agent.goals import (
    build_engagement,
    classify_constraint,
    constraints_prompt,
    decompose,
    save_engagement,
)
from camty.cli import cmd_goals
from camty.guardrail.rules import check_rules
from tests.test_artex_port import make_eng


class MockRouter:
    def __init__(self, content):
        self.content = content
        self.seen = []

    def chat(self, role, messages, tools=None, timeout=None):
        self.seen.append(messages)
        return {"content": self.content, "tool_calls": []}


class RecordingRouter:
    """按脚本回放并记录完整 messages（断言提示词注入用）。"""

    def __init__(self, script):
        self.script = list(script)
        self.messages_seen = []

    def chat(self, role, messages, tools=None, timeout=None):
        self.messages_seen.append(messages)
        return self.script.pop(0)


DECISION = {
    "root_domain": "abc.example.net",
    "cidrs": [],
    "extra_domains": ["cdn.example.net"],
    "constraints": [
        {"type": "deny", "rule": "不扫描 abc.example.net 的端口"},
        {"type": "deny", "rule": "禁止对 abc.example.net 做写操作"},
    ],
    "goals": [{"title": "取得已验证漏洞清单", "done_when": "台账 ≥1 verified vuln"}],
    "suggested_pack": "ext-web",
    "name": "abc-web",
}


class TestDecompose(unittest.TestCase):
    def test_parse_and_validate(self):
        router = MockRouter(json.dumps(DECISION))
        decision = decompose(router, "对 abc.example.net 全面渗透")
        self.assertEqual(decision["root_domain"], "abc.example.net")
        self.assertEqual(len(decision["constraints"]), 2)

    def test_no_target_rejected(self):
        router = MockRouter(json.dumps({"root_domain": "", "cidrs": [], "goals": []}))
        with self.assertRaises(ValueError) as ctx:
            decompose(router, "随便测测")
        self.assertIn("目标资产", str(ctx.exception))

    def test_unparseable_output(self):
        router = MockRouter("我觉得没法输出 JSON")
        with self.assertRaises(ValueError):
            decompose(router, "x")


class TestBuildEngagement(unittest.TestCase):
    def setUp(self):
        self.cfg = build_engagement(DECISION)

    def test_scope_and_pack(self):
        self.assertEqual(self.cfg["pack"], "ext-web")
        self.assertEqual(self.cfg["scope"]["domains"],
                         ["abc.example.net", "cdn.example.net"])
        self.assertEqual(self.cfg["root_domain"], "abc.example.net")
        self.assertEqual(self.cfg["objective"]["min_verified_findings"], 1)

    def test_int_ad_pack_when_cidr(self):
        cfg = build_engagement({**DECISION, "cidrs": ["10.0.0.0/24"]})
        self.assertEqual(cfg["pack"], "int-ad")
        self.assertEqual(cfg["target_cidr"], "10.0.0.0/24")

    def test_no_portscan_rule_denies_fscan(self):
        # nl-no-portscan 规则：fscan 全量 deny
        self.assertIsNotNone(check_rules(self.cfg, "fscan", {"target": "abc.example.net"}))
        # 不误伤其它适配器
        self.assertIsNone(check_rules(self.cfg, "browser-visit", {"url": "https://abc.example.net"}))

    def test_no_write_rule_denies_write_sql_only(self):
        from camty.adapters.registry import REGISTRY

        self.assertIsNotNone(REGISTRY["sqli-exploit"])  # 适配器存在
        self.assertIsNotNone(
            check_rules(self.cfg, "sqli-exploit", {"query": "UPDATE users SET name='x'"}))
        self.assertIsNotNone(
            check_rules(self.cfg, "sqli-exploit", {"query": "INSERT INTO logs VALUES(1)"}))
        # 读操作放行
        self.assertIsNone(
            check_rules(self.cfg, "sqli-exploit", {"query": "SELECT version()"}))

    def test_write_confirm_flag(self):
        self.assertEqual(self.cfg["authz"]["write_confirm"], True)

    def test_constraints_kept_for_prompt(self):
        self.assertEqual(len(self.cfg["constraints"]), 2)


class TestConstraintInjection(unittest.TestCase):
    def test_constraints_prompt(self):
        text = constraints_prompt({"constraints": DECISION["constraints"]})
        self.assertIn("操作约束", text)
        self.assertIn("不扫描 abc.example.net 的端口", text)
        self.assertIn("[deny]", text)

    def test_empty_constraints(self):
        self.assertEqual(constraints_prompt({}), "")
        self.assertEqual(constraints_prompt({"constraints": []}), "")

    def test_worker_prompt_gets_constraints(self):
        """引擎 LLM worker 的 system 提示包含操作约束。"""
        import json as _json

        from camty.agent.engine import Engine
        from tests.test_artex_port import build_registry

        tmp = tempfile.mkdtemp()
        eng = make_eng(tmp, extra_cfg={
            "constraints": [{"type": "deny", "rule": "禁止对 example.com 做写操作"}]})
        todolist = _json.dumps({
            "todolist": [{"item_id": "T1", "title": "侦察", "depends_on": [],
                          "status": "pending"}], "spawn": ["T1"]})
        router = RecordingRouter([
            {"content": todolist, "tool_calls": []},
            {"content": "侦察完成，无写动作", "tool_calls": []},
        ])
        engine = Engine(eng, router=router, registry=build_registry(), max_total_steps=5)
        engine.run()
        # chat 顺序：先 planner 后 worker；worker 的 system 是 messages[0]
        worker_messages = router.messages_seen[1]
        self.assertIn("禁止对 example.com 做写操作", worker_messages[0]["content"])

    def test_planner_prompt_gets_constraints(self):
        from camty.agent.engine import Engine
        from tests.test_artex_port import build_registry

        tmp = tempfile.mkdtemp()
        eng = make_eng(tmp, extra_cfg={
            "constraints": [{"type": "deny", "rule": "只允许被动侦察 example.com"}]})
        router = RecordingRouter([
            {"content": json.dumps({"todolist": [], "spawn": []}), "tool_calls": []},
        ])
        engine = Engine(eng, router=router, registry=build_registry(), max_total_steps=5)
        engine.run()
        planner_prompt = router.messages_seen[0][-1]["content"]
        self.assertIn("只允许被动侦察 example.com", planner_prompt)


class TestSaveEngagement(unittest.TestCase):
    def test_save_and_reload(self):
        tmp = tempfile.mkdtemp()
        root = Path(tmp)
        (root / "packs" / "ext-web").mkdir(parents=True)
        (root / "packs" / "ext-web" / "pack.yaml").write_text(
            yaml.safe_dump({"name": "ext-web", "title": "外部 Web", "phases": []}),
            encoding="utf-8")
        path = root / "engagements" / "abc-web.yaml"
        import os

        cwd = os.getcwd()
        os.chdir(root)  # Engagement 在 cfg 父目录的上级找 packs/
        try:
            out = save_engagement(DECISION, path)
            self.assertTrue(Path(out).exists())
            cfg = yaml.safe_load(Path(out).read_text(encoding="utf-8"))
            self.assertEqual(cfg["scope"]["domains"][0], "abc.example.net")
            self.assertIn("extra", cfg["rules"])
        finally:
            os.chdir(cwd)

    def test_cli_goals_save(self):
        tmp = tempfile.mkdtemp()
        root = Path(tmp)
        (root / "packs" / "ext-web").mkdir(parents=True)
        (root / "packs" / "ext-web" / "pack.yaml").write_text(
            yaml.safe_dump({"name": "ext-web", "title": "外部 Web", "phases": []}),
            encoding="utf-8")
        args = argparse.Namespace(text="对 abc.example.net 渗透，不扫端口", save=True)
        import os

        cwd = os.getcwd()
        os.chdir(root)
        try:
            with mock.patch("camty.cli.LLMRouter") as router_cls:
                router_cls.return_value = MockRouter(json.dumps(DECISION))
                out = io.StringIO()
                with mock.patch("sys.stdout", out):
                    cmd_goals(args)
            self.assertIn("交战配置已保存", out.getvalue())
            self.assertTrue((root / "engagements" / "abc-web.yaml").exists())
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
