"""侧问测试：只读快照问答 + 态势注入 + activity 留痕 + CLI/API。"""

from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from unittest import mock

from camty.agent.sidequestion import answer_question
from camty.cli import cmd_ask
from tests.test_artex_port import make_eng
from tests.test_goals import MockRouter


class TestSideQuestion(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)
        self.eng.ledger.add(kind="vuln", target="https://a.example.com",
                            detail="sqli 注入点 /api/users", severity="high", verified=True)
        self.eng.db.add_note("waf", "a.example.com 检出 WAF", source="I-001")

    def test_answer_with_snapshot(self):
        router = MockRouter("最严重的是 F-001 sqli 注入点（high，已验证）")
        answer = answer_question(self.eng, router, "现在最严重的发现是什么？")
        self.assertIn("F-001", answer)
        # 态势快照进入 system 提示：台账 + 黑板
        system = router.seen[0][0]["content"]
        self.assertIn("sqli 注入点", system)
        self.assertIn("a.example.com 检出 WAF", system)
        self.assertIn("todolist", system)
        # 问题在 user 消息
        self.assertEqual(router.seen[0][1]["content"], "现在最严重的发现是什么？")

    def test_answer_recorded_to_activity(self):
        router = MockRouter("答案文本")
        answer_question(self.eng, router, "问一句")
        entries = self.eng.db.load_activity()
        side = [e for e in entries if e["tool"] == "side-question"]
        self.assertEqual(len(side), 1)
        self.assertIn("问一句", side[0]["args_digest"])

    def test_snapshot_includes_recent_traces(self):
        self.eng.db.add_activity("I-001", 1, "nuclei", '{"x":1}', "2 hits", None)
        router = MockRouter("ok")
        answer_question(self.eng, router, "q")
        system = router.seen[0][0]["content"]
        self.assertIn("最近执行过程", system)
        self.assertIn("2 hits", system)

    def test_empty_question_rejected(self):
        with self.assertRaises(ValueError):
            answer_question(self.eng, MockRouter("x"), "  ")

    def test_cli_ask(self):
        args = argparse.Namespace(
            engagement=str(self.eng.cfg_path), question="现在有什么发现")
        out = io.StringIO()
        with mock.patch("camty.cli.LLMRouter") as router_cls:
            router_cls.return_value = MockRouter("台账里有一个已验证注入点")
            with mock.patch("sys.stdout", out):
                cmd_ask(args)
        self.assertIn("已验证注入点", out.getvalue())


class TestAskAPI(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient

        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)
        from camty.api import app as app_mod

        app_mod._ENGAGEMENTS[self.eng.name] = self.eng
        self.client = TestClient(app_mod.app)
        self.app_mod = app_mod

    def tearDown(self):
        self.app_mod._ENGAGEMENTS.pop(self.eng.name, None)

    def test_ask_endpoint(self):
        with mock.patch("camty.llm.router.LLMRouter") as router_cls:
            router_cls.return_value = MockRouter("回答内容")
            resp = self.client.post(f"/api/engagements/{self.eng.name}/ask",
                                    json={"question": "状态如何"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["answer"], "回答内容")

    def test_ask_endpoint_empty_question(self):
        resp = self.client.post(f"/api/engagements/{self.eng.name}/ask",
                                json={"question": " "})
        self.assertEqual(resp.status_code, 400)

    def test_ask_endpoint_llm_failure(self):
        with mock.patch("camty.llm.router.LLMRouter") as router_cls:
            router_cls.return_value.chat.side_effect = RuntimeError("no key")
            resp = self.client.post(f"/api/engagements/{self.eng.name}/ask",
                                    json={"question": "x"})
        self.assertEqual(resp.status_code, 503)
        self.assertIn("侧问失败", resp.json()["detail"])


if __name__ == "__main__":
    unittest.main()
