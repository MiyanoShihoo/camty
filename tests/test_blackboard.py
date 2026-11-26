"""黑板继承 + 台账压缩测试：跨唤醒持久观察 + 大台账无损摘要。"""

from __future__ import annotations

import json
import tempfile
import unittest

from camty.agent.blackboard import Blackboard, ledger_digest
from camty.agent.engine import Engine
from camty.agent.state import Engagement
from tests.test_artex_port import build_registry, make_eng
from tests.test_goals import RecordingRouter


class TestBlackboard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)
        self.board = Blackboard(self.eng)

    def test_add_and_summary(self):
        self.board.add("waf", "api.example.com 检出 WAF（cloudflare）", source="I-001")
        self.board.add("rate-limit", "nuclei 并发 10 触发 429", source="I-002")
        self.assertEqual(len(self.eng.db.load_notes()), 2)
        summary = self.board.summary()
        self.assertIn("黑板", summary)
        self.assertIn("[waf]", summary)
        self.assertIn("429", summary)
        # 按时间正序展示
        self.assertLess(summary.index("[waf]"), summary.index("[rate-limit]"))

    def test_summary_empty(self):
        self.assertEqual(self.board.summary(), "")

    def test_filtered_notes(self):
        self.board.add("lesson", " Turnstile 与注入互斥")
        self.board.add("waf", "cloudflare")
        waf = self.eng.db.load_notes(kind="waf")
        self.assertEqual(len(waf), 1)
        self.assertEqual(waf[0]["kind"], "waf")

    def test_persistence_across_reload(self):
        """断点续跑不丢：新 Engagement 实例能看到黑板。"""
        self.board.add("lesson", "登录态 30 分钟过期")
        self.eng.save_state()
        self.eng.close()
        reloaded = Engagement(self.eng.cfg_path)
        notes = Blackboard(reloaded).notes()
        self.assertEqual(len(notes), 1)
        self.assertIn("登录态", notes[0]["note"])


class TestLedgerDigest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)

    def test_small_ledger_full(self):
        self.eng.ledger.add(kind="vuln", target="a.com", detail="注入点", verified=True)
        digest = ledger_digest(self.eng)
        self.assertIn("F-001", digest)
        self.assertIn("注入点", digest)

    def test_large_ledger_compacts_without_loss(self):
        """25 项 finding：高危 verified 保留明细，全部计入聚合计数。"""
        for i in range(25):
            sev = "high" if i % 5 == 0 else "info"
            self.eng.ledger.add(kind="vuln", target=f"s{i}.example.com",
                                detail=f"发现{i}", severity=sev, verified=i % 2 == 0)
        digest = ledger_digest(self.eng)
        self.assertIn("台账共 25 项", digest)
        self.assertIn("info×20", digest)
        self.assertIn("high×5", digest)
        # verified 高危保留明细；info 级明细被压缩（保聚合）
        self.assertIn("s0.example.com", digest)     # 首个 high verified
        self.assertNotIn("s1.example.com", digest)  # info 未验证，压缩掉明细
        # 无静默丢失：任何 finding 都至少计入聚合计数
        self.assertIn("verified 13/25", digest)

    def test_digest_replaces_truncation(self):
        """验证旧 `[:1500]` 截断丢 finding 的问题已修：digest 比硬截断保留更多关键信息。"""
        for i in range(29):
            self.eng.ledger.add(kind="vuln", target=f"host{i}.example.com",
                                detail="x" * 80, severity="high", verified=True)
        # 一条利用链血缘：F-003 ← F-001
        self.eng.ledger.add(kind="access", target="host0.example.com",
                            detail="利用产出会话", severity="high", verified=True,
                            derived_from=["F-001"])
        digest = ledger_digest(self.eng)
        self.assertIn("台账共 30 项", digest)
        self.assertIn("血缘链", digest)
        self.assertIn("F-030 ← F-001", digest)


class TestEngineBlackboardInheritance(unittest.TestCase):
    """引擎：worker 写黑板 → 下一轮 planner 与 worker 都能看到（继承）。"""

    def test_worker_notes_planner_inherits(self):
        """worker 写黑板 → 下一轮 planner 提示里能看到（跨唤醒继承）。"""
        tmp = tempfile.mkdtemp()
        eng = make_eng(tmp)
        plan1 = {"todolist": [
            {"item_id": "T1", "title": "侦察", "depends_on": [], "status": "pending"},
            {"item_id": "T2", "title": "利用", "depends_on": ["T1"], "status": "pending"}],
            "spawn": ["T1"]}
        plan2 = {"todolist": [
            {"item_id": "T1", "title": "侦察", "depends_on": [], "status": "done"},
            {"item_id": "T2", "title": "利用", "depends_on": ["T1"], "status": "pending"}],
            "spawn": ["T2"]}
        plan3 = {"todolist": [
            {"item_id": "T1", "title": "侦察", "depends_on": [], "status": "done"},
            {"item_id": "T2", "title": "利用", "depends_on": ["T1"], "status": "done"}],
            "spawn": []}
        router = RecordingRouter([
            {"content": json.dumps(plan1), "tool_calls": []},        # planner 1（只派 T1）
            {"content": "", "tool_calls": [
                {"id": "c1", "name": "blackboard-note",
                 "arguments": {"kind": "waf", "note": "example.com 有 WAF"}}]},  # worker T1 记黑板
            {"content": "", "tool_calls": [
                {"id": "c2", "name": "mock-subfinder",
                 "arguments": {"domain": "example.com"}}]},          # worker T1 真实调用
            {"content": "", "tool_calls": [
                {"id": "c3", "name": "report-result",
                 "arguments": {"verdict": "成功", "evidence": "侦察完成"}}]},  # worker T1 上报
            {"content": "侦察完成", "tool_calls": []},               # worker T1 总结
            {"content": json.dumps(plan2), "tool_calls": []},        # planner 2（派 T2）
            {"content": "", "tool_calls": [
                {"id": "c4", "name": "mock-subfinder",
                 "arguments": {"domain": "example.com"}}]},          # worker T2 真实调用
            {"content": "", "tool_calls": [
                {"id": "c5", "name": "report-result",
                 "arguments": {"verdict": "成功", "evidence": "利用完成"}}]},  # worker T2 上报
            {"content": "利用完成", "tool_calls": []},               # worker T2 总结
            {"content": json.dumps(plan3), "tool_calls": []},        # planner 3（全 done，收束）
        ])
        engine = Engine(eng, router=router, registry=build_registry(), max_total_steps=10)
        engine.run()
        # 黑板已入库
        notes = eng.db.load_notes()
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["kind"], "waf")
        # 第 2 轮 planner（chat #6）继承黑板
        planner_prompt = router.messages_seen[5][-1]["content"]
        self.assertIn("example.com 有 WAF", planner_prompt)

    def test_worker_tool_list_contains_blackboard(self):
        """LLM worker 的工具列表包含 blackboard-note。"""
        tmp = tempfile.mkdtemp()
        eng = make_eng(tmp)
        todolist = json.dumps({
            "todolist": [{"item_id": "T1", "title": "侦察", "depends_on": [],
                          "status": "pending"}], "spawn": ["T1"]})
        done_list = json.dumps({
            "todolist": [{"item_id": "T1", "title": "侦察", "depends_on": [],
                          "status": "done"}], "spawn": []})
        captured_tools = []

        class ToolCapturingRouter(RecordingRouter):
            def chat(self, role, messages, tools=None, timeout=None):
                if tools is not None:
                    captured_tools.append([t["function"]["name"] for t in tools])
                return super().chat(role, messages, tools, timeout)

        router = ToolCapturingRouter([
            {"content": todolist, "tool_calls": []},                  # planner 1（派 T1）
            {"content": "", "tool_calls": [
                {"id": "c1", "name": "blackboard-note",
                 "arguments": {"kind": "lesson", "note": "观察"}}]},   # worker T1 记黑板
            {"content": "", "tool_calls": [
                {"id": "c2", "name": "mock-subfinder",
                 "arguments": {"domain": "example.com"}}]},            # worker T1 真实调用
            {"content": "", "tool_calls": [
                {"id": "c3", "name": "report-result",
                 "arguments": {"verdict": "成功", "evidence": "侦察完成"}}]},  # worker T1 上报
            {"content": "侦察完成", "tool_calls": []},                 # worker T1 总结
            {"content": done_list, "tool_calls": []},                  # planner 2（T1 done，收束）
        ])
        engine = Engine(eng, router=router, registry=build_registry(), max_total_steps=10)
        engine.run()
        # planner 的 tools=None；worker 的工具列表应含 blackboard-note 与 search-traces
        flat = [name for names in captured_tools for name in names]
        self.assertIn("blackboard-note", flat)
        self.assertIn("search-traces", flat)


if __name__ == "__main__":
    unittest.main()
