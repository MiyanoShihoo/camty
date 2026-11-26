"""引擎修复批次回归（R4）：证据锚定完成判定 / blocked 释放 / 空计划守卫 / 重试。

对应 buglog：BUG-01（mission 不进上下文）、BUG-02（blocked intent 楔死）、
BUG-03（worker 零重试）、BUG-06（空计划覆写）、BUG-08（done 恒真桩）。
"""

import json
import tempfile
import unittest

from camty.agent.engine import Engine
from tests.test_artex_port import build_registry, make_eng


class MockRouter:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def chat(self, role, messages, tools=None, timeout=None):
        self.calls.append((role, messages))
        return self.script.pop(0)


def _plan(items_status="pending"):
    return {"content": json.dumps({
        "todolist": [{"item_id": "T1", "title": "侦察", "depends_on": [],
                      "status": items_status, "note": ""}], "spawn": ["T1"]}),
        "tool_calls": []}


def _tool_call(cid="c1", name="mock-subfinder"):
    return {"content": "", "tool_calls": [
        {"id": cid, "name": name, "arguments": {"domain": "example.com"}}]}


class TestEvidenceAnchoredDone(unittest.TestCase):
    """BUG-08：done 需要真实适配器调用，纯叙事 = blocked。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_hollow_narrative_is_blocked(self):
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),                                     # 规划 1：派 T1
            {"content": "侦察完成（纯叙事无动作）", "tool_calls": []},  # worker 只总结
            _plan(),                                     # 规划 2（沿用）
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        items = {i["item_id"]: i for i in __import__("camty.agent.explore", fromlist=["Todolist"])
                 .Todolist(eng).items()}
        self.assertEqual(items["T1"]["status"], "blocked",
                         "纯叙事无真实工具调用的意图不得记 done")
        self.assertIsNone(items["T1"]["intent_id"],
                          "blocked 后 intent_id 必须释放（BUG-02），否则永久楔死")
        eng.close()

    def test_real_tool_call_with_success_marker_is_done(self):
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),
            _tool_call(),                                # 真实适配器调用
            {"content": "侦察完成：确认无注册入口\n[RESULT: 成功]", "tool_calls": []},
            _plan("done"),
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        items = {i["item_id"]: i for i in __import__("camty.agent.explore", fromlist=["Todolist"])
                 .Todolist(eng).items()}
        self.assertEqual(items["T1"]["status"], "done",
                         "真实工具调用 + [RESULT: 成功] 标记的意图应记 done")
        eng.close()


class TestPlannerCannotResurrect(unittest.TestCase):
    """BUG-10：规划者输出不得把 worker 判 blocked 的项翻成 done。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_planner_flip_blocked_to_done_is_guarded(self):
        eng = make_eng(self.tmp)
        # worker 真实调用后如实报告失败 → blocked；随后规划者输出 status=done 试图翻案
        router = MockRouter([
            _plan(),
            _tool_call(),
            {"content": "登录尝试全部被拒\n[RESULT: 失败]", "tool_calls": []},
            _plan("done"),   # 规划者幻觉翻案
            _plan("done"),   # 后续规划轮（无 ready 项）
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        items = {i["item_id"]: i for i in __import__("camty.agent.explore", fromlist=["Todolist"])
                 .Todolist(eng).items()}
        self.assertEqual(items["T1"]["status"], "blocked",
                         "规划者不得把 blocked 项翻成 done——done 只能来自 worker 的成功标记")
        eng.close()


class TestEmptyPlanGuard(unittest.TestCase):
    """BUG-06：LLM 输出空 todolist 不得清空既有计划。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_empty_plan_preserves_existing(self):
        eng = make_eng(self.tmp)
        empty = {"content": json.dumps({"todolist": [], "spawn": []}), "tool_calls": []}
        router = MockRouter([_plan(), empty, _plan("done")])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        from camty.agent.explore import Todolist
        titles = [i["title"] for i in Todolist(eng).items()]
        self.assertIn("侦察", titles, "空计划输出不得清空既有 todolist")
        eng.close()


class TestMissionInPlannerPrompt(unittest.TestCase):
    """BUG-01：objective.mission 全文必须进规划者提示词。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_mission_reaches_planner(self):
        eng = make_eng(self.tmp, extra_cfg={
            "objective": {"title": "通关考试", "mission": "MISSION_MAGIC_TEXT 三阶段按序"}})
        router = MockRouter([_plan(), _plan("done")])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        planner_prompts = [m for r, msgs in router.calls if r == "decide" for m in msgs
                           if m.get("role") == "user"]
        self.assertTrue(any("MISSION_MAGIC_TEXT" in m["content"] for m in planner_prompts),
                         "mission 全文应出现在规划者提示词")
        eng.close()


class TestWorkerRetry(unittest.TestCase):
    """BUG-03：worker 决策调用失败一次应重试而不是整杀意图。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_retry_survives_transient_failure(self):
        eng = make_eng(self.tmp)

        class FlakyRouter:
            def __init__(self):
                self.calls = 0
                self.script = [_plan(), _tool_call(),
                               {"content": "完成\n[RESULT: 成功]", "tool_calls": []}, _plan("done")]

            def chat(self, role, messages, tools=None, timeout=None):
                self.calls += 1
                if self.calls == 2:  # worker 第一次决策：瞬时抖动
                    raise RuntimeError("模拟瞬时网络错误")
                return self.script.pop(0)
        router = FlakyRouter()
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        from camty.agent.explore import Todolist
        items = {i["item_id"]: i for i in Todolist(eng).items()}
        self.assertEqual(items["T1"]["status"], "done",
                         "一次瞬时失败后重试应成功，意图不得打成 blocked")
        eng.close()


class TestClaimedSuccess(unittest.TestCase):
    """BUG-09：done 验证的是结果标记，不是动作量——fail-closed。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _run_worker(self, worker_summaries):
        """worker: 真实工具调用一次 → 总结收尾；返回 item 状态。"""
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),
            _tool_call(),
            {"content": worker_summaries, "tool_calls": []},
            _plan(),  # 规划轮（item 状态由 worker 已标）
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        from camty.agent.explore import Todolist
        items = {i["item_id"]: i for i in Todolist(eng).items()}
        eng.close()
        return items

    def test_honest_failure_is_blocked(self):
        """动手但如实报告失败 → blocked（获得重派），不再机械记 done。"""
        items = self._run_worker("登录尝试 4 次全部被拒，未获得有效会话\n[RESULT: 失败]")
        self.assertEqual(items["T1"]["status"], "blocked")

    def test_success_marker_is_done(self):
        items = self._run_worker("侦察完成：确认无注册入口，登录仅支持已知凭据\n[RESULT: 成功]")
        self.assertEqual(items["T1"]["status"], "done")

    def test_missing_marker_fails_closed(self):
        """忘打标记 → 按失败处理（fail-closed），防止叙事漏网。"""
        items = self._run_worker("完成了，看起来都试过了（未打标记）")
        self.assertEqual(items["T1"]["status"], "blocked")


class TestBlockedReleasesIntentStorage(unittest.TestCase):
    """BUG-02（storage 层）：mark blocked 同步释放 intent_id。"""

    def test_blocked_clears_intent_id(self):
        import sqlite3
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp())
        eng = make_eng(str(tmp))
        try:
            from camty.agent.explore import Todolist
            todo = Todolist(eng)
            todo.replace([{"item_id": "T1", "title": "t", "depends_on": [],
                           "status": "pending", "intent_id": "I-001"}])
            eng.db.mark_todolist_item("T1", "blocked", note="测试阻塞")
            row = eng.db.conn.execute(
                "SELECT status, intent_id FROM todolist WHERE item_id='T1'").fetchone()
            self.assertEqual(row[0], "blocked")
            self.assertIsNone(row[1], "blocked 时 intent_id 应被释放")
        finally:
            eng.close()


if __name__ == "__main__":
    unittest.main()
