"""引擎修复批次回归（R4/R5）：证据锚定完成判定 / blocked 释放 / 空计划守卫 / 重试 /
结果上报工具化 / blocked 重臂生命周期。

对应 buglog：BUG-01（mission 不进上下文）、BUG-02（blocked intent 楔死）、
BUG-03（worker 零重试）、BUG-06（空计划覆写）、BUG-08（done 恒真桩）、
BUG-09（标记验证 fail-closed）、BUG-10（规划者翻案守卫）、BUG-11（结果标记
协议不遵从 → report-result 工具化，工具上报为权威判定）、BUG-12（blocked
依赖饿死 → 重臂回收 + 预算耗尽标注 + 乒乓守卫）。
"""

import json
import tempfile
import unittest

from camty.agent.engine import Engine
from camty.agent.explore import ExplorationGraph, Todolist
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


def _report_call(cid="r1", verdict="成功", evidence=""):
    """BUG-11：worker 的 report-result 工具调用脚本项。"""
    return {"content": "", "tool_calls": [
        {"id": cid, "name": "report-result",
         "arguments": {"verdict": verdict, "evidence": evidence}}]}


def _summary(text):
    return {"content": text, "tool_calls": []}


def _items(eng):
    return {i["item_id"]: i for i in Todolist(eng).items()}


def _intents(eng):
    """按创建顺序返回意图节点（node_id 计数器单调递增）。"""
    return sorted((n for n in ExplorationGraph(eng).graph()["nodes"]
                   if n["kind"] == "intent"),
                  key=lambda n: int(n["node_id"].rsplit("-", 1)[1]))


class TestEvidenceAnchoredDone(unittest.TestCase):
    """BUG-08：done 需要真实适配器调用，纯叙事 = blocked。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_hollow_narrative_is_blocked(self):
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),                                     # 规划 1：派 D1
            {"content": "侦察完成（纯叙事无动作）", "tool_calls": []},  # D1 只总结 → blocked
            _plan("blocked"),                            # 规划 2：无 ready → 引擎重臂 T1（BUG-12）
            _plan(),                                    # 规划 3：重派 D2
            {"content": "仍无动作（纯叙事）", "tool_calls": []},      # D2 仍纯叙事 → blocked
            _plan("blocked"),                            # 规划 4：重派预算耗尽 → 收束
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        items = _items(eng)
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
        # （一次直接翻 + 一次借重臂 pending 窗口翻），两次都必须被守卫拦下
        router = MockRouter([
            _plan(),
            _tool_call(),
            {"content": "登录尝试全部被拒\n[RESULT: 失败]", "tool_calls": []},
            _plan("done"),   # 规划者幻觉翻案 1：blocked → done
            _plan("done"),   # 规划者幻觉翻案 2：重臂 pending → done（两步翻案）
            _tool_call("c6"),  # 重臂后的 D2 真实调用
            {"content": "重派仍全部被拒\n[RESULT: 失败]", "tool_calls": []},  # D2 如实失败
            _plan("blocked"),  # 规划 4：重派预算耗尽 → 收束
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        items = _items(eng)
        self.assertEqual(items["T1"]["status"], "blocked",
                         "规划者不得把 blocked 项翻成 done——done 只能来自 worker 的成功判定")
        eng.close()


class TestEmptyPlanGuard(unittest.TestCase):
    """BUG-06：LLM 输出空 todolist 不得清空既有计划。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_empty_plan_preserves_existing(self):
        eng = make_eng(self.tmp)
        empty = {"content": json.dumps({"todolist": [], "spawn": []}), "tool_calls": []}
        router = MockRouter([
            _plan(),          # 规划 1：派 D1
            empty,            # D1 总结（无真实动作）→ blocked
            _plan("done"),    # 规划 2：无 ready → 引擎重臂 T1
            _plan(),          # 规划 3：重派 D2
            _tool_call("c2"),  # D2 真实调用
            {"content": "侦察完成：确认无注册入口\n[RESULT: 成功]", "tool_calls": []},
        ])
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
        """worker: 真实工具调用一次 → 总结收尾；失败用例走完整重臂周期后返回 item 状态。

        成功用例在首轮 objective 达成即收束（脚本尾部条目不消耗）；失败用例
        D1 blocked → 引擎重臂 → D2 同样总结 → 重派预算耗尽 → 收束。
        """
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),                                    # 规划 1：派 D1
            _tool_call(),                               # D1 真实调用
            {"content": worker_summaries, "tool_calls": []},  # D1 总结（按用例文本）
            _plan("blocked"),                           # 规划 2：无 ready → 引擎重臂 T1
            _plan(),                                    # 规划 3：重派 D2
            _tool_call("c3"),                           # D2 真实调用
            {"content": worker_summaries, "tool_calls": []},  # D2 同样总结（重派同结果）
            _plan("blocked"),                           # 规划 4：重派预算耗尽 → 收束
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        items = _items(eng)
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


class TestReportResultTool(unittest.TestCase):
    """BUG-11：report-result 工具上报是判定的权威来源，文本标记降为遗留兜底。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_report_success_without_text_marker_is_done(self):
        """(a) 工具上报成功 + 真实调用 + 总结无文本标记 → done（工具判定生效）。"""
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),                                            # 规划 1：派 D1
            _tool_call(),                                       # D1 真实适配器调用
            _report_call("c2", "成功", "subfinder 实测返回 3 个子域"),  # 工具上报成功
            _summary("侦察完成：确认无注册入口（总结无 [RESULT:] 文本标记）"),
            _plan("done"),                                      # 备用规划轮
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        self.assertTrue(engine.run())
        items = _items(eng)
        self.assertEqual(items["T1"]["status"], "done",
                         "report-result(成功) 应记 done，即使总结没有 [RESULT:] 文本标记")
        reports = [a for a in eng.db.load_activity() if a["tool"] == "report-result"]
        self.assertEqual(len(reports), 1, "工具上报应落一条过程记录")
        self.assertIn("成功", reports[0]["args_digest"])
        eng.close()

    def test_report_failure_overrides_text_success_marker(self):
        """(b) 工具上报失败 + 总结文本声称 [RESULT: 成功] → blocked（工具权威覆盖文本）。"""
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),                                        # 规划 1：派 D1
            _tool_call(),                                   # D1 真实调用
            _report_call("c2", "失败", "登录尝试 4 次全部被拒"),  # 工具上报失败
            _summary("虽然文本写着成功\n[RESULT: 成功]"),        # 文本标记成功（应被覆盖）
            _plan("blocked"),                              # 规划 2：无 ready → 引擎重臂 T1
            _plan(),                                        # 规划 3：重派 D2
            _tool_call("c4"),                               # D2 真实调用
            _report_call("c5", "成功", "重试后获得有效会话"),     # D2 工具上报成功
            _summary("第二次完成"),                          # D2 总结
            _plan("done"),                                  # 备用规划轮
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        self.assertTrue(engine.run())
        intents = _intents(eng)
        self.assertEqual(len(intents), 2, "D1 失败 → 重臂 → D2：应恰好两次派发")
        self.assertEqual(intents[0]["status"], "blocked",
                         "工具上报失败必须覆盖总结文本里的 [RESULT: 成功]——"
                         "若文本标记仍生效，首个意图节点会是 done")
        self.assertEqual(intents[1]["status"], "done")
        items = _items(eng)
        self.assertEqual(items["T1"]["status"], "done", "重臂后 D2 成功 → 终态 done")
        eng.close()

    def test_report_success_without_real_calls_is_blocked(self):
        """(c) 工具上报成功但零真实调用 → 仍 blocked（BUG-08a fail-closed 不放松）。"""
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),                                    # 规划 1：派 D1
            _report_call("c1", "成功", "确认无此漏洞"),   # D1 只上报，零真实调用
            _summary("侦察完成：确认无此漏洞"),
            _plan("blocked"),                           # 规划 2：重臂
            _plan(),                                    # 规划 3：重派 D2
            _report_call("c3", "成功", "确认无此漏洞"),   # D2 仍零真实调用
            _summary("确认无此漏洞（无动作）"),
            _plan("blocked"),                           # 规划 4：重派预算耗尽 → 收束
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        self.assertFalse(engine.run())
        items = _items(eng)
        self.assertEqual(items["T1"]["status"], "blocked",
                         "report-result 不计入真实产出（BUG-08a）：上报成功但零真实调用"
                         "仍 fail-closed 判 blocked")
        eng.close()


class TestBlockedRearm(unittest.TestCase):
    """BUG-12：blocked 生命周期——饥饿重臂 / 预算耗尽标注 / 规划者乒乓守卫。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_honest_failure_rearms_then_succeeds(self):
        """(d) 诚实失败 → 引擎自动重臂 → 第二次派发成功 → 终态 done，且恰好两次派发。"""
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),                                   # 规划 1：派 D1
            _tool_call(),                              # D1 真实调用
            _summary("尝试被拒\n[RESULT: 失败]"),       # D1 诚实失败 → blocked
            _plan("blocked"),                          # 规划 2：无 ready → 引擎重臂 T1
            _plan(),                                   # 规划 3：重派 D2
            _tool_call("c4"),                          # D2 真实调用
            _summary("重派后完成\n[RESULT: 成功]"),     # D2 成功
            _plan("done"),                             # 备用规划轮
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        self.assertTrue(engine.run())
        items = _items(eng)
        self.assertEqual(items["T1"]["status"], "done",
                         "重臂后的第二次派发成功应记 done（修复前 blocked 链永久冻结）")
        intents = _intents(eng)
        self.assertEqual(len(intents), 2, "应恰好两次 worker 派发（失败一次 + 重派一次）")
        self.assertEqual(engine._spawn_counts.get("T1"), 2)
        eng.close()

    def test_budget_exhaustion_annotates_and_terminates(self):
        """(e) 两次派发都失败 → note 标"重派预算耗尽"，无第三次派发，引擎收束。"""
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),                                   # 规划 1：派 D1
            _tool_call(),                              # D1 真实调用
            _summary("失败一\n[RESULT: 失败]"),
            _plan("blocked"),                          # 规划 2：重臂
            _plan(),                                   # 规划 3：重派 D2
            _tool_call("c4"),                          # D2 真实调用
            _summary("失败二\n[RESULT: 失败]"),
            _plan("blocked"),                          # 规划 4：预算耗尽 → 收束
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        self.assertFalse(engine.run())
        items = _items(eng)
        self.assertEqual(items["T1"]["status"], "blocked")
        self.assertIn("重派预算耗尽", items["T1"]["note"] or "",
                      "预算耗尽的 blocked 项必须标注，供规划者重排依赖它的条目")
        intents = _intents(eng)
        self.assertEqual(len(intents), 2, "MAX_RESPAWN=2：最多两次派发，不得有第三次")
        eng.close()

    def test_pingpong_guard_terminates(self):
        """(f) 规划者每轮把重臂项翻回 blocked → 乒乓守卫拦重臂，引擎有限步收束。"""
        eng = make_eng(self.tmp)
        router = MockRouter([
            _plan(),                                   # 规划 1：派 D1
            _tool_call(),                              # D1 真实调用
            _summary("失败\n[RESULT: 失败]"),           # D1 失败 → blocked
            _plan("blocked"),                          # 规划 2：引擎重臂 T1
            _plan("blocked"),                          # 规划 3：规划者翻回 blocked → 守卫 → 收束
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()  # 必须返回：重臂不兑现成派发就不得再次重臂，不得无限循环
        items = _items(eng)
        self.assertEqual(items["T1"]["status"], "blocked")
        intents = _intents(eng)
        self.assertEqual(len(intents), 1,
                         "乒乓守卫：重臂未兑现成真实派发前不得再次重臂（只有 1 次派发）")
        self.assertNotIn("重派预算耗尽", items["T1"]["note"] or "",
                          "只派发 1 次遭规划者乒乓，不应标预算耗尽")
        eng.close()


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
