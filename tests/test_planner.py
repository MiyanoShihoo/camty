"""攻击树规划器测试：全遍历 / 提前收束 / 分支剪枝 / 断点幂等。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from camty.agent.planner import Planner, objective_met
from camty.agent.state import Engagement
from camty.adapters.mock import MockGated, MockSubfinder
from camty.report import ReportAdapter

from tests.test_auto import MockFindings


def build_registry():
    return {
        "mock-subfinder": MockSubfinder(),
        "mock-findings": MockFindings(),
        "mock-gated": MockGated(),
        "report": ReportAdapter(),
    }


def make_project(tmp: str, plan: list, objective: dict | None = None) -> Path:
    root = Path(tmp)
    (root / "packs" / "plan-pack").mkdir(parents=True)
    (root / "packs" / "plan-pack" / "pack.yaml").write_text(
        yaml.safe_dump({"name": "plan-pack", "title": "规划测试", "phases": [], "plan": plan}),
        encoding="utf-8",
    )
    (root / "engagements").mkdir()
    cfg = {
        "name": "plan-eng",
        "pack": "plan-pack",
        "root_domain": "example.com",
        "scope": {"domains": ["example.com"], "min_interval_seconds": 0},
        "auto_confirm": True,
    }
    if objective:
        cfg["objective"] = objective
    path = root / "engagements" / "plan-eng.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path


FULL_PLAN = [
    {"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"}, "provides": ["subdomains"]},
    {"adapter": "mock-findings", "requires": ["subdomains"], "provides": ["findings"]},
    {"adapter": "mock-gated", "requires": ["finding:mock-vuln"], "provides": ["gated"]},
    {"adapter": "report"},
]

NO_FINDING_PLAN = [
    {"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"}, "provides": ["subdomains"]},
    {"adapter": "mock-gated", "requires": ["finding:mock-vuln"], "provides": ["gated"]},
    {"adapter": "report"},
]


class TestPlanner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._engs: list = []

    def tearDown(self):
        for eng in self._engs:
            eng.close()
        self.tmp.cleanup()

    def eng(self, plan, objective=None) -> Engagement:
        path = make_project(self.tmp.name, plan, objective)
        eng = Engagement(path)
        self._engs.append(eng)
        return eng

    def test_full_traversal(self):
        eng = self.eng(FULL_PLAN)
        self.assertTrue(Planner(eng, build_registry()).run())
        done = eng.completed_steps("plan")
        self.assertEqual(done, {0: "done", 1: "done", 2: "done", 3: "done"},
                         f"无 objective 时应全遍历，实际 {done}")
        self.assertEqual(eng.context.get("gated"), "F-001")

    def test_prune_branch_without_finding(self):
        eng = self.eng(NO_FINDING_PLAN)
        self.assertTrue(Planner(eng, build_registry()).run())
        done = eng.completed_steps("plan")
        self.assertEqual(done, {0: "done", 2: "done"},
                         "finding:mock-vuln 永不满足 → mock-gated 被剪枝（未标记），报告步执行")
        self.assertNotIn("gated", eng.context, "被剪枝分支不应执行")

    def test_objective_early_stop(self):
        eng = self.eng(FULL_PLAN, objective={"min_verified_findings": 1})
        self.assertTrue(Planner(eng, build_registry()).run())
        done = eng.completed_steps("plan")
        self.assertEqual(done, {0: "done", 1: "done"}, "objective 在 findings 步后达成，应提前收束")

    def test_objective_context_key(self):
        eng = self.eng(FULL_PLAN, objective={"context_keys": ["gated"]})
        self.assertTrue(Planner(eng, build_registry()).run())
        done = eng.completed_steps("plan")
        self.assertEqual(done, {0: "done", 1: "done", 2: "done"}, "gated 产出即达成")
        met, why = objective_met(eng, {"context_keys": ["gated"]})
        self.assertTrue(met)

    def test_resume_idempotent(self):
        eng = self.eng(FULL_PLAN)
        Planner(eng, build_registry()).run()
        first = dict(eng.completed_steps("plan"))
        self.assertTrue(Planner(eng, build_registry()).run())
        self.assertEqual(eng.completed_steps("plan"), first, "二跑应全跳过")

    def test_dry_run_executes_nothing(self):
        eng = self.eng(FULL_PLAN)
        self.assertTrue(Planner(eng, build_registry()).run(dry_run=True))
        self.assertEqual(eng.completed_steps("plan"), {})
        self.assertEqual(len(eng.ledger.findings), 0)

    def test_missing_plan_section(self):
        root = Path(self.tmp.name)
        pack_dir = root / "packs" / "plan-pack"
        pack_dir.mkdir(parents=True, exist_ok=True)
        pack_dir.joinpath("pack.yaml").write_text(
            yaml.safe_dump({"name": "plan-pack", "title": "t", "phases": []}), encoding="utf-8")
        (root / "engagements").mkdir(exist_ok=True)
        cfg = root / "engagements" / "plan-eng.yaml"
        cfg.write_text(yaml.safe_dump({
            "name": "plan-eng", "pack": "plan-pack", "root_domain": "example.com",
            "scope": {"domains": ["example.com"], "min_interval_seconds": 0},
            "auto_confirm": True}), encoding="utf-8")
        eng = Engagement(cfg)
        self._engs.append(eng)
        with self.assertRaises(KeyError):
            Planner(eng, build_registry()).run()


class TestPlannerV2(unittest.TestCase):
    """v2：requires 扩展 / 并行批 / 预算 / 并发 F-ID。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._engs: list = []

    def tearDown(self):
        for eng in self._engs:
            eng.close()
        self.tmp.cleanup()

    def eng(self, plan, objective=None, budget=None) -> Engagement:
        path = make_project(self.tmp.name, plan, objective)
        if budget is not None:
            cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
            cfg["plan_budget"] = budget
            path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        eng = Engagement(path)
        self._engs.append(eng)
        return eng

    def test_requirement_findings_count(self):
        eng = self.eng([{"adapter": "report"}])
        from camty.agent.planner import _requirement_met
        self.assertFalse(_requirement_met(eng, "findings:mock-vuln:2"))
        eng.ledger.add(kind="vuln", target="t", detail="mock-vuln-1", verified=True)
        self.assertFalse(_requirement_met(eng, "findings:mock-vuln:2"))
        eng.ledger.add(kind="vuln", target="t", detail="mock-vuln-2", verified=True)
        self.assertTrue(_requirement_met(eng, "findings:mock-vuln:2"))
        self.assertTrue(_requirement_met(eng, "findings::3") is False)  # 空模式匹配全部（当前 2 < 3）

    def test_requirement_severity(self):
        eng = self.eng([{"adapter": "report"}])
        from camty.agent.planner import _requirement_met
        eng.ledger.add(kind="vuln", target="t", detail="x", severity="high", verified=True)
        self.assertTrue(_requirement_met(eng, "severity:high"))
        self.assertFalse(_requirement_met(eng, "severity:critical"))

    def test_requirement_any(self):
        plan = [
            {"adapter": "mock-findings", "requires_any": ["never_gonna", "subdomains"],
             "provides": ["findings"]},
            {"adapter": "report"},
        ]
        eng = self.eng(plan)
        self.assertTrue(Planner(eng, build_registry()).run())
        done = eng.completed_steps("plan")
        # requires_any 任一满足：subdomains 不存在但步已执行（never_gonna 也不存在 → 不满足！）
        # 实际上两个条件都不满足 → 该步不 ready → report 无非终态步 → 直接跑 report
        self.assertNotIn(0, done, "requires_any 全不满足时不应执行")
        self.assertEqual(done[1], "done")

    def test_parallel_batch_siblings(self):
        plan = [
            {"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"}, "provides": ["subdomains"]},
            {"adapter": "mock-findings", "requires": ["subdomains"], "provides": ["findings"]},
            {"adapter": "report"},
        ]
        eng = self.eng(plan)
        self.assertTrue(Planner(eng, build_registry()).run())
        done = eng.completed_steps("plan")
        self.assertEqual(done, {0: "done", 1: "done", 2: "done"})

    def test_budget_stops_early(self):
        plan = [
            {"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"}},
            {"adapter": "mock-findings", "requires": ["subdomains"]},
            {"adapter": "mock-gated", "requires": ["finding:mock-vuln"]},
            {"adapter": "report"},
        ]
        eng = self.eng(plan, budget=2)
        self.assertTrue(Planner(eng, build_registry()).run())
        done = eng.completed_steps("plan")
        self.assertEqual(len(done), 2, f"预算 2 步后应收束，实际 {done}")

    def test_ledger_thread_safe_ids(self):
        import threading as _t

        plan = [{"adapter": "report"}]
        eng = self.eng(plan)
        errs = []

        def add_many():
            try:
                for _ in range(50):
                    eng.ledger.add(kind="vuln", target="t", detail="x", verified=True)
            except Exception as exc:  # noqa: BLE001
                errs.append(exc)

        threads = [_t.Thread(target=add_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        ids = [f.id for f in eng.ledger.findings]
        self.assertEqual(len(ids), 200)
        self.assertEqual(len(set(ids)), 200, "并发下 F-ID 必须唯一")
        self.assertFalse(errs)


if __name__ == "__main__":
    unittest.main()
