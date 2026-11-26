"""planner_skill 注入通道回归：规划者开局直接读取配置技能的方法论正文。

对应指令：内置 agent-orchestrator 编排技能并让引擎直接读取调用——
配置 planner_skill: <技能名> → 技能库加载正文进规划者 system 提示词
（沿用 skill-lookup 根目录探测与 6000 字符截断），缺失时静默降级。
"""

import os
import tempfile
import unittest
from pathlib import Path

from camty.agent.engine import Engine, PLANNER_SYSTEM
from tests.test_artex_port import build_registry, make_eng
from tests.test_engine_fixes import MockRouter, _plan


def _planner_systems(router) -> list[str]:
    return [m["content"] for role, msgs in router.calls if role == "decide"
            for m in msgs if m.get("role") == "system"]


class TestPlannerSkillInjection(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _with_extra_skills(self, skill_root: Path, cfg: dict) -> dict:
        """夹具技能库：CAMTY_SKILL_EXTRA_DIRS 指向临时根（用完恢复）。"""
        old = os.environ.get("CAMTY_SKILL_EXTRA_DIRS")
        os.environ["CAMTY_SKILL_EXTRA_DIRS"] = str(skill_root)
        self.addCleanup(lambda: os.environ.__setitem__(
            "CAMTY_SKILL_EXTRA_DIRS", old) if old is not None
            else os.environ.pop("CAMTY_SKILL_EXTRA_DIRS", None))
        return cfg

    def test_planner_skill_injected(self):
        skill_root = Path(self.tmp) / "skills"
        (skill_root / "zskill-orch").mkdir(parents=True)
        (skill_root / "zskill-orch" / "SKILL.md").write_text(
            "# 编排方法论\nORCH_MARKER_X 证据优先，单决策推进，独立评审。", encoding="utf-8")
        cfg = self._with_extra_skills(skill_root, {"planner_skill": "zskill-orch"})
        eng = make_eng(self.tmp, extra_cfg=cfg)
        router = MockRouter([_plan(), _plan("done")])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        systems = _planner_systems(router)
        self.assertTrue(systems, "规划者应至少被调用一次")
        self.assertIn("ORCH_MARKER_X", systems[0],
                      "planner_skill 配置的技能正文应注入规划者 system 提示词")
        self.assertIn("编排方法论技能", systems[0],
                      "注入块应带来源标注（技能名）")
        eng.close()

    def test_missing_skill_degrades_silently(self):
        eng = make_eng(self.tmp, extra_cfg={"planner_skill": "no-such-skill"})
        router = MockRouter([_plan(), _plan("done")])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()  # 技能缺失不得抛异常、不得阻断交战
        systems = _planner_systems(router)
        self.assertEqual(systems[0], PLANNER_SYSTEM,
                         "技能缺失时规划者提示词应与基线完全一致（静默降级）")
        eng.close()

    def test_no_config_no_block(self):
        eng = make_eng(self.tmp)
        router = MockRouter([_plan(), _plan("done")])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2)
        engine.run()
        systems = _planner_systems(router)
        self.assertEqual(systems[0], PLANNER_SYSTEM,
                         "未配置 planner_skill 时不得注入任何块")
        eng.close()


if __name__ == "__main__":
    unittest.main()
