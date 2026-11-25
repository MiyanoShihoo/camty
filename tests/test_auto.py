"""全自动模式（Orchestrator）测试：全链 / 门控阻断 / 断点续跑 / dry-run。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.adapters.mock import MockSubfinder
from camty.agent.orchestrator import Orchestrator, gate_check, phase_status
from camty.agent.state import Engagement
from camty.report import ReportAdapter

PACK = {
    "name": "auto-pack",
    "title": "自动链",
    "phases": [
        {"id": "recon", "title": "侦察", "steps": [
            {"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"}},
        ]},
        {"id": "verify", "title": "验证", "gate": {"require_context": ["subdomains"]}, "steps": [
            {"adapter": "mock-findings"},
        ]},
        {"id": "exploit", "title": "利用", "gate": {"min_verified_findings": 1}, "steps": [
            {"adapter": "mock-gated"},
        ]},
        {"id": "evidence", "title": "报告", "steps": [{"adapter": "report"}]},
    ],
}

CFG = {
    "name": "auto-eng",
    "pack": "auto-pack",
    "root_domain": "example.com",
    "scope": {"domains": ["example.com"], "min_interval_seconds": 0},
    "auto_confirm": True,
}


class MockFindings(ToolAdapter):
    name = "mock-findings"
    description = "mock 产出 verified findings"

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {"type": "object", "properties": {}}

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        return ToolResult(
            summary="1 条命中",
            data={"findings": [{"template": "mock-vuln", "severity": "high", "url": "https://example.com"}]},
        )


def build_registry():
    from camty.adapters.mock import MockGated

    return {
        "mock-subfinder": MockSubfinder(),
        "mock-findings": MockFindings(),
        "mock-gated": MockGated(),
        "report": ReportAdapter(),
    }


def make_project(tmp: str) -> Path:
    root = Path(tmp)
    (root / "packs" / "auto-pack").mkdir(parents=True)
    (root / "packs" / "auto-pack" / "pack.yaml").write_text(yaml.safe_dump(PACK), encoding="utf-8")
    (root / "engagements").mkdir()
    cfg = root / "engagements" / "auto-eng.yaml"
    cfg.write_text(yaml.safe_dump(CFG), encoding="utf-8")
    return cfg


class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_project(self.tmp.name)
        self._engs: list = []

    def tearDown(self):
        for eng in self._engs:
            eng.close()
        self.tmp.cleanup()

    def eng(self) -> Engagement:
        eng = Engagement(self.cfg)
        self._engs.append(eng)
        return eng

    def test_full_auto_chain(self):
        eng = self.eng()
        ok = Orchestrator(eng, build_registry()).run()
        self.assertTrue(ok)
        self.assertEqual(phase_status(eng, PACK["phases"][0]), "done")
        self.assertEqual(phase_status(eng, PACK["phases"][2]), "done")
        self.assertGreaterEqual(len(eng.ledger.findings), 1)
        reports = list((eng.dir).glob("report-*.html"))
        self.assertTrue(reports, "结束应自动生成报告")
        docx = list((eng.dir).glob("report-*.docx"))
        # docx 报告依赖 python-docx；缺它时产 HTML 不产 docx，断言应跟可用性对齐
        try:
            import docx  # noqa: F401
            docx_available = True
        except ImportError:
            docx_available = False
        if docx_available:
            self.assertTrue(docx, "python-docx 可用时应同时出 docx")
        else:
            self.assertEqual(docx, [], "缺 python-docx 时不应生成 docx")

    def test_resume_idempotent(self):
        eng = self.eng()
        Orchestrator(eng, build_registry()).run()
        n_findings = len(eng.ledger.findings)
        ok = Orchestrator(eng, build_registry()).run()  # 二次运行：全部阶段跳过
        self.assertTrue(ok)
        self.assertEqual(len(eng.ledger.findings), n_findings, "已完成阶段跳过不应重复产出")

    def test_gate_blocks_without_evidence(self):
        no_verify = yaml.safe_load(yaml.safe_dump(PACK))
        no_verify["phases"][1]["steps"] = [{"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"}}]
        pack_dir = Path(self.tmp.name) / "packs" / "auto-pack"
        pack_dir.joinpath("pack.yaml").write_text(yaml.safe_dump(no_verify), encoding="utf-8")

        eng = self.eng()
        ok = Orchestrator(eng, build_registry()).run()
        self.assertFalse(ok, "verify 阶段不产 finding 时，exploit 门控应停止整场交战")
        self.assertEqual(phase_status(eng, no_verify["phases"][2]), "pending", "被门控的阶段不应被执行")
        self.assertEqual(phase_status(eng, no_verify["phases"][3]), "pending")
        self.assertEqual(eng.completed_steps("exploit"), {})

        # 补上证据后重跑同命令 → 从断点续，门控放行
        eng.ledger.add("vuln", "https://example.com", "manual-supply", severity="high", verified=True)
        eng.save_state()
        ok = Orchestrator(eng, build_registry()).run()
        self.assertTrue(ok, "证据补齐后重跑应全链通过")
        self.assertEqual(phase_status(eng, no_verify["phases"][2]), "done")

    def test_dry_run_executes_nothing(self):
        eng = self.eng()
        Orchestrator(eng, build_registry()).run(dry_run=True)
        self.assertEqual(eng.completed_steps("recon"), {}, "dry-run 不应执行任何步骤")
        self.assertEqual(len(eng.ledger.findings), 0)
        self.assertFalse(list((eng.dir).glob("report-*.html")), "dry-run 不生成报告")

    def test_gate_check_unit(self):
        eng = self.eng()
        phase = {"id": "x", "gate": {"min_verified_findings": 2}}
        ok, why = gate_check(eng, phase)
        self.assertFalse(ok)
        self.assertIn("verified", why)
        eng.ledger.add("vuln", "a", "d", verified=True)
        eng.ledger.add("vuln", "b", "d", verified=True)
        self.assertTrue(gate_check(eng, phase)[0])
        ctx_gate = {"id": "y", "gate": {"require_context": ["live_hosts"]}}
        self.assertFalse(gate_check(eng, ctx_gate)[0])
        eng.context["live_hosts"] = ["https://a"]
        self.assertTrue(gate_check(eng, ctx_gate)[0])


if __name__ == "__main__":
    unittest.main()
