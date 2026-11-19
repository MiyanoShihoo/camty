"""交战级编排器：一条命令全自动从侦察打到报告。

- 阶段按场景包顺序执行；确定性模式跑固定链，--agent 模式阶段内由 LLM 决策
- 阶段门控由引擎强制（证据不足自动停在利用类阶段之前）：
    gate:
      min_verified_findings: 1    # 台账 verified 数下限
      require_context: [live_hosts]  # 上下文必备变量
- 断点续跑：整交战可中断重跑，已完成阶段自动跳过，半完成阶段从断点继续
- 结束自动生成报告（HTML + docx，若 python-docx 可用）
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from camty.agent.runner import AgentRunner, DeterministicRunner
from camty.agent.state import Engagement


def phase_status(eng: Engagement, phase: dict) -> str:
    """pending（未开始）| partial（进行中断点续跑）| done（全部步骤完成/跳过）。"""
    steps = phase.get("steps", [])
    if not steps:
        return "done"
    done = eng.completed_steps(phase["id"])
    statuses = [done.get(i) for i in range(len(steps))]
    if all(s in ("done", "skipped") for s in statuses):
        return "done"
    if any(statuses):
        return "partial"
    return "pending"


def gate_check(eng: Engagement, phase: dict) -> tuple[bool, str]:
    gate = phase.get("gate") or {}
    min_findings = int(gate.get("min_verified_findings", 0))
    verified = sum(1 for f in eng.ledger.findings if f.verified)
    if verified < min_findings:
        return False, f"门控要求 ≥{min_findings} 个 verified finding（当前 {verified}），证据不足"
    for key in gate.get("require_context") or []:
        if not eng.context.get(key):
            return False, f"门控要求上下文变量 {key}（前置阶段未产出），证据不足"
    return True, ""


class Orchestrator:
    def __init__(self, eng: Engagement, registry: dict | None = None, router=None):
        self.eng = eng
        self.registry = registry
        self.router = router

    def run(self, dry_run: bool = False, rerun: bool = False, agent: bool = False,
            plan: bool = False) -> bool:
        if plan:
            from camty.agent.planner import Planner

            ok = Planner(self.eng, self.registry).run(dry_run=dry_run, rerun=rerun)
            if not dry_run:
                self._finish()
            return ok
        phases = self.eng.pack["phases"]
        print(
            f"=== 全自动交战 {self.eng.name} | 场景包 {self.eng.pack['name']} "
            f"| {len(phases)} 阶段 | 模式: {'Agent 决策' if agent else '确定性链'}"
        )
        stopped_at = None
        for phase in phases:
            pid, title = phase["id"], phase.get("title", "")
            status = phase_status(self.eng, phase)
            if status == "done" and not rerun:
                print(f"[跳过] 阶段 {pid} - {title}（已完成）")
                continue
            ok, why = gate_check(self.eng, phase)
            if not ok and not dry_run:
                print(f"[停止] 阶段 {pid} - {title}：{why}")
                print("[说明] 引擎门控拒绝继续。先跑验证类阶段产出 verified finding，重跑本命令即从断点续。")
                stopped_at = pid
                break
            if dry_run:
                state = "门控通过" if ok else f"门控待满足（{why}）——前置产出到位后放行"
                print(f"[auto/dry-run] 阶段 {pid} - {title}：{state}，{len(phase.get('steps', []))} 步骤")
                continue
            if rerun:
                self.eng.clear_phase(pid)
            if agent:
                if self.router is None:
                    raise SystemExit("--agent 需要 LLM 配置（python -m camty keys set）")
                AgentRunner(self.eng, self.router, self.registry).run(pid)
            else:
                DeterministicRunner(self.eng, self.registry).run(pid, rerun=False)
        if not dry_run:
            self._finish()
        return stopped_at is None

    def _finish(self) -> None:
        from camty.report import write_report

        report = write_report(self.eng)
        print(f"[报告] {report}")
        try:
            from camty.report import write_docx

            print(f"[报告] {write_docx(self.eng)}")
        except ImportError:
            pass
        counts = Counter(f.severity for f in self.eng.ledger.findings)
        verified = sum(1 for f in self.eng.ledger.findings if f.verified)
        print(
            f"=== 交战结束：发现 {len(self.eng.ledger.findings)} 项（已验证 {verified}），"
            f"severity 分布 {dict(counts) or '无'}"
        )
        print("=== 台账:")
        print(self.eng.ledger.summary())
