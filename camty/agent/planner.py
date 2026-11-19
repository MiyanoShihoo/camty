"""攻击树规划器 v2：依赖图动态选步，并行批次 + 优先级 + 预算。

pack 的 `plan:` 段声明候选步骤：
    - adapter / args / confirm 同 phase 步骤
    - requires: 前置条件，写法
        "context_key"          → 上下文变量已存在（前置步骤产出）
        "finding:模式串"        → 台账存在 template 含模式串的 verified finding
        "findings:模式串:N"     → 至少 N 个匹配的 verified finding
        "severity:high"        → 存在该 severity 的 verified finding
    - requires_any: [条件...]  → 任一满足即放行（与 requires 全满足 AND 组合）
    - priority: N              → 同批并行执行无顺序差异，仅影响批内排序展示
    - terminal: true           → 终态步骤（如 report 自动终态）：仅当无其它
                                 非终态步骤 ready 时执行，objective 提前收束时跳过
    - provides: 该步产出（文档性说明，产出本身由 data merge 进上下文）

v2 与 v1 的区别：
- 每轮把 ready 的非终态、非 confirm 步骤作为一批并行执行（上限 max_parallel=4）；
  confirm 步骤串行执行（避免并发交互式确认打架）
- plan_budget: 交战配置最大执行步数（默认 100），超出即收束
- 遍历规则：ready = 未执行且前置全满足；执行后重算，直到无新执行
- requires 永不满足的分支自动剪枝；objective 达成即收束（终态步骤不补跑）
- 断点续跑：plan 步骤按索引记录在 phase_progress（phase_id = "plan"）
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from camty.agent.state import Engagement

PLAN_PHASE_ID = "plan"
DEFAULT_BUDGET = 100
MAX_PARALLEL = 4


def _finding_matches(eng: Engagement, pattern: str) -> int:
    """匹配 pattern 的 verified finding 数量。空模式匹配全部。"""
    pat = pattern.lower()
    return sum(
        1 for f in eng.ledger.findings
        if f.verified and pat in f.detail.lower()
    )


def _requirement_met(eng: Engagement, req: str) -> bool:
    if req.startswith("finding:"):
        pattern = req[len("finding:"):]
        return _finding_matches(eng, pattern) >= 1
    if req.startswith("findings:"):
        _, pattern, count = req.split(":", 2)
        return _finding_matches(eng, pattern) >= int(count)
    if req.startswith("severity:"):
        sev = req[len("severity:"):].lower()
        return any(f.verified and f.severity == sev for f in eng.ledger.findings)
    return bool(eng.context.get(req))


def _is_terminal(step: dict) -> bool:
    """report 适配器自动终态；任意步骤可显式 terminal: true。"""
    return bool(step.get("terminal", False)) or step.get("adapter") == "report"


def _step_priority(step: dict) -> int:
    return int(step.get("priority", 0))


def _step_ready(eng: Engagement, step: dict) -> bool:
    if not all(_requirement_met(eng, req) for req in step.get("requires") or []):
        return False
    any_reqs = step.get("requires_any") or []
    if any_reqs and not any(_requirement_met(eng, req) for req in any_reqs):
        return False
    return True


def ready(eng: Engagement, steps: list[dict], done: dict[int, str]) -> list[int]:
    """可执行步骤索引（调用方自行分流并行批/终态/confirm）。"""
    out = []
    for idx, step in enumerate(steps):
        if idx in done:
            continue
        if _step_ready(eng, step):
            out.append(idx)
    return out


def objective_met(eng: Engagement, objective: dict | None) -> tuple[bool, str]:
    if not objective:
        return False, ""
    min_findings = int(objective.get("min_verified_findings", 0))
    verified = sum(1 for f in eng.ledger.findings if f.verified)
    if min_findings and verified >= min_findings:
        return True, f"verified findings ≥ {min_findings}（当前 {verified}）"
    for key in objective.get("context_keys") or []:
        if eng.context.get(key):
            return True, f"context key {key} 已产出"
    return False, ""


class Planner:
    def __init__(self, eng: Engagement, registry: dict | None = None):
        self.eng = eng
        from camty.adapters.registry import REGISTRY

        self.registry = registry or REGISTRY

    def _run_batch(self, runner, steps: list[dict], indices: list[int],
                   done: dict[int, str]) -> bool:
        """并行执行一批非 confirm 步骤。返回 False 表示需要中止。"""
        print(f"[plan] 执行批 {len(indices)} 步: {[steps[i]['adapter'] for i in indices]}")
        with ThreadPoolExecutor(max_workers=min(len(indices), MAX_PARALLEL)) as pool:
            futures = {i: pool.submit(runner._run_single, steps[i]) for i in indices}
            aborted = False
            for idx, fut in futures.items():
                try:
                    fut.result()
                    done[idx] = "done"
                    self.eng.mark_step(PLAN_PHASE_ID, idx, "done")
                except KeyError as exc:
                    print(f"[plan] 剪枝 {steps[idx]['adapter']}: {exc}")
                    done[idx] = "skipped"
                    self.eng.mark_step(PLAN_PHASE_ID, idx, "skipped")
                except RuntimeError as exc:
                    print(f"[plan] 中止：{steps[idx]['adapter']}: {exc}")
                    aborted = True
        return not aborted

    def _run_one(self, runner, step: dict, idx: int, done: dict[int, str]) -> str:
        """串行执行单步（confirm/终态步）。返回 done|skipped|aborted。"""
        try:
            runner._run_single(step)
            done[idx] = "done"
            self.eng.mark_step(PLAN_PHASE_ID, idx, "done")
            return "done"
        except KeyError as exc:
            print(f"[plan] 剪枝 {step['adapter']}: {exc}")
            done[idx] = "skipped"
            self.eng.mark_step(PLAN_PHASE_ID, idx, "skipped")
            return "skipped"
        except RuntimeError as exc:
            print(f"[plan] 中止：{exc}")
            return "aborted"

    def run(self, dry_run: bool = False, rerun: bool = False) -> bool:
        from camty.agent.runner import DeterministicRunner

        steps = self.eng.pack.get("plan") or []
        if not steps:
            raise KeyError(f"场景包 {self.eng.pack['name']} 无 plan: 段（--plan 需要依赖图声明）")
        if rerun:
            self.eng.clear_phase(PLAN_PHASE_ID)
        done = self.eng.completed_steps(PLAN_PHASE_ID)
        runner = DeterministicRunner(self.eng, self.registry)
        objective = self.eng.cfg.get("objective")
        budget = int(self.eng.cfg.get("plan_budget", DEFAULT_BUDGET))
        executed = 0

        print(
            f"=== 攻击树规划 {self.eng.name} | 场景包 {self.eng.pack['name']} | "
            f"{len(steps)} 候选步骤 | objective: {objective or '（未声明，尽力遍历）'} | "
            f"预算 {budget} 步"
        )
        while True:
            if dry_run:
                for idx, step in enumerate(steps):
                    status = "已执行" if idx in done else (
                        "ready" if _step_ready(self.eng, step) else "前置未满足")
                    print(f"[plan/dry-run] {step['adapter']}: {status}")
                return True
            if executed >= budget:
                met, why = objective_met(self.eng, objective)
                print(f"[plan] 预算耗尽收束（{executed} 步）："
                      f"objective {'达成（' + why + '）' if met else '未达成'}")
                break
            ready_idx = ready(self.eng, steps, done)
            if not ready_idx:
                met, why = objective_met(self.eng, objective)
                state = f"objective 达成（{why}）" if met else "无 ready 步骤（依赖不满足，分支已剪枝）"
                print(f"[plan] 遍历完成：{state}")
                break
            # 分流：非终态非 confirm 并行批 > confirm 串行 > 终态（report 类）串行
            batch = [i for i in ready_idx
                     if not _is_terminal(steps[i]) and not steps[i].get("confirm", False)]
            confirms = [i for i in ready_idx
                         if not _is_terminal(steps[i]) and steps[i].get("confirm", False)]
            terminals = [i for i in ready_idx if _is_terminal(steps[i])]
            if batch:
                batch.sort(key=lambda i: -_step_priority(steps[i]))
                take = min(len(batch), budget - executed)
                batch = batch[:take]
                if len(batch) > 1:
                    if not self._run_batch(runner, steps, batch, done):
                        return False
                    executed += len(batch)
                else:
                    outcome = self._run_one(runner, steps[batch[0]], batch[0], done)
                    if outcome == "aborted":
                        return False
                    if outcome == "done":
                        executed += 1
            elif confirms:
                idx = confirms[0]
                outcome = self._run_one(runner, steps[idx], idx, done)
                if outcome == "aborted":
                    return False
                if outcome == "done":
                    executed += 1
            else:
                idx = terminals[0]
                outcome = self._run_one(runner, steps[idx], idx, done)
                if outcome == "aborted":
                    return False
                if outcome == "done":
                    executed += 1
            met, why = objective_met(self.eng, objective)
            if met:
                print(f"[plan] objective 达成，提前收束：{why}")
                break
        executed_names = [s["adapter"] for i, s in enumerate(steps) if done.get(i) == "done"]
        skipped = [s["adapter"] for i, s in enumerate(steps) if done.get(i) == "skipped"]
        print(f"[plan] 执行 {len(executed_names)} 步 {executed_names}；剪枝 {len(skipped)} 步 {skipped}")
        return True


def _requirement_met_all(eng: Engagement, step: dict) -> bool:
    return _step_ready(eng, step)
