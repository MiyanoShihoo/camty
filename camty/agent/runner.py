"""双 Runner：DeterministicRunner（固定链，无 LLM）与 AgentRunner（LLM 工具循环）。

断点续跑：每步成功后写入 SQLite（state.db 的 phase_progress），
重跑同命令自动跳过已完成步骤；--rerun 清空该阶段进度重跑。
并发：phase 步骤里可用 `parallel: [step, step]` 组，组内并发执行（上限 4）。
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from camty.adapters.base import ToolResult
from camty.adapters.registry import REGISTRY
from camty.agent.state import Engagement
from camty.guardrail.approval import decide_confirm
from camty.guardrail.rules import check_rules
from camty.guardrail.scope import ScopeError
from camty.knowledge.playbooks import PlaybookLibrary
from camty.llm.router import ROLE_DECIDE, LLMRouter
from camty.tools import ToolUnavailable

TOOL_RESULT_LIMIT = 2000
MAX_PARALLEL = 4


def ingest_assets(eng: Engagement, data: dict) -> None:
    """适配器结构化产出 → 资产图（程序计算父子链，命中 finding 即标记已测）。"""
    assets = getattr(eng, "assets", None)
    if assets is None:
        return
    for sub in data.get("subdomains") or []:
        assets.upsert("subdomain", str(sub), source="runner")
    for site in data.get("live_sites") or []:
        assets.upsert("service", site.get("url", ""), source="runner")
    for host in data.get("live_hosts") or []:
        assets.upsert("host", str(host), source="runner")
    for ep in data.get("endpoints") or []:
        value = ep.get("endpoint", "") if isinstance(ep, dict) else str(ep)
        if value:
            assets.upsert("endpoint", value, source="runner")
    for f in data.get("findings") or []:
        assets.mark_tested(f.get("url", ""))
    for key in ("hosts", "targets"):
        for host in data.get(key) or []:
            assets.mark_tested(str(host))


def _merge_result(eng: Engagement, result: ToolResult,
                  derived_from: list[str] | None = None) -> None:
    eng.context.update(result.data)
    ingest_assets(eng, result.data)
    for f in result.data.get("findings", []) or []:
        eng.ledger.add(
            kind="vuln",
            target=f.get("url", ""),
            detail=f.get("template", ""),
            severity=f.get("severity", "info"),
            evidence=result.evidence,
            verified=f.get("verified", True),  # 模式审计类可自带 verified=False 待复核
            derived_from=derived_from,
        )


def _gate_finding(adapter, args: dict, ledger) -> str | None:
    """利用级动作门控：args 必须引用台账 verified finding。放行返回 None。"""
    if not getattr(adapter, "requires_finding", False):
        return None
    fid = str(args.get("finding_id", "")).strip()
    if fid and fid in ledger.verified_ids():
        return None
    verified = sorted(ledger.verified_ids())
    return (
        f"门控拒绝：{adapter.name} 是利用级动作，参数必须包含 finding_id 且引用台账中已验证的 finding。"
        f"当前已验证: {verified if verified else '（无）'}。先跑验证类阶段产出证据。"
    )


def _resolve_args(spec: dict, context: dict) -> dict:
    out = {}
    for key, value in spec.items():
        if isinstance(value, str):
            inner = value[1:-1] if value.startswith("{") and value.endswith("}") else None
            if inner is not None and "{" not in inner and "}" not in inner:
                if inner not in context:
                    raise RuntimeError(f"上下文缺少变量 {inner}（用 --var key=value 注入或检查步骤依赖顺序）")
                out[key] = context[inner]
            else:
                try:
                    out[key] = value.format(**context)
                except KeyError as exc:
                    raise RuntimeError(f"上下文缺少变量 {exc}，检查 pack 步骤依赖顺序") from exc
        else:
            out[key] = value
    return out


def _matched_playbook_hints(eng: Engagement, library: PlaybookLibrary, injected: set[str]) -> list[str]:
    """按指纹/服务命中战术手册，未注入过的返回提示文本。"""
    hints = []
    hits = library.match_tech(eng.context.get("tech_map") or {})
    hits += library.match_service(eng.context.get("services") or [])
    hits += library.match_findings([f.__dict__ for f in eng.ledger.findings])
    for pb in hits:
        if pb["name"] not in injected:
            injected.add(pb["name"])
            hints.append(PlaybookLibrary.as_prompt(pb))
    return hints


class DeterministicRunner:
    def __init__(self, eng: Engagement, registry: dict | None = None, router: LLMRouter | None = None):
        self.eng = eng
        self.registry = registry or REGISTRY
        self.router = router  # model 审批模式用

    def _confirm(self, name: str, args: dict) -> bool:
        adapter = self.registry.get(name)
        proceed, mode, note = decide_confirm(self.eng, adapter, args, self.router)
        if not proceed:
            self.eng.audit.record(name, args, ok=False, note=f"approval[{mode}]: {note}")
        return proceed

    def _run_single(self, step: dict) -> dict:
        name = step["adapter"]
        adapter = self.registry.get(name)
        if adapter is None:
            raise KeyError(f"适配器未实现: {name}")
        args = _resolve_args(step.get("args", {}), self.eng.context)
        if getattr(adapter, "requires_finding", False) and "finding_id" not in args:
            latest = [f for f in self.eng.ledger.findings if f.verified]
            if not latest:
                raise RuntimeError(
                    f"门控拒绝：{name} 是利用级动作，台账无 verified finding，先跑验证类阶段产出证据"
                )
            args = {**args, "finding_id": latest[-1].id}
            print(f"[门控] {name} 自动引用最新 verified finding: {args['finding_id']}")
        gate = _gate_finding(adapter, args, self.eng.ledger)
        if gate:
            raise RuntimeError(gate)
        rule = check_rules(self.eng.cfg, name, args)
        if rule:
            self.eng.audit.record(name, args, ok=False, note=f"rule-deny: {rule}")
            raise RuntimeError(f"规则门拒绝: {rule}")
        if step.get("confirm", False) and not self._confirm(name, args):
            raise RuntimeError("operator 拒绝")
        result = adapter.run(args, self.eng.ctx)
        _merge_result(
            self.eng, result,
            derived_from=[args["finding_id"]] if args.get("finding_id") else None,
        )
        print(f"[完成] {name}: {result.summary}（证据: {result.evidence}）")
        return {"summary": result.summary, "data": result.data, "evidence": result.evidence}

    def run(self, phase_id: str, dry_run: bool = False, rerun: bool = False) -> None:
        phase = self.eng.phase(phase_id)
        print(
            f"=== 交战 {self.eng.name} | 场景包 {self.eng.pack['name']} | "
            f"阶段 {phase_id} - {phase.get('title', '')}"
        )
        if rerun:
            self.eng.clear_phase(phase_id)
        done = self.eng.completed_steps(phase_id)
        missing: list[str] = []
        library = PlaybookLibrary()
        for idx, step in enumerate(phase.get("steps", [])):
            group = step.get("parallel") if isinstance(step, dict) else None
            entries = group if group is not None else [step]

            if dry_run:
                for e in entries:
                    name = e["adapter"]
                    adapter = self.registry.get(name)
                    if adapter is None:
                        missing.append(name)
                        print(f"[跳过] {name}: 适配器未实现（按 packs 标注的里程碑交付）")
                        continue
                    ok = adapter.available()
                    print(f"[dry-run] {name}({'工具可用' if ok else '工具未安装'}) 参数: {e.get('args', {})}")
                    if not ok:
                        missing.append(name)
                continue

            if idx in done:
                print(f"[断点] 步骤 {idx}（{entries[0].get('adapter', 'parallel')}）已完成({done[idx]})，跳过")
                continue

            if group is not None and len(group) > 1:
                for e in group:
                    if e.get("confirm", False) and not self.eng.cfg.get("auto_confirm", False):
                        e_args = _resolve_args(e.get("args", {}), self.eng.context)
                        if not self._confirm(e["adapter"], e_args):
                            print("[中止] operator 拒绝，本阶段停止")
                            return
                with ThreadPoolExecutor(max_workers=min(len(group), MAX_PARALLEL)) as pool:
                    futures = {e["adapter"]: pool.submit(self._run_single, e) for e in group}
                    errors = []
                    for adapter_name, fut in futures.items():
                        try:
                            fut.result()
                        except Exception as exc:  # noqa: BLE001 - 单步骤失败不拖垮其它并发分支
                            errors.append((adapter_name, str(exc)))
                for adapter_name, err in errors:
                    print(f"[失败] {adapter_name}: {err}")
                if errors:
                    print("[中止] 并发组存在失败，断点保留；修复后重跑同命令续跑")
                    return
            else:
                try:
                    self._run_single(entries[0])
                except KeyError as exc:
                    missing.append(entries[0]["adapter"])
                    print(f"[跳过] {exc}")
                    self.eng.mark_step(phase_id, idx, "skipped")
                    continue
                except RuntimeError as exc:
                    print(f"[中止] {exc}")
                    return
            self.eng.mark_step(phase_id, idx, "done")
            self.eng.save_state()
            for hint in _matched_playbook_hints(self.eng, library, set()):
                print(f"[playbook] {hint.splitlines()[0]}")

        if missing:
            print(f"[提示] 缺失: {', '.join(sorted(set(missing)))}")
        self.eng.save_state()
        print(f"=== 阶段结束，台账:\n{self.eng.ledger.summary()}")


class AgentRunner:
    SYSTEM_PROMPT = """你是红队交战工作台的执行智能体，工作在一次已授权的渗透交战中。
规则：
1. evidence-first：只依据工具返回的摘要与台账判断，不臆测；未验证的猜想先验证再下结论。
2. 范围外目标引擎会强制拦截，不要尝试绕过。
3. 利用类动作必须引用台账中 verified finding 的 ID，否则引擎会拒绝。
4. 阶段目标：{goal}
5. 目标达成或无更多有效动作时，直接输出总结文本，不再调用工具。

当前证据台账：
{ledger}
"""

    def __init__(self, eng: Engagement, router: LLMRouter, registry: dict | None = None):
        self.eng = eng
        self.router = router
        self.registry = registry or REGISTRY
        self._injected_playbooks: set[str] = set()

    def _tool_content(self, payload: dict) -> str:
        text = json.dumps(payload, ensure_ascii=False)
        if len(text) > TOOL_RESULT_LIMIT:
            text = text[:TOOL_RESULT_LIMIT] + "...(截断，全文见证据文件)"
        return text

    def _operator_confirm(self, adapter, args: dict) -> bool:
        proceed, mode, note = decide_confirm(self.eng, adapter, args, self.router)
        if not proceed:
            self.eng.audit.record(adapter.name, args, ok=False, note=f"approval[{mode}]: {note}")
        return proceed

    def run(self, phase_id: str, max_steps: int = 30) -> None:
        from camty.agent.blackboard import Blackboard, ledger_digest
        from camty.agent.goals import constraints_prompt

        phase = self.eng.phase(phase_id)
        tools = [a.tool_def() for a in self.registry.values() if a.available()]
        if not tools:
            print("[停止] 没有可用工具（未安装），先安装工具或用 DeterministicRunner")
            return
        tools.append({
            "type": "function",
            "function": {
                "name": "blackboard-note",
                "description": "把持久观察写入黑板（后续所有阶段与规划轮共享）",
                "parameters": {"type": "object",
                               "properties": {"kind": {"type": "string"},
                                               "note": {"type": "string"}},
                               "required": ["kind", "note"]},
            },
        })
        system_prompt = self.SYSTEM_PROMPT.format(
            goal=phase.get("goal", ""), ledger=ledger_digest(self.eng))
        constraints = constraints_prompt(self.eng.cfg)
        blackboard = Blackboard(self.eng).summary()
        if blackboard:
            system_prompt += f"\n{blackboard}\n"
        if constraints:
            system_prompt += f"\n{constraints}\n"
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    f"交战目标: {self.eng.context.get('root_domain', self.eng.context.get('target_cidr', '(未配置)'))}\n"
                    f"开始执行阶段 {phase_id} - {phase.get('title', '')}。"
                ),
            },
        ]
        library = PlaybookLibrary()
        for _ in range(max_steps):
            resp = self.router.chat(ROLE_DECIDE, messages, tools)
            messages.append(
                {"role": "assistant", "content": resp["content"], "tool_calls": resp["tool_calls"]}
            )
            if not resp["tool_calls"]:
                print(resp["content"])
                break
            for tc in resp["tool_calls"]:
                if tc["name"] == "blackboard-note":
                    kind = str(tc["arguments"].get("kind", "lesson")).strip()[:40] or "lesson"
                    note = str(tc["arguments"].get("note", "")).strip()
                    if note:
                        Blackboard(self.eng).add(kind, note, source="agent-runner")
                        print(f"[blackboard] [{kind}] {note[:60]}")
                    content = self._tool_content(
                        {"ok": bool(note), "message": "已写入黑板" if note else "note 不能为空"})
                    messages.append({"role": "tool", "tool_call_id": tc["id"], "content": content})
                    continue
                adapter = self.registry.get(tc["name"])
                if adapter is None:
                    content = self._tool_content({"error": f"未知工具 {tc['name']}"})
                elif (gate := _gate_finding(adapter, tc["arguments"], self.eng.ledger)):
                    content = self._tool_content({"error": gate})
                    self.eng.audit.record(tc["name"], tc["arguments"], ok=False, note="finding-gate 拒绝")
                elif (rule := check_rules(self.eng.cfg, tc["name"], tc["arguments"])):
                    content = self._tool_content({"error": f"规则门拒绝: {rule}"})
                    self.eng.audit.record(tc["name"], tc["arguments"], ok=False, note=f"rule-deny: {rule}")
                elif adapter.requires_confirm and not self._operator_confirm(adapter, tc["arguments"]):
                    content = self._tool_content({"error": "审批拒绝执行该动作"})
                else:
                    try:
                        result = adapter.run(tc["arguments"], self.eng.ctx)
                        _merge_result(
                            self.eng, result,
                            derived_from=[tc["arguments"]["finding_id"]]
                            if tc["arguments"].get("finding_id") else None,
                        )
                        content = self._tool_content(
                            {"summary": result.summary, "data": result.data, "evidence": result.evidence}
                        )
                        print(f"[工具] {tc['name']}: {result.summary}")
                        for hint in _matched_playbook_hints(self.eng, library, self._injected_playbooks):
                            messages.append({"role": "user", "content": hint})
                            print(f"[playbook] {hint.splitlines()[0]}")
                    except ScopeError as exc:
                        content = self._tool_content({"error": f"范围拦截: {exc}"})
                        self.eng.audit.record(tc["name"], tc["arguments"], ok=False, note=f"scope: {exc}")
                    except ToolUnavailable as exc:
                        content = self._tool_content({"error": str(exc)})
                    except Exception as exc:  # noqa: BLE001 - 单工具失败不终止循环
                        content = self._tool_content({"error": str(exc)})
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": content})
        else:
            print(f"[停止] 达到 max_steps={max_steps}")
        self.eng.save_state()
        print(f"=== 阶段结束，台账:\n{self.eng.ledger.summary()}")
