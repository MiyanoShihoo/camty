"""多 agent 引擎：planner → frontier 意图 → N worker 并行 → 写回双图 → 重规划。

ARTEX 引擎语义的 Camty 落地（单进程线程池实现，无外部依赖）：
- planner 是唯一意图生成者：LLM 模式按态势生成/更新共享 todolist；确定性模式
  从 pack plan: 段派生 todolist。todolist 按依赖跨轮逐步 spawn 意图（稳定攻击链）。
- worker 领一条意图执行：LLM 模式是有界工具循环（含跨意图过程检索 search-traces）；
  确定性模式直接跑 plan 步骤。写回 fact/finding/资产 → 意图 done/blocked。
- 每批 worker 排空后重规划，objective 达成/预算耗尽/无 ready 即收束。
- 全程 activity 落库（过程级信息交换），血缘边（spawns/yields/proves）进探索图。
"""

from __future__ import annotations

import json
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from camty.adapters.base import ToolResult
from camty.adapters.registry import REGISTRY
from camty.agent.explore import ExplorationGraph, Todolist
from camty.agent.runner import (
    _gate_finding,
    _merge_result,
    TOOL_RESULT_LIMIT,
)
from camty.agent.state import Engagement
from camty.guardrail.approval import decide_confirm
from camty.guardrail.rules import check_rules
from camty.llm.router import ROLE_DECIDE
from camty.tools import ToolUnavailable

DEFAULT_WORKERS = 4
DEFAULT_TOTAL_BUDGET = 80
PER_INTENT_STEPS = 12
PLAN_TIMEOUT = 150.0    # 规划调用超时：reasoning 模型长 prompt 实测 >45s（onyx-ai 实战校准）
WORKER_TIMEOUT = 120.0  # worker 单次 LLM 调用超时
MAX_PLAN_FAILURES = 3   # 规划连续失败次数 → 降级 pack 确定性模式
MAX_RESPAWN = 2         # 同一 item 重复派意图上限 → 死循环检测

PLANNER_SYSTEM = """你是渗透交战的规划者（planner）。基于当前态势维护攻击链 todolist。

规则：
1. 只输出 JSON，无其它文本
2. todolist 是完整列表（含已完成项），item_id 稳定复用（T1、T2…）
3. 串行利用链用 depends_on 表达；侦察类无依赖项并行
4. 已被台账 verified finding 满足的步骤标 done；被证伪/无法推进的标 blocked
5. 新步骤只加有真实攻击价值的；宁少勿滥

输出格式：
{"todolist": [{"item_id": "T1", "title": "枚举子域", "depends_on": [], "status": "pending", "note": ""}],
 "spawn": ["T2"]}
spawn 列出本轮要派执行的 item_id（其前置必须已 done）。"""

WORKER_SYSTEM = """你是红队交战的执行 worker，负责完成一条意图。
规则：
1. evidence-first：只依据工具返回判断，不臆测
2. 范围外目标引擎会拦截，不要尝试绕过
3. 利用类动作必须引用台账中 verified finding 的 ID
4. 意图完成（产出 evidence/fact）或无有效动作时输出总结文本，不再调用工具
5. 完成判定必须锚定客观证据：你声称"偷到会话/读到文件/拿到权限"的唯一合法依据
   是工具返回中真实出现了该证据（如 exploit server 访问日志里出现目标 cookie、
   响应体中出现文件内容、响应状态发生实际变化）。证据不存在时，总结必须如实
   声明"未达成/未验证"并描述卡点——自述成功而无证据会被引擎复核判 blocked 并重派。
6. 结束总结的最后一行必须是判定标记：意图目标达成写 [RESULT: 成功]，
   尝试了但未达成写 [RESULT: 失败]。"确认无此漏洞"类侦察结论属成功。
   引擎按标记机械判定——无标记按失败处理，诚实报告失败会获得重派机会。

意图：{intent}
相关上下文：{payload}
当前台账：
{ledger}
"""


def _parse_json_content(content: str) -> dict | None:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None


class Engine:
    def __init__(self, eng: Engagement, router=None, registry: dict | None = None,
                 n_workers: int = DEFAULT_WORKERS,
                 max_total_steps: int = DEFAULT_TOTAL_BUDGET):
        self.eng = eng
        self.router = router
        self.registry = registry or REGISTRY
        # MCP 工具源：交战配置 mcp_servers → 发现并入本引擎 registry（不污染全局）
        if eng.cfg.get("mcp_servers"):
            merged = dict(self.registry)
            from camty import mcpbridge

            mcpbridge.attach(eng.cfg, merged)
            self.registry = merged
        self.n_workers = n_workers
        self.max_total_steps = max_total_steps
        self.graph = ExplorationGraph(eng)
        self.todolist = Todolist(eng)
        self._claim_lock = threading.Lock()
        self._steps = 0
        self._plan_failures = 0     # 连续失败计数（降级阈值）
        self._spawn_counts: dict[str, int] = {}  # 死循环检测：item 重派次数

    # ---- 生命周期 ----

    def run(self) -> bool:
        goal = self._ensure_goal()
        print(f"=== 多 agent 引擎 {self.eng.name} | goal: {goal['title'][:80]} | "
              f"workers: {self.n_workers} | 预算 {self.max_total_steps} 步")
        rounds = 0
        while self._steps < self.max_total_steps:
            rounds += 1
            try:
                spawned = self._plan_round(goal)
            except KeyError as exc:
                # LLM 不可用且 pack 无确定性计划：无规划来源，优雅收束
                print(f"[engine] 无可用规划来源（LLM 失败且 {exc}），收束")
                break
            done = self._drain_workers(goal)
            if not done and not spawned:
                if self.router is not None and self._plan_failures >= 1:
                    if self._plan_failures < MAX_PLAN_FAILURES:
                        # 限流类失败退避重试（15s×次数），避免打在限流窗口上（crouter 实战校准）
                        backoff = 15.0 * self._plan_failures
                        print(f"[plan] 规划失败退避 {backoff:.0f}s 后重试"
                              f"（{self._plan_failures}/{MAX_PLAN_FAILURES}）")
                        time.sleep(backoff)
                        continue
                    self.router = None
                    print(f"[plan] 规划连续失败 {MAX_PLAN_FAILURES} 次，引擎降级 pack 确定性模式")
                    continue
                break
            if self._objective_met(goal):
                pending_items = [i for i in self.todolist.items() if i["status"] == "pending"]
                blocked_items = [i for i in self.todolist.items() if i["status"] == "blocked"]
                if not pending_items and blocked_items:
                    print(f"[engine] 无可推进项（{len(blocked_items)} 步 blocked），收束")
                else:
                    print("[engine] objective 达成，收束")
                break
        self._print_summary()
        return self._objective_met(goal)

    def _ensure_goal(self) -> dict:
        overview = self.graph.overview()
        existing = overview.get("goal")
        if existing:
            return existing
        objective = self.eng.cfg.get("objective") or {}
        title = objective.get("title") or self.eng.pack.get("title", "") or self.eng.name
        goal_id = self.graph.add_node("goal", title, payload=objective)
        return {"node_id": goal_id, "kind": "goal", "title": title, "status": "pending"}

    def _objective_met(self, goal: dict) -> bool:
        from camty.agent.planner import objective_met as check

        objective = self.eng.cfg.get("objective")
        met, why = check(self.eng, objective)
        if not met:
            # 目标节点自身完成（全 todolist done 且无 pending intent）
            pending = self.graph.intents_pending()
            ready = self.todolist.ready_items()
            if not pending and not ready and self.todolist.items():
                # 仅全部条目 done 才算达成——受阻项 ≠ 完成（F-012 误判修复）
                return all(i["status"] == "done" for i in self.todolist.items())
        return met

    # ---- 规划 ----

    def _plan_round(self, goal: dict) -> int:
        """更新 todolist 并为 ready 未派意图项生成 intent。返回本轮 spawn 数。"""
        if self.router is not None:
            self._llm_plan(goal)
        else:
            self._pack_plan(goal)
        spawned = 0
        for item in self.todolist.ready_items():
            item_id = item["item_id"]
            if item.get("intent_id"):
                continue
            # 死循环检测：同一 item 反复重派（LLM 把 blocked/pending 状态来回翻）→ 强制封死
            count = self._spawn_counts.get(item_id, 0)
            if count >= MAX_RESPAWN:
                self.todolist.mark(item_id, "blocked", note=f"重复派意图 {count} 次超限，判死循环")
                print(f"[plan] 死循环检测：{item_id} 重派 {count} 次，标 blocked")
                continue
            payload = {"item_id": item_id, "title": item["title"], "note": item.get("note", "")}
            intent_id = self.graph.add_node("intent", item["title"], payload=payload)
            self.graph.link(goal["node_id"], intent_id, "spawns")
            self.todolist.mark(item_id, "pending", note=item.get("note", ""))
            self._set_item_intent(item_id, intent_id)
            self._spawn_counts[item_id] = count + 1
            spawned += 1
            print(f"[plan] 派意图 {intent_id}: {item['title']}")
        return spawned

    def _llm_plan(self, goal: dict) -> None:
        from camty.agent.blackboard import Blackboard, ledger_digest
        from camty.agent.goals import constraints_prompt
        from camty.guardrail.steer import as_prompt, take_pending

        steer_notes = take_pending(self.eng)
        blackboard = Blackboard(self.eng).summary()
        mission = str((self.eng.cfg.get("objective") or {}).get("mission", ""))
        prompt = (
            (as_prompt(steer_notes) + "\n" if steer_notes else "")
            + f"交战目标: {goal['title']}\n"
            + ("任务全文:\n" + mission[:900] + "\n" if mission else "")
            + f"资产覆盖: {self.eng.assets.summary()}\n"
            f"台账:\n{ledger_digest(self.eng)}\n"
            f"当前 todolist:\n{self.todolist.summary()[:1000]}\n"
            f"探索图态势: {json.dumps(self.graph.overview()['counts'], ensure_ascii=False)}\n"
            + (f"{blackboard}\n" if blackboard else "")
            + (f"\n{constraints_prompt(self.eng.cfg)}\n"
               if constraints_prompt(self.eng.cfg) else "")
        )
        try:
            resp = self.router.chat(ROLE_DECIDE, [
                {"role": "system", "content": PLANNER_SYSTEM},
                {"role": "user", "content": prompt},
            ], None, timeout=PLAN_TIMEOUT)
            data = _parse_json_content(resp.get("content", "") or "")
            if not data or "todolist" not in data:
                raise ValueError("todolist 缺失")
        except Exception as exc:  # noqa: BLE001 - 只计数；降级决策在 run 循环（那里才能 continue 进 pack）
            self._plan_failures += 1
            print(f"[plan] LLM 规划失败（{self._plan_failures}/{MAX_PLAN_FAILURES}，"
                  f"沿用现有 todolist）: {exc}")
            return
        self._plan_failures = 0
        existing = {i["item_id"]: i for i in self.todolist.items()}
        merged = []
        for item in data["todolist"]:
            item_id = str(item.get("item_id", "")).strip()
            title = str(item.get("title", "")).strip()
            if not item_id or not title:
                continue
            prev = existing.get(item_id, {})
            merged.append({
                "item_id": item_id,
                "title": title,
                "depends_on": [str(d) for d in item.get("depends_on") or []],
                "status": str(item.get("status", prev.get("status", "pending"))),
                "intent_id": prev.get("intent_id"),
                "note": str(item.get("note", prev.get("note", ""))),
            })
        # BUG-10 守卫：规划者不得把 worker 判 blocked 的项翻成 done——
        # done 的唯一合法来源是 worker 的 [RESULT: 成功] 标记（防规划者
        # 幻觉状态越权推翻一线执行判定）
        for item in merged:
            if existing.get(item["item_id"], {}).get("status") == "blocked"                     and item["status"] == "done":
                item["status"] = "blocked"
        # 空计划守卫：LLM 输出空/全无效 todolist 时不得清空既有计划（BUG-06 实录：
        # 91 步积累的 T1-T6 全链被一次空输出抹掉，下一轮被迫重新规划）
        if not merged and existing:
            print("[plan] LLM 输出空 todolist，保留既有计划不覆写")
            return
        self.todolist.replace(merged)

    def _pack_plan(self, goal: dict) -> None:
        """确定性模式：pack plan: 段 → todolist（首次），requires 由引擎照常校验。"""
        if self.todolist.items():
            return
        steps = self.eng.pack.get("plan") or []
        items = []
        for idx, step in enumerate(steps):
            adapter = step.get("adapter", "")
            title = step.get("provides") and f"{adapter}: 产出 {','.join(step['provides'])}" or adapter
            depends = [f"T{i + 1}" for i, req in enumerate(steps[:idx])
                       if req.get("provides") and set(req["provides"]) & set(step.get("requires") or [])]
            items.append({
                "item_id": f"T{idx + 1}",
                "title": title,
                "depends_on": depends,
                "status": "pending",
                "intent_id": None,
                "note": json.dumps(step, ensure_ascii=False, default=str),
            })
        if not items:
            raise KeyError(f"场景包 {self.eng.pack['name']} 无 plan: 段（确定性引擎需要依赖图声明）")
        self.todolist.replace(items)

    def _set_item_intent(self, item_id: str, intent_id: str) -> None:
        items = self.todolist.items()
        for item in items:
            if item["item_id"] == item_id:
                item["intent_id"] = intent_id
        self.todolist.replace(items)

    # ---- 执行 ----

    def _drain_workers(self, goal: dict) -> int:
        """并行领完所有 pending 意图（批大小受剩余预算钳制，防并行越界）。"""
        completed = []
        while True:
            if self._steps >= self.max_total_steps:
                break
            intents = self.graph.intents_pending()
            if not intents:
                break
            remaining = max(0, self.max_total_steps - self._steps)
            batch = []
            for node in intents[:remaining]:
                with self._claim_lock:
                    if node["status"] != "pending":
                        continue
                    self.graph.set_status(node["node_id"], "running")
                batch.append(node)
            if not batch:
                break
            with ThreadPoolExecutor(max_workers=min(self.n_workers, len(batch))) as pool:
                futures = {node["node_id"]: pool.submit(self._worker, goal, node)
                           for node in batch}
                for node_id, fut in futures.items():
                    ok = fut.result()
                    completed.append((node_id, ok))
        for node_id, ok in completed:
            print(f"[worker] {node_id} {'done' if ok else 'blocked'}")
        return len(completed)

    def _worker(self, goal: dict, intent: dict) -> bool:
        node_id = intent["node_id"]
        try:
            ok, result_digest = self._execute_intent(intent)
        except Exception as exc:  # noqa: BLE001 - worker 异常不拖垮引擎
            self.graph.set_status(node_id, "blocked")
            self.graph.trace(node_id, 0, "engine", {"intent": intent["title"]},
                             f"worker 异常: {exc}")
            self._mark_item(intent, "blocked", str(exc)[:200])
            return False
        self.graph.set_status(node_id, "done" if ok else "blocked")
        # yields 边：意图产出的 fact 摘要
        fact_id = self.graph.add_node("fact", result_digest[:200])
        self.graph.link(node_id, fact_id, "yields")
        self._mark_item(intent, "done" if ok else "blocked", result_digest[:200])
        return ok

    def _mark_item(self, intent: dict, status: str, note: str) -> None:
        payload = intent.get("payload")
        item_id = None
        if payload:
            try:
                data = json.loads(payload) if isinstance(payload, str) else payload
                item_id = data.get("item_id")
            except (json.JSONDecodeError, TypeError):
                item_id = None
        if item_id:
            self.todolist.mark(item_id, status, note=note)

    # ---- 意图执行（LLM 工具循环 / 确定性步骤） ----

    def _execute_intent(self, intent: dict) -> tuple[bool, str]:
        payload = {}
        if intent.get("payload"):
            try:
                payload = json.loads(intent["payload"]) if isinstance(intent["payload"], str) \
                    else intent["payload"]
            except json.JSONDecodeError:
                payload = {}
        if self.router is not None:
            return self._llm_worker(intent, payload)
        return self._deterministic_worker(intent, payload)

    def _deterministic_worker(self, intent: dict, payload: dict) -> tuple[bool, str]:
        """pack 步骤执行（复用 runner 单步语义 + 规则门/审批/留痕）。"""
        from camty.agent.runner import DeterministicRunner, _resolve_args

        node_id = intent["node_id"]
        step = payload.get("note")
        if not step:
            return True, "空步骤"
        try:
            step = json.loads(step)
        except json.JSONDecodeError:
            return False, "步骤 payload 不可解析"
        adapter_name = step.get("adapter", "")
        adapter = self.registry.get(adapter_name)
        if adapter is None:
            return False, f"适配器未实现: {adapter_name}"
        args = _resolve_args(step.get("args", {}), self.eng.context)
        if getattr(adapter, "requires_finding", False) and "finding_id" not in args:
            latest = [f for f in self.eng.ledger.findings if f.verified]
            if not latest:
                return False, "门控拒绝：无 verified finding"
            args = {**args, "finding_id": latest[-1].id}
        gate = _gate_finding(adapter, args, self.eng.ledger)
        if gate:
            return False, gate
        reason = check_rules(self.eng.cfg, adapter_name, args)
        if reason:
            return False, f"规则门拒绝: {reason}"
        if adapter.requires_confirm:
            proceed, mode, note = decide_confirm(self.eng, adapter, args, self.router)
            self.eng.audit.record(adapter_name, args, ok=proceed, note=f"approval[{mode}]: {note}")
            if not proceed:
                return False, f"审批拒绝: {note}"
        runner = DeterministicRunner(self.eng, self.registry)
        result = runner._run_single(step)
        self._steps += 1
        digest = f"{adapter_name}: {result['summary']}"
        self.graph.trace(node_id, self._steps, adapter_name,
                         args, digest, result.get("evidence"))
        return True, digest

    def _llm_worker(self, intent: dict, payload: dict) -> tuple[bool, str]:
        """有界工具循环 + 过程留痕 + 跨意图检索 + 黑板继承。"""
        from camty.agent.blackboard import Blackboard, ledger_digest
        from camty.agent.goals import constraints_prompt

        tools = [a.tool_def() for a in self.registry.values() if a.available()]
        tools.append({
            "type": "function",
            "function": {
                "name": "search-traces",
                "description": "检索其它意图的执行过程（跨 worker 过程级信息交换）",
                "parameters": {"type": "object",
                               "properties": {"query": {"type": "string"}},
                               "required": ["query"]},
            },
        })
        tools.append({
            "type": "function",
            "function": {
                "name": "blackboard-note",
                "description": "把持久观察写入黑板（WAF 检出/限流节奏/登录态失效等，"
                               "后续所有意图与规划轮共享）",
                "parameters": {"type": "object",
                               "properties": {"kind": {"type": "string",
                                                       "description": "观察类别，如 waf/rate-limit/login/lesson"},
                                               "note": {"type": "string"}},
                               "required": ["kind", "note"]},
            },
        })
        node_id = intent["node_id"]
        constraints = constraints_prompt(self.eng.cfg)
        blackboard = Blackboard(self.eng).summary()
        worker_system = WORKER_SYSTEM.format(
            intent=intent["title"],
            payload=json.dumps(payload, ensure_ascii=False)[:800],
            ledger=ledger_digest(self.eng),
        )
        if blackboard:
            worker_system += f"\n{blackboard}\n"
        if constraints:
            worker_system += f"\n{constraints}\n"
        messages = [
            {"role": "system", "content": worker_system},
            {"role": "user", "content": f"开始执行意图: {intent['title']}"},
        ]
        digest_parts = []
        real_calls = 0  # 真实适配器调用计数（叙事不算产出，BUG-08）
        for step_i in range(PER_INTENT_STEPS):
            if self._steps >= self.max_total_steps:
                return (bool(digest_parts), "预算耗尽: " + "; ".join(digest_parts[-2:]))
            resp = self._chat_with_retry(messages, tools)
            messages.append({"role": "assistant", "content": resp["content"],
                             "tool_calls": resp.get("tool_calls") or []})
            if not resp.get("tool_calls"):
                summary = (resp.get("content") or "")[:400]
                self.graph.trace(node_id, step_i, "llm", {}, summary)
                digest_parts.append(summary)
                break
            for tc in resp["tool_calls"]:
                self._steps += 1
                if tc.get("name") in self.registry:
                    real_calls += 1
                content = self._execute_tool_call(node_id, step_i, tc)
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": content})
                from camty.guardrail.steer import as_prompt, take_pending

                notes = take_pending(self.eng)
                if notes:
                    messages.append({"role": "user", "content": as_prompt(notes)})
                    print(f"[steer] {node_id} 收到 operator 转向: {notes[0]['message'][:60]}")
        ok = self._intent_produced(intent, real_calls) and self._claimed_success(digest_parts)
        return ok, "; ".join(digest_parts) or "（无总结输出）"

    def _chat_with_retry(self, messages: list, tools: list) -> dict:
        """worker 决策调用带一次重试（BUG-03：供应商瞬时抖动不应整杀 worker）。

        规划者已有 3 次失败降级路径；worker 循环原先零重试——一次超时即把
        整个意图打成 blocked（实验实录：I-005 首枪未发即死于 120s 超时）。
        """
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                return self.router.chat(ROLE_DECIDE, messages, tools, timeout=WORKER_TIMEOUT)
            except Exception as exc:  # noqa: BLE001 - 二次失败才上抛
                last_exc = exc
                if attempt == 0:
                    print(f"[worker] LLM 调用失败，重试 1/2: {str(exc)[:120]}")
        raise last_exc

    def _execute_tool_call(self, node_id: str, step_i: int, tc: dict) -> str:
        name = tc["name"]
        args = tc.get("arguments") or {}
        if name == "search-traces":
            query = str(args.get("query", ""))
            hits = self.graph.search_traces(query, exclude_node=node_id, limit=10)
            return self._tool_content_json({"traces": hits})
        if name == "blackboard-note":
            from camty.agent.blackboard import Blackboard

            kind = str(args.get("kind", "lesson")).strip()[:40] or "lesson"
            note = str(args.get("note", "")).strip()
            if not note:
                return self._tool_content_json({"error": "note 不能为空"})
            Blackboard(self.eng).add(kind, note, source=node_id)
            return self._tool_content_json({"ok": True, "message": "已写入黑板"})
        adapter = self.registry.get(name)
        if adapter is None:
            return self._tool_content_json({"error": f"未知工具 {name}"})
        gate = _gate_finding(adapter, args, self.eng.ledger)
        if gate:
            self.eng.audit.record(name, args, ok=False, note="finding-gate 拒绝")
            return self._tool_content_json({"error": gate})
        reason = check_rules(self.eng.cfg, name, args)
        if reason:
            self.eng.audit.record(name, args, ok=False, note=f"rule-deny: {reason}")
            return self._tool_content_json({"error": f"规则门拒绝: {reason}"})
        if adapter.requires_confirm:
            proceed, mode, note = decide_confirm(self.eng, adapter, args, self.router)
            self.eng.audit.record(name, args, ok=proceed, note=f"approval[{mode}]: {note}")
            if not proceed:
                return self._tool_content_json({"error": f"审批拒绝: {note}"})
        try:
            result = adapter.run(args, self.eng.ctx)
            _merge_result(self.eng, result,
                          derived_from=[args["finding_id"]] if args.get("finding_id") else None)
            self.graph.trace(node_id, step_i, name, args, result.summary, result.evidence)
            return self._tool_content_json(
                {"summary": result.summary, "data": result.data, "evidence": result.evidence})
        except ToolUnavailable as exc:
            return self._tool_content_json({"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - 单工具失败不终止意图
            return self._tool_content_json({"error": str(exc)})

    @staticmethod
    def _claimed_success(digest_parts: list) -> bool:
        """BUG-09：完成判定验证结果，不是动作量。

        worker 诚实报告失败（动手但被拒）或忘打标记 → 一律按失败处理
        （fail-closed）→ blocked → 规划者换路重派。只有总结末段带
        [RESULT: 成功] 标记且有过真实动作才记 done——标记协议由
        WORKER_SYSTEM 规则 6 约定，"确认无此漏洞"类侦察结论也属成功。
        """
        if not digest_parts:
            return False
        return bool(re.search(r"\[RESULT:\s*成功\]", digest_parts[-1]))

    def _intent_produced(self, intent: dict, real_calls: int = 0) -> bool:
        """意图是否有真实产出（BUG-08：完成是验证状态，不是叙事状态）。

        旧实现 `return bool(intent)` 恒真——worker 只输出总结文本即可换 done
        （实验实录：三个阶段自述完成、平台 0/3）。现在 done 要求本意图
        实际调用过真实适配器（search-traces/blackboard-note 不算）；纯叙事
        无动作 → not produced → blocked → 规划者可重派（intent_id 已释放）。
        """
        return real_calls > 0

    @staticmethod
    def _tool_content_json(payload: dict) -> str:
        text = json.dumps(payload, ensure_ascii=False, default=str)
        if len(text) > TOOL_RESULT_LIMIT:
            text = text[:TOOL_RESULT_LIMIT] + "...(截断，全文见证据文件)"
        return text

    def _print_summary(self) -> None:
        cov = self.eng.assets.coverage()
        print(f"[engine] 结束：步数 {self._steps}/{self.max_total_steps}，"
              f"资产 {cov['total']}(测 {cov['tested']})，发现 {len(self.eng.ledger.findings)} 项")
        print(f"[engine] todolist:\n{self.todolist.summary()}")
        print(f"[engine] 台账:\n{self.eng.ledger.summary()}")
