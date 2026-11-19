"""FastAPI 服务：交战面板（双图/资产/流量/过程/复测/黑板）+ 引擎控制 + SSE 活动流。

启动: uvicorn camty.api.app:app --port 8090
鉴权: 设置 CAMTY_PANEL_TOKEN 环境变量后，/api/* 要求 Bearer token（或 ?token=，SSE 用）
（可选依赖：pip install fastapi uvicorn）
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from camty.agent.engine import Engine
from camty.agent.explore import ExplorationGraph, Todolist
from camty.agent.runner import DeterministicRunner
from camty.agent.state import Engagement
from camty.llm.router import UsageLog
from camty.report import write_report
from camty.traffic import TrafficProxy

app = FastAPI(title="Camty", version="0.3.0")
_ENGAGEMENTS: dict[str, Engagement] = {}
_ENGINE_STATE: dict[str, dict] = {}
_RETEST_STATE: dict[str, dict] = {}


def _panel_token() -> str:
    return os.environ.get("CAMTY_PANEL_TOKEN", "")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """设置 CAMTY_PANEL_TOKEN 后 /api/* 需要 Bearer 鉴权（SSE 走 ?token=）。"""
    token = _panel_token()
    if token and request.url.path.startswith("/api/"):
        auth = request.headers.get("Authorization", "")
        supplied = auth[7:].strip() if auth.startswith("Bearer ") else ""
        supplied = supplied or request.query_params.get("token", "")
        if supplied != token:
            return JSONResponse(status_code=401, content={"detail": "面板未授权（Bearer token 错误）"})
    return await call_next(request)


class RunRequest(BaseModel):
    dry_run: bool = True
    rerun: bool = False
    vars: dict[str, str] = {}


class EngineRequest(BaseModel):
    agent: bool = False
    workers: int = 4
    budget: int = 80
    traffic: bool = False
    vars: dict[str, str] = {}


class PreauthRequest(BaseModel):
    adapter: str
    pattern: str = ".*"
    note: str = ""


def _list_configs() -> list[Path]:
    root = Path.cwd() / "engagements"
    return sorted(root.glob("*.yaml")) if root.is_dir() else []


def _engagement(name: str) -> Engagement:
    if name not in _ENGAGEMENTS:
        match = next((p for p in _list_configs() if p.stem == name), None)
        if match is None:
            raise HTTPException(404, f"交战不存在: {name}（engagements/ 下无对应 yaml）")
        _ENGAGEMENTS[name] = Engagement(match)
    return _ENGAGEMENTS[name]


def _traffic_stats(eng: Engagement) -> dict:
    log = eng.dir / "traffic" / "traffic.jsonl"
    if not log.exists():
        return {"requests": 0, "hosts": {}}
    import json

    hosts: dict[str, int] = {}
    n = 0
    for line in log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        n += 1
        try:
            entry = json.loads(line)
            hosts[entry.get("host", "?")] = hosts.get(entry.get("host", "?"), 0) + 1
        except json.JSONDecodeError:
            continue
    return {"requests": n, "hosts": dict(sorted(hosts.items(), key=lambda kv: -kv[1])[:20])}


# ---- 交战与执行 ----


@app.get("/api/engagements")
def list_engagements():
    out = []
    for path in _list_configs():
        try:
            eng = _ENGAGEMENTS.get(path.stem) or Engagement(path)
            _ENGAGEMENTS[path.stem] = eng
            out.append(
                {
                    "name": eng.name,
                    "pack": eng.pack.get("name"),
                    "pack_title": eng.pack.get("title"),
                    "phases": [
                        {"id": p["id"], "title": p.get("title", "")} for p in eng.pack["phases"]
                    ],
                    "findings": len(eng.ledger.findings),
                    "assets": eng.assets.coverage(),
                    "engine": _ENGINE_STATE.get(path.stem, {}).get("status", "idle"),
                }
            )
        except Exception as exc:  # noqa: BLE001 - 单个坏配置不拖垮面板
            out.append({"name": path.stem, "error": str(exc)})
    return out


@app.get("/api/engagements/{name}/dashboard")
def dashboard(name: str):
    """一次拉全：台账 + 双图 + todolist + 流量 + 过程尾部。"""
    eng = _engagement(name)
    graph = ExplorationGraph(eng)
    return {
        "findings": [asdict(f) for f in eng.ledger.findings],
        "lineage": eng.ledger.lineage_summary(),
        "assets": eng.assets.coverage(),
        "asset_tree": eng.assets.tree(),
        "graph": graph.graph(),
        "todolist": Todolist(eng).items(),
        "activity": eng.db.load_activity(limit=100),
        "traffic": _traffic_stats(eng),
        "engine": _ENGINE_STATE.get(name, {"status": "idle"}),
        "retests": eng.db.load_retests(),
        "retest": _RETEST_STATE.get(name, {"status": "idle"}),
        "blackboard": eng.db.load_notes(limit=20),
    }


@app.post("/api/engagements/{name}/run/{phase}")
def run_phase(name: str, phase: str, req: RunRequest):
    eng = _engagement(name)
    try:
        eng.phase(phase)
    except KeyError as exc:
        raise HTTPException(400, str(exc)) from exc
    eng.context.update(req.vars)
    DeterministicRunner(eng).run(phase, dry_run=req.dry_run, rerun=req.rerun)
    eng.save_state()
    return {
        "status": "done",
        "dry_run": req.dry_run,
        "findings": [asdict(f) for f in eng.ledger.findings],
    }


@app.post("/api/engagements/{name}/engine")
def start_engine(name: str, req: EngineRequest):
    """后台线程启动多 agent 引擎，状态经 dashboard 轮询。"""
    eng = _engagement(name)
    if _ENGINE_STATE.get(name, {}).get("status") == "running":
        return {"status": "already-running"}
    eng.context.update(req.vars)

    def _run():
        proxy = None
        _ENGINE_STATE[name] = {"status": "running"}
        try:
            from camty.llm.router import LLMRouter

            router = LLMRouter() if req.agent else None
            if req.traffic:
                proxy = TrafficProxy(eng, port=8899)
                proxy.start()
                eng.context["proxy"] = proxy.proxy_url()
            ok = Engine(eng, router=router, n_workers=req.workers,
                        max_total_steps=req.budget).run()
            eng.save_state()
            _ENGINE_STATE[name] = {"status": "done" if ok else "stopped"}
        except Exception as exc:  # noqa: BLE001
            _ENGINE_STATE[name] = {"status": "error", "error": str(exc)[:300]}
        finally:
            if proxy:
                proxy.stop()

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "started"}


class SteerRequest(BaseModel):
    message: str


@app.post("/api/engagements/{name}/steer")
def steer_engagement(name: str, req: SteerRequest):
    """人在环路：跑动中注入转向指令（worker/planner 下一轮消费）。"""
    from camty.guardrail import steer as steer_mod

    eng = _engagement(name)
    note = steer_mod.steer(eng, req.message)
    return {"status": "queued", "note": note}


@app.get("/api/engagements/{name}/steer")
def list_steer(name: str):
    from camty.guardrail import steer as steer_mod

    eng = _engagement(name)
    return {"pending": steer_mod.pending_summary(eng),
            "all": eng.context.get("steer_notes", [])}


class RetestRequest(BaseModel):
    finding_id: str
    note: str = ""


@app.post("/api/engagements/{name}/retest")
def start_retest(name: str, req: RetestRequest):
    """漏洞复测：后台线程跑独立会话，状态经 retests 端点轮询。"""
    eng = _engagement(name)
    known = {f.id for f in eng.ledger.findings}
    if req.finding_id not in known:
        raise HTTPException(400, f"台账无 finding {req.finding_id}")
    if _RETEST_STATE.get(name, {}).get("status") == "running":
        return {"status": "already-running"}

    def _run():
        from camty.agent.retester import run_retest
        from camty.llm.router import LLMRouter

        _RETEST_STATE[name] = {"status": "running", "finding_id": req.finding_id}
        try:
            result = run_retest(eng, LLMRouter(), req.finding_id, note=req.note)
            _RETEST_STATE[name] = {"status": "done", "result": result}
        except Exception as exc:  # noqa: BLE001
            _RETEST_STATE[name] = {"status": "error", "error": str(exc)[:300]}

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "started", "finding_id": req.finding_id}


@app.get("/api/engagements/{name}/retests")
def list_retests(name: str, finding_id: str | None = None):
    """复测历史 + 当前会话状态（面板轮询）。"""
    eng = _engagement(name)
    return {"records": eng.db.load_retests(finding_id),
            "session": _RETEST_STATE.get(name, {"status": "idle"})}


class BlackboardRequest(BaseModel):
    kind: str = "operator"
    note: str


@app.get("/api/engagements/{name}/blackboard")
def get_blackboard(name: str, limit: int = 50):
    eng = _engagement(name)
    return {"notes": eng.db.load_notes(limit=limit)}


@app.post("/api/engagements/{name}/blackboard")
def add_blackboard_note(name: str, req: BlackboardRequest):
    """operator 手写持久观察（planner/worker 下一轮继承）。"""
    eng = _engagement(name)
    if not req.note.strip():
        raise HTTPException(400, "note 不能为空")
    note_id = eng.db.add_note(req.kind.strip()[:40] or "operator", req.note.strip()[:800],
                             source="panel")
    return {"id": note_id, "status": "saved"}


# ---- LLM 用量（ARTEX token 记账语义）----


class AskRequest(BaseModel):
    question: str


@app.post("/api/engagements/{name}/ask")
def ask_question(name: str, req: AskRequest):
    """侧问：只读快照问答，答案落 activity（不干扰跑动中的引擎）。"""
    from camty.agent.sidequestion import answer_question
    from camty.llm.router import LLMRouter

    eng = _engagement(name)
    if not req.question.strip():
        raise HTTPException(400, "问题不能为空")
    try:
        answer = answer_question(eng, LLMRouter(), req.question)
    except Exception as exc:  # noqa: BLE001 - LLM 未配置等给出可读错误
        raise HTTPException(503, f"侧问失败: {exc}") from exc
    return {"answer": answer}


def _usage_log() -> UsageLog:
    vault = Path(os.environ.get("CAMTY_VAULT", "keys.json"))
    return UsageLog(vault.parent / "usage.jsonl")


@app.get("/api/usage")
def llm_usage(limit: int = 50):
    """LLM 调用聚合：按 provider 的调用数 / token / 错误数 + 最近记录。"""
    log = _usage_log()
    return {"totals": log.totals(), "recent": list(reversed(log.read(limit=limit)))}


# ---- SSE 活动流（ARTEX 实时流语义：轮询 activity 表推增量）----


@app.get("/api/engagements/{name}/events")
async def engagement_events(name: str, duration: float = 600, interval: float = 2.0):
    """text/event-stream：定期推 activity 增量 + 引擎/复测状态。

    duration：流的存活秒数（默认 600，防止僵尸连接；EventSource 会自动重连）。
    """
    import time as _time

    eng = _engagement(name)

    async def stream():
        started = _time.monotonic()
        last_activity_id = 0
        last_state: dict = {}
        while _time.monotonic() - started <= max(duration, 0.1):
            rows = [r for r in eng.db.load_activity(limit=50) if r["id"] > last_activity_id]
            if rows:
                last_activity_id = rows[-1]["id"]
            state = {"engine": _ENGINE_STATE.get(name, {}).get("status", "idle"),
                     "retest": _RETEST_STATE.get(name, {}).get("status", "idle")}
            payload = {"activity": rows, "state": state}
            if state != last_state or rows:
                yield f"data: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"
            last_state = state
            await asyncio.sleep(max(interval, 0.05))

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


# ---- 只读明细 ----


@app.get("/api/engagements/{name}/ledger")
def get_ledger(name: str):
    eng = _engagement(name)
    return {"findings": [asdict(f) for f in eng.ledger.findings],
            "lineage": eng.ledger.lineage_summary()}


@app.get("/api/engagements/{name}/assets")
def get_assets(name: str):
    eng = _engagement(name)
    return {"coverage": eng.assets.coverage(), "tree": eng.assets.tree()}


@app.get("/api/engagements/{name}/graph")
def get_graph(name: str):
    return ExplorationGraph(_engagement(name)).graph()


@app.get("/api/engagements/{name}/todolist")
def get_todolist(name: str):
    return {"items": Todolist(_engagement(name)).items()}


@app.get("/api/engagements/{name}/activity")
def get_activity(name: str, tail: int = 100):
    return {"entries": _engagement(name).db.load_activity(limit=tail)}


@app.get("/api/engagements/{name}/traffic")
def get_traffic(name: str):
    return _traffic_stats(_engagement(name))


@app.get("/api/engagements/{name}/traffic/entries")
def get_traffic_entries(name: str, offset: int = 0, limit: int = 50):
    """流量回放：逐条请求/响应查看（JSONL 分页）。"""
    eng = _engagement(name)
    log = eng.dir / "traffic" / "traffic.jsonl"
    if not log.exists():
        return {"entries": [], "total": 0}
    entries = []
    for line in log.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return {"total": len(entries), "entries": entries[offset:offset + limit]}


@app.get("/api/engagements/{name}/audit")
def get_audit(name: str, tail: int = 50):
    eng = _engagement(name)
    return {"entries": eng.audit.entries()[-tail:]}


# ---- 预授权（审批队列：比赛场景一键放行，审计留痕） ----


@app.get("/api/engagements/{name}/preauth")
def list_preauth(name: str):
    eng = _engagement(name)
    return {"rules": eng.context.get("preauth_rules", [])}


@app.post("/api/engagements/{name}/preauth")
def add_preauth(name: str, req: PreauthRequest):
    from camty.guardrail import preauth

    eng = _engagement(name)
    rule = preauth.add_rule(eng, req.adapter, req.pattern, req.note)
    return {"status": "added", "rule": rule}


@app.delete("/api/engagements/{name}/preauth")
def clear_preauth(name: str):
    from camty.guardrail import preauth

    eng = _engagement(name)
    n = preauth.clear_rules(eng)
    return {"status": "cleared", "rules": n}


@app.get("/api/engagements/{name}/report", response_class=HTMLResponse)
def get_report(name: str):
    eng = _engagement(name)
    return HTMLResponse(Path(write_report(eng)).read_text(encoding="utf-8"))


# ---- 内嵌单页 UI ----

_PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>Camty 面板</title><style>
body{font-family:'Segoe UI',system-ui,sans-serif;margin:0;background:#0f1117;color:#e8e8e8}
header{padding:12px 20px;background:#161a23;border-bottom:1px solid #2a2f3d;display:flex;gap:16px;align-items:center}
header h1{font-size:18px;margin:0;color:#c0392b}
nav{display:flex;gap:8px;flex-wrap:wrap}
nav button{background:#1e2430;color:#e8e8e8;border:1px solid #2a2f3d;padding:6px 14px;border-radius:6px;cursor:pointer}
nav button.active{background:#c0392b;border-color:#c0392b}
main{padding:20px;display:grid;gap:16px}
.card{background:#161a23;border:1px solid #2a2f3d;border-radius:10px;padding:16px}
.card h2{margin:0 0 12px;font-size:15px;color:#9fb3c8}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border-bottom:1px solid #232a38;padding:6px 8px;text-align:left}
th{color:#9fb3c8;font-weight:600}
.badge{padding:1px 8px;border-radius:10px;font-size:11px;color:#fff}
.high{background:#e74c3c}.critical{background:#c0392b}.medium{background:#e67e22}.low{background:#f39c12}.info{background:#7f8c8d}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
select,button.run{background:#1e2430;color:#e8e8e8;border:1px solid #2a2f3d;padding:6px 10px;border-radius:6px}
#toast{position:fixed;bottom:20px;right:20px;background:#c0392b;padding:10px 16px;border-radius:8px;display:none}
</style></head><body>
<header><h1>Camty 交战面板</h1>
<select id="engSel"></select>
<nav>
<button data-tab="dash" class="active">仪表盘</button>
<button data-tab="ledger">台账</button>
<button data-tab="assets">资产图</button>
<button data-tab="graph">探索图</button>
<button data-tab="todo">攻击链</button>
<button data-tab="traffic">流量</button>
<button data-tab="activity">过程</button>
<button data-tab="usage">用量</button>
</nav>
<input id="steerInput" placeholder="跑动中转向指令（人在环路）…" style="flex:1;min-width:180px;background:#1e2430;color:#e8e8e8;border:1px solid #2a2f3d;padding:6px 10px;border-radius:6px">
<button class="run" id="engineBtn">▶ 启动引擎</button>
</header>
<main id="main"></main><div id="toast"></div>
<script>
let eng = '';
let evtSource = null;
const $ = s => document.querySelector(s);
async function api(path, opts){
  opts = opts || {};
  opts.headers = Object.assign({}, opts.headers || {});
  const token = localStorage.getItem('camty_token') || '';
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  const r = await fetch(path, opts);
  if (r.status === 401){
    const t = prompt('面板需要鉴权（CAMTY_PANEL_TOKEN）：');
    if (t){ localStorage.setItem('camty_token', t); return api(path, opts); }
  }
  return r.json();
}
async function loadEngs(){
  const list = await api('/api/engagements');
  $('#engSel').innerHTML = (list||[]).map(e=>`<option>${e.name}</option>`).join('');
  eng = $('#engSel').value || '';
}
$('#engSel').onchange = () => { eng = $('#engSel').value; render(); };
document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));
  b.classList.add('active'); render();
});
function sev(s){ return `<span class="badge ${s}">${s}</span>`; }
function toast(msg){ const box=$('#toast'); box.textContent=msg; box.style.display='block'; setTimeout(()=>box.style.display='none', 3000); }
async function render(){
  if(!eng) return;
  const tab = document.querySelector('nav button.active').dataset.tab;
  const main = $('#main');
  if(tab==='dash'){
    const d = await api(`/api/engagements/${eng}/dashboard`);
    main.innerHTML = `
    <div class="grid2">
      <div class="card"><h2>发现（${d.findings.length}）</h2>
        <table><tr><th>ID</th><th>级别</th><th>目标</th><th>详情</th><th>验证</th></tr>
        ${d.findings.slice(0,15).map(f=>`<tr><td>${f.id}</td><td>${sev(f.severity)}</td>
        <td>${f.target}</td><td>${f.detail}</td><td>${f.verified?'✓':'—'}</td></tr>`).join('')}</table></div>
      <div class="card"><h2>资产覆盖</h2>
        <table><tr><th>类型</th><th>总数</th><th>已测</th></tr>
        ${Object.entries(d.assets.by_kind||{}).map(([k,v])=>`<tr><td>${k}</td><td>${v.total}</td><td>${v.tested}</td></tr>`).join('')}
        </table>
        <h2 style="margin-top:14px">流量</h2><p>${d.traffic.requests} 笔请求，${Object.keys(d.traffic.hosts||{}).length} 主机</p>
        <h2 style="margin-top:14px">血缘链</h2><pre style="font-size:12px;white-space:pre-wrap">${d.lineage||'（无）'}</pre></div>
    </div>
    <div class="card"><h2>攻击链（todolist）</h2>
      <table><tr><th>ID</th><th>状态</th><th>步骤</th><th>前置</th></tr>
      ${(d.todolist||[]).map(t=>`<tr><td>${t.item_id}</td><td>${t.status}</td><td>${t.title}</td><td>${(t.depends_on||[]).join(',')}</td></tr>`).join('')}</table></div>
    <div class="card"><h2>实时活动流（SSE，引擎 ${d.engine.status||'idle'} / 复测 ${d.retest.status||'idle'}）</h2>
      <div id="live-activity"></div></div>`;
  } else if(tab==='ledger'){
    const [d, rt] = await Promise.all([
      api(`/api/engagements/${eng}/ledger`),
      api(`/api/engagements/${eng}/retests`)]);
    const session = rt.session || {status:'idle'};
    main.innerHTML = `<div class="card"><h2>证据台账</h2>
      <p id="retest-status" style="font-size:12px;color:#9fb3c8">${
        session.status==='running' ? `复测进行中（${session.finding_id||''}）…` :
        session.status==='error' ? `复测失败：${session.error||''}` :
        (session.result ? `最近复测 [${session.result.verdict}] ${session.result.finding_id}: ${session.result.summary||''}` : '')}</p>
      <table><tr><th>ID</th><th>类型</th><th>级别</th><th>目标</th><th>详情</th><th>血缘</th><th>验证</th><th>处置</th><th>证据</th><th></th></tr>
      ${d.findings.map(f=>`<tr><td>${f.id}</td><td>${f.kind}</td><td>${sev(f.severity)}</td>
      <td>${f.target}</td><td>${f.detail}</td><td>${(f.derived_from||[]).join('←')}</td>
      <td>${f.verified?'✓':'—'}</td>
      <td>${f.disposal==='fixed' ? '<span style="color:#2ecc71">已修复</span>' : '开放'}</td>
      <td><code style="font-size:11px">${f.evidence||''}</code></td>
      <td><button class="run" data-retest="${f.id}" ${session.status==='running'?'disabled':''}>复测</button></td></tr>`).join('')}</table></div>
    <div class="card"><h2>复测历史（${(rt.records||[]).length}）</h2>
      <table><tr><th>#</th><th>时间</th><th>漏洞</th><th>结论</th><th>总结</th></tr>
      ${(rt.records||[]).map(r=>`<tr><td>${r.id}</td><td>${r.created_ts}</td><td>${r.finding_id}</td>
      <td>${r.verdict==='fixed' ? '<span style="color:#2ecc71">已修复</span>' :
             r.verdict==='reproduced' ? '<span style="color:#e74c3c">仍可复现</span>' : '无法确认'}</td>
      <td>${(r.summary||'').slice(0,120)}</td></tr>`).join('') || '<tr><td colspan="5">（暂无）</td></tr>'}</table></div>`;
    document.querySelectorAll('button[data-retest]').forEach(b => b.onclick = async () => {
      const note = prompt('复测补充说明（可空）：') ?? '';
      await api(`/api/engagements/${eng}/retest`, {method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({finding_id: b.dataset.retest, note})});
      toast(`复测已启动: ${b.dataset.retest}`);
      render();
    });
    if(session.status==='running'){ setTimeout(render, 5000); }
  } else if(tab==='assets'){
    const d = await api(`/api/engagements/${eng}/assets`);
    const row = a => `<tr><td>${a.kind}</td><td>${a.value}</td><td>${a.tested?'✓ 已测':'○ 未测'}</td><td>${a.source||''}</td></tr>`;
    main.innerHTML = `<div class="grid2">
      <div class="card"><h2>覆盖图（${(d.coverage.tested||0)}/${d.coverage.total||0}，点节点看详情）</h2>
        <canvas id="fdg" width="720" height="480" style="background:#0d1017;width:100%"></canvas>
        <div id="fdg-detail" style="margin-top:8px;font-size:12px;color:#9fb3c8"></div></div>
      <div class="card"><h2>资产表</h2>
      <table><tr><th>类型</th><th>值</th><th>状态</th><th>来源</th></tr>
      ${(d.tree||[]).flatMap(t=>[row(t),...(t.children||[]).flatMap(c=>[row(c),...(c.children||[]).map(g=>row(g))])]).join('')}</table></div></div>`;
    renderFDG(d.tree);
  } else if(tab==='traffic'){
    const d = await api(`/api/engagements/${eng}/traffic/entries?offset=0&limit=100`);
    const rows = (d.entries||[]).map((e,i)=>`<tr data-i="${i}"><td>${e.ts||''}</td><td>${e.host||''}</td>
      <td>${e.method||''}</td><td style="max-width:200px;overflow:hidden">${(e.path||'').slice(0,40)}</td>
      <td>${e.status??''}</td><td>${e.resp_bytes??''}</td></tr>`).join('');
    main.innerHTML = `<div class="card"><h2>流量回放（${d.total||0} 笔，点行展开）</h2>
      <table><tr><th>时间</th><th>主机</th><th>方法</th><th>路径</th><th>状态</th><th>字节</th></tr>${rows}</table>
      <div id="traffic-detail" style="margin-top:10px"></div></div>`;
    document.querySelectorAll('#traffic-detail') && document.querySelectorAll('table tr[data-i]').forEach(tr => tr.onclick = () => {
      const e = d.entries[+tr.dataset.i];
      document.getElementById('traffic-detail').innerHTML =
        `<h2 style="color:#e74c3c">请求</h2><pre style="font-size:12px;white-space:pre-wrap;background:#0d1017;padding:8px;border-radius:6px">${JSON.stringify(e.req_headers||{},null,1)}
${(e.req_body||'').slice(0,2000)}</pre>`+
        `<h2 style="color:#e74c3c">响应 ${e.status}</h2><pre style="font-size:12px;white-space:pre-wrap;background:#0d1017;padding:8px;border-radius:6px">${JSON.stringify(e.resp_headers||{},null,1)}
${(e.resp_body||'').slice(0,3000)}</pre>`;
    });
  } else if(tab==='graph'){
    const d = await api(`/api/engagements/${eng}/graph`);
    main.innerHTML = `<div class="card"><h2>探索图（${(d.nodes||[]).length} 节点 / ${(d.edges||[]).length} 边）</h2>
      <table><tr><th>节点</th><th>类型</th><th>状态</th><th>标题</th><th>时间</th></tr>
      ${(d.nodes||[]).map(n=>`<tr><td>${n.node_id}</td><td>${n.kind}</td><td>${n.status}</td><td>${n.title}</td><td>${n.updated_ts||''}</td></tr>`).join('')}</table>
      <h2 style="margin-top:14px">血缘边</h2>
      <table><tr><th>源</th><th>关系</th><th>目标</th></tr>
      ${(d.edges||[]).map(e=>`<tr><td>${e.src}</td><td>${e.relation}</td><td>${e.dst}</td></tr>`).join('')}</table></div>`;
  } else if(tab==='todo'){
    const d = await api(`/api/engagements/${eng}/todolist`);
    main.innerHTML = `<div class="card"><h2>攻击链 todolist</h2>
      <table><tr><th>ID</th><th>状态</th><th>步骤</th><th>前置</th><th>意图</th><th>备注</th></tr>
      ${(d.items||[]).map(t=>`<tr><td>${t.item_id}</td><td>${t.status}</td><td>${t.title}</td>
      <td>${(t.depends_on||[]).join(',')}</td><td>${t.intent_id||''}</td><td>${t.note||''}</td></tr>`).join('')}</table></div>`;
  } else if(tab==='activity'){
    const d = await api(`/api/engagements/${eng}/activity?tail=200`);
    main.innerHTML = `<div class="card"><h2>侧问（跑动中提问，只读不干扰主流程）</h2>
      <div style="display:flex;gap:8px">
      <input id="askInput" placeholder="问点什么…如「现在最严重的发现是什么」" style="flex:1;background:#1e2430;color:#e8e8e8;border:1px solid #2a2f3d;padding:6px 10px;border-radius:6px">
      <button class="run" id="askBtn">提问</button></div>
      <div id="ask-answer" style="margin-top:8px;white-space:pre-wrap;font-size:13px"></div></div>
    <div class="card"><h2>执行过程（跨意图检索可用 evidence-search 适配器）</h2>
      <table><tr><th>#</th><th>意图</th><th>步</th><th>工具</th><th>结果摘要</th></tr>
      ${(d.entries||[]).map(a=>`<tr><td>${a.id}</td><td>${a.node_id||''}</td><td>${a.step}</td>
      <td>${a.tool}</td><td style="font-size:12px">${(a.result_digest||'').slice(0,120)}</td></tr>`).join('')}</table></div>`;
    const doAsk = async () => {
      const q = (document.getElementById('askInput').value||'').trim(); if (!q) return;
      document.getElementById('ask-answer').textContent = '思考中…';
      const r = await api(`/api/engagements/${eng}/ask`, {method:'POST',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify({question: q})});
      document.getElementById('ask-answer').textContent = r.answer || r.detail || '（无回答）';
    };
    document.getElementById('askBtn').onclick = doAsk;
    document.getElementById('askInput').onkeydown = ev => { if (ev.key==='Enter') doAsk(); };
  } else if(tab==='usage'){
    const d = await api('/api/usage?limit=30');
    const t = d.totals || {};
    main.innerHTML = `<div class="card"><h2>LLM 用量</h2>
      <p>调用 ${t.calls||0} 次（失败 ${t.errors||0}）· prompt ${(t.prompt_tokens||0).toLocaleString()} tok · completion ${(t.completion_tokens||0).toLocaleString()} tok</p>
      <table><tr><th>Provider</th><th>调用</th><th>失败</th><th>prompt tok</th><th>completion tok</th></tr>
      ${Object.entries(t.by_provider||{}).map(([p,v])=>`<tr><td>${p}</td><td>${v.calls}</td>
      <td>${v.errors}</td><td>${(v.prompt_tokens||0).toLocaleString()}</td><td>${(v.completion_tokens||0).toLocaleString()}</td></tr>`).join('') || '<tr><td colspan="5">（暂无调用）</td></tr>'}</table></div>
    <div class="card"><h2>最近调用</h2>
      <table><tr><th>时间</th><th>角色</th><th>provider/模型</th><th>token（p/c）</th><th>状态</th></tr>
      ${(d.recent||[]).map(r=>`<tr><td>${r.ts}</td><td>${r.role}</td><td>${r.provider}/${r.model}</td>
      <td>${r.prompt_tokens}/${r.completion_tokens}</td><td>${r.ok?'✓':'✗ '+(r.error||'').slice(0,40)}</td></tr>`).join('') || '<tr><td colspan="5">（暂无）</td></tr>'}</table></div>`;
  }
  subscribeEvents(tab);
}
function subscribeEvents(tab){
  if (evtSource){ evtSource.close(); evtSource = null; }
  if (tab!=='dash' || !eng) return;
  const url = `/api/engagements/${eng}/events` +
    (localStorage.getItem('camty_token') ? `?token=${localStorage.getItem('camty_token')}` : '');
  evtSource = new EventSource(url);
  evtSource.onmessage = ev => {
    const data = JSON.parse(ev.data);
    const box = document.getElementById('live-activity');
    if (box && (data.activity||[]).length){
      box.innerHTML = (data.activity||[]).slice(-8).map(a =>
        `<div style="font-size:12px;color:#9fb3c8">[${a.ts}] ${a.node_id||''} ${a.tool}: ${(a.result_digest||'').slice(0,90)}</div>`
      ).join('') + box.innerHTML.split('</div>').slice(0, 24).join('</div>');
    }
  };
}
$('#steerInput') && ($('#steerInput').onkeydown = async (ev) => {
  if (ev.key !== 'Enter' || !eng) return;
  const msg = ev.target.value.trim(); if (!msg) return;
  const r = await api(`/api/engagements/${eng}/steer`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({message: msg})});
  ev.target.value = '';
  const box = $('#toast'); box.textContent = `已注入转向: ${msg.slice(0,40)}`; box.style.display='block';
  setTimeout(()=>box.style.display='none', 2500);
});
$('#engineBtn').onclick = async () => {
  if(!eng) return;
  const r = await api(`/api/engagements/${eng}/engine`, {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
  $('#toast').textContent = `引擎: ${r.status}`; $('#toast').style.display='block';
  setTimeout(()=>$('#toast').style.display='none', 3000);
  render();
};
let fdgTimer = null;
function renderFDG(tree){
  if (fdgTimer) cancelAnimationFrame(fdgTimer);
  const nodes = [], links = [];
  const walk = (n, parent) => { const i = nodes.length; nodes.push({...n, idx: i, x: 360+Math.random()*120-60, y: 240+Math.random()*120-60, vx:0, vy:0});
    (n.children||[]).forEach(c => { walk(c, n); links.push([nodes.filter(x=>x.dedup_key===n.dedup_key)[0].idx, nodes.filter(x=>x.dedup_key===c.dedup_key)[0].idx]); }); };
  (tree||[]).forEach(t => walk(t, null));
  const colors = {root_domain:'#c0392b', subdomain:'#e67e22', host:'#f39c12', service:'#27ae60', endpoint:'#2980b9'};
  const canvas = document.getElementById('fdg'); if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const step = () => {
    for (let i=0;i<nodes.length;i++){ const a=nodes[i];
      for (let j=i+1;j<nodes.length;j++){ const b=nodes[j];
        let dx=a.x-b.x, dy=a.y-b.y, d2=dx*dx+dy*dy+40, d=Math.sqrt(d2);
        const f=1800/d2; dx/=d; dy/=d; a.vx+=dx*f; a.vy+=dy*f; b.vx-=dx*f; b.vy-=dy*f; }
      a.vx += (360-a.x)*0.003; a.vy += (240-a.y)*0.003; }
    links.forEach(([s,t2])=>{ const a=nodes[s], b=nodes[t2];
      const dx=b.x-a.x, dy=b.y-a.y, d=Math.sqrt(dx*dx+dy*dy)||1;
      const f=(d-60)*0.02; a.vx+=dx/d*f; a.vy+=dy/d*f; b.vx-=dx/d*f; b.vy-=dy/d*f; });
    ctx.clearRect(0,0,720,480);
    links.forEach(([s,t2])=>{ ctx.strokeStyle='#2a2f3d'; ctx.beginPath();
      ctx.moveTo(nodes[s].x,nodes[s].y); ctx.lineTo(nodes[t2].x,nodes[t2].y); ctx.stroke(); });
    nodes.forEach(n=>{ n.x+=n.vx*0.85; n.y+=n.vy*0.85; n.vx*=0.85; n.vy*=0.85;
      ctx.beginPath(); ctx.arc(n.x,n.y, n.kind==='endpoint'?3:6, 0, 7);
      ctx.fillStyle = colors[n.kind]||'#7f8c8d'; ctx.fill();
      if (n.tested){ ctx.strokeStyle='#2ecc71'; ctx.lineWidth=2; ctx.stroke(); ctx.lineWidth=1; } });
    fdgTimer = requestAnimationFrame(step);
  };
  step();
  canvas.onclick = (ev) => {
    const rect = canvas.getBoundingClientRect();
    const mx = (ev.clientX-rect.left)*(720/rect.width), my = ev.clientY-rect.top;
    const hit = nodes.find(n => (n.x-mx)**2+(n.y-my)**2 < 144);
    document.getElementById('fdg-detail').innerHTML = hit
      ? `<b style="color:${colors[hit.kind]||'#fff'}">${hit.kind}</b> ${hit.value} ${hit.tested?'<span style="color:#2ecc71">✓ 已测</span>':'<span style="color:#7f8c8d">○ 未测</span>'} ${hit.source?`· 来源 ${hit.source}`:''}`
      : '';
  };
}
loadEngs().then(render);
setInterval(()=>{ if(eng && document.querySelector('nav button.active').dataset.tab==='dash') render(); }, 8000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(_PAGE)
