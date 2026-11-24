"""报告引擎：零依赖 HTML 报告 + 复测对比。"""

from __future__ import annotations

import html
import time
from dataclasses import asdict
from pathlib import Path

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.agent.state import Engagement

_STYLE = """
body{font-family:'Segoe UI',system-ui,sans-serif;margin:2rem;color:#1a1a2e;background:#fafafa}
h1{border-bottom:3px solid #c0392b;padding-bottom:.4rem}
h2{margin-top:2rem;color:#c0392b}
table{border-collapse:collapse;width:100%;margin:1rem 0;background:#fff}
th,td{border:1px solid #ddd;padding:.5rem .8rem;text-align:left;font-size:.92rem}
th{background:#2c3e50;color:#fff}
tr.verified td:first-child{color:#c0392b;font-weight:600}
code{background:#eee;padding:.1rem .3rem;border-radius:3px;font-size:.85em}
.meta{color:#666;font-size:.9rem}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:1rem;color:#fff;font-size:.8rem}
.high{background:#e74c3c}.critical{background:#c0392b}.medium{background:#e67e22}.low{background:#f39c12}.info{background:#7f8c8d}
"""


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _severity_badge(severity: str) -> str:
    cls = severity if severity in ("high", "critical", "medium", "low", "info") else "info"
    return f'<span class="badge {cls}">{_esc(severity)}</span>'


def _findings_table(findings: list[dict]) -> str:
    if not findings:
        return "<p>（暂无发现）</p>"
    rows = "".join(
        f"<tr class='{'verified' if f['verified'] else ''}'>"
        f"<td>{_esc(f['id'])}</td><td>{_esc(f['kind'])}</td><td>{_severity_badge(f.get('severity', 'info'))}</td>"
        f"<td>{_esc(f['target'])}</td><td>{_esc(f['detail'])}</td>"
        f"<td>{'已修复' if f.get('disposal') == 'fixed' else '开放'}</td>"
        f"<td><code>{_esc(f.get('evidence') or '')}</code></td></tr>"
        for f in findings
    )
    return (
        "<table><tr><th>ID</th><th>类型</th><th>严重度</th><th>目标</th><th>详情</th><th>处置</th><th>证据</th></tr>"
        f"{rows}</table>"
    )


_VERDICT_CN = {"reproduced": "仍可复现", "fixed": "已修复", "inconclusive": "无法确认"}


def _retest_section(eng: Engagement) -> str:
    """复测历史（ARTEX retester 语义：每 finding 多轮结论存档）。"""
    records = eng.db.load_retests()
    if not records:
        return ""
    rows = "".join(
        f"<tr><td>{r['id']}</td><td>{_esc(r['created_ts'])}</td><td>{_esc(r['finding_id'])}</td>"
        f"<td>{_esc(_VERDICT_CN.get(r['verdict'], r['verdict']))}</td>"
        f"<td>{_esc(r['summary'][:160])}</td></tr>"
        for r in records
    )
    return (
        f"<h2>漏洞复测记录（{len(records)}）</h2>"
        "<table><tr><th>#</th><th>时间</th><th>漏洞</th><th>结论</th><th>总结</th></tr>"
        f"{rows}</table>"
    )


def _coverage_table(eng: Engagement) -> str:
    cov = eng.assets.coverage()
    if not cov["by_kind"]:
        return "<p>（资产图空）</p>"
    rows = "".join(
        f"<tr><td>{_esc(kind)}</td><td>{v['total']}</td><td>{v['tested']}</td>"
        f"<td>{'%.0f%%' % (100 * v['tested'] / v['total']) if v['total'] else 0}</td></tr>"
        for kind, v in sorted(cov["by_kind"].items())
    )
    total_pct = 100 * cov["tested"] / cov["total"] if cov["total"] else 0
    return (
        f"<p>资产 {cov['total']} 个，已测 {cov['tested']}（{total_pct:.0f}%）</p>"
        "<table><tr><th>类型</th><th>总数</th><th>已测</th><th>覆盖率</th></tr>"
        f"{rows}</table>"
    )


def _traffic_section(eng: Engagement) -> str:
    import json as _json

    log = eng.dir / "traffic" / "traffic.jsonl"
    if not log.exists():
        return "<p>（未启用流量留痕）</p>"
    hosts: dict[str, int] = {}
    n = 0
    for line in log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        n += 1
        try:
            entry = _json.loads(line)
            hosts[entry.get("host", "?")] = hosts.get(entry.get("host", "?"), 0) + 1
        except _json.JSONDecodeError:
            continue
    rows = "".join(
        f"<tr><td>{_esc(h)}</td><td>{c}</td></tr>"
        for h, c in sorted(hosts.items(), key=lambda kv: -kv[1])[:15]
    )
    return (
        f"<p>{n} 笔请求留痕（<code>{_esc(str(log))}</code>）</p>"
        "<table><tr><th>主机</th><th>请求数</th></tr>" f"{rows}</table>"
    )


def _graph_section(eng: Engagement) -> str:
    from camty.agent.explore import ExplorationGraph

    graph = ExplorationGraph(eng).graph()
    nodes, edges = graph["nodes"], graph["edges"]
    if not nodes:
        return "<p>（探索图空：未跑多 agent 引擎）</p>"
    node_rows = "".join(
        f"<tr><td>{_esc(n['node_id'])}</td><td>{_esc(n['kind'])}</td><td>{_esc(n['status'])}</td>"
        f"<td>{_esc(n['title'][:80])}</td><td>{_esc(n['updated_ts'] or '')}</td></tr>"
        for n in sorted(nodes, key=lambda x: x["node_id"])
    )
    edge_rows = "".join(
        f"<tr><td>{_esc(e['src'])}</td><td>{_esc(e['relation'])}</td><td>{_esc(e['dst'])}</td></tr>"
        for e in edges[:200]
    )
    return (
        f"<p>探索图：{len(nodes)} 节点 / {len(edges)} 血缘边</p>"
        "<table><tr><th>节点</th><th>类型</th><th>状态</th><th>标题</th><th>更新</th></tr>"
        f"{node_rows}</table>"
        "<h3>血缘边</h3><table><tr><th>源</th><th>关系</th><th>目标</th></tr>" f"{edge_rows}</table>"
    )


def render_html(eng: Engagement) -> str:
    findings = [asdict(f) for f in eng.ledger.findings]
    scope = eng.cfg.get("scope", {})
    scope_desc = ", ".join(
        (scope.get("domains") or []) + (scope.get("cidrs") or []) + (scope.get("ips") or [])
    ) or "（未声明）"
    audit_rows = eng.audit.entries()
    per_adapter: dict[str, int] = {}
    for row in audit_rows:
        per_adapter[row.get("adapter", "?")] = per_adapter.get(row.get("adapter", "?"), 0) + 1
    audit_stats = ", ".join(f"{k}×{v}" for k, v in sorted(per_adapter.items())) or "（无动作记录）"
    verified = sum(1 for f in findings if f.get("verified"))
    return f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>交战报告 - {_esc(eng.name)}</title><style>{_STYLE}</style></head><body>
<h1>交战报告：{_esc(eng.name)}</h1>
<p class="meta">场景包 {_esc(eng.pack.get('name', ''))} · 生成时间 {time.strftime('%Y-%m-%d %H:%M:%S')} ·
发现 {len(findings)} 项（已验证 {verified}）</p>
<h2>授权范围</h2><p>{_esc(scope_desc)}</p>
<h2>动作审计</h2><p>{_esc(audit_stats)}（完整记录：{_esc(str(eng.audit.path))}）</p>
<h2>资产覆盖度</h2>
{_coverage_table(eng)}
<h2>发现清单</h2>
{_findings_table(findings)}
{_retest_section(eng)}
<h2>利用链血缘</h2>
<pre style="font-size:.9rem;white-space:pre-wrap">{_esc(eng.ledger.lineage_summary())}</pre>
<h2>探索图</h2>
{_graph_section(eng)}
<h2>流量留痕</h2>
{_traffic_section(eng)}
</body></html>"""


def write_report(eng: Engagement, path: str | Path | None = None) -> str:
    path = Path(path) if path else eng.dir / f"report-{time.strftime('%Y%m%d-%H%M%S')}.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(eng), encoding="utf-8")
    eng.anchor_audit()  # 报告生成时锚定审计链（count, head_hash）
    return str(path)


def compare(a: Engagement, b: Engagement) -> dict:
    """复测对比：以 (target, detail) 为 key。new=本次新增，fixed=上次有而本次没有。"""

    def key(f):
        return (f.target, f.detail)

    ma = {key(f): f for f in a.ledger.findings}
    mb = {key(f): f for f in b.ledger.findings}
    return {
        "new": [asdict(mb[k]) for k in mb if k not in ma],
        "fixed": [asdict(ma[k]) for k in ma if k not in mb],
        "common": [asdict(mb[k]) for k in mb if k in ma],
    }


def render_compare_html(a: Engagement, b: Engagement) -> str:
    diff = compare(a, b)
    return f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>复测对比 - {_esc(b.name)}</title><style>{_STYLE}</style></head><body>
<h1>复测对比：{_esc(a.name)} → {_esc(b.name)}</h1>
<p class="meta">新增 {len(diff['new'])} · 已修复 {len(diff['fixed'])} · 仍存在 {len(diff['common'])}</p>
<h2>本次新增</h2>{_findings_table(diff['new'])}
<h2>已修复（上次存在，本次未复现）</h2>{_findings_table(diff['fixed'])}
<h2>仍存在</h2>{_findings_table(diff['common'])}
</body></html>"""


def write_src_md(eng: Engagement, path: str | Path | None = None) -> str:
    """SRC 平台提交格式（markdown）：按 finding 逐条可提交（标题/级别/复现/POC/证据/修复）。"""
    import time as _t

    path = Path(path) if path else eng.dir / f"src-report-{_t.strftime('%Y%m%d-%H%M%S')}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    findings = [f.__dict__ for f in eng.ledger.findings if f.severity in ("high", "critical", "medium")]
    if not findings:
        findings = [f.__dict__ for f in eng.ledger.findings]
    lines = [
        f"# 漏洞报告：{eng.name}",
        "",
        f"- 目标：{eng.cfg.get('root_domain', eng.name)}",
        f"- 授权范围：{', '.join((eng.cfg.get('scope', {}).get('domains') or [])) or '见交战配置'}",
        f"- 生成时间：{_t.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 发现总数：{len(findings)}（high/critical "
        f"{sum(1 for f in findings if f['severity'] in ('high', 'critical'))}）",
        "",
    ]
    fix_map = {
        "cracked-credential": "强制口令复杂度与定期轮换；哈希加盐升级（bcrypt/argon2）",
        "captured-ntlm-hash": "启用账户与 NTLM 审计；部署 LAPS；限制本地管理员重用",
        "authz/idor": "资源访问校验属主（服务端）；越权动作记录审计日志",
        "authz/forced-browse": "受保护资源统一服务端鉴权校验，不依赖前端隐藏",
        "secret/openai-api-key": "立即吊销泄露凭据；密钥改服务端代理下发；轮换机制",
        "injection/": "参数化查询覆盖全部输入点；输出编码；WAF 辅助",
        "kerberoastable-spn": "高权限 SPN 改 MSA；kerberoast 审计",
        "asreproastable-user": "关闭无预认证账户；预认证强制",
        "ntlm-relay-success": "启用 SMB 签名/EPA；分段隔离认证流量",
    }
    for f in findings:
        fix = next((v for k, v in fix_map.items() if k in f["detail"]), "按根因修复")
        lines += [
            f"## [{f['severity'].upper()}] {f['detail'][:80]}",
            "",
            f"- **类型**：{f['kind']}　**目标**：`{f['target']}`",
            f"- **发现 ID**：{f['id']}（{'已验证' if f['verified'] else '待验证'}）",
            f"- **证据**：`{f['evidence'] or '（见交战 evidence 目录）'}`",
            f"- **复现**：见证据文件（可复放的操作记录）",
            f"- **修复建议**：{fix}",
            "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


class ReportAdapter(ToolAdapter):
    name = "report"
    description = "生成交战 HTML 报告（台账 + 审计统计 + 证据索引），返回报告路径。"

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {"type": "object", "properties": {}}

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        if ctx.eng is None:
            return ToolResult(summary="无交战引用，无法生成报告", data={})
        path = write_report(ctx.eng)
        ctx.audit.record(self.name, args, ok=True, note=path)
        return ToolResult(
            summary=f"报告已生成: {Path(path).name}",
            data={"report": path},
            evidence=None,
        )


def write_docx(eng: Engagement, path: str | Path | None = None) -> str:
    """docx 导出（可选依赖 python-docx）。"""
    from docx import Document

    path = Path(path) if path else eng.dir / f"report-{time.strftime('%Y%m%d-%H%M%S')}.docx"
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = Document()
    doc.add_heading(f"交战报告：{eng.name}", 0)
    findings = [asdict(f) for f in eng.ledger.findings]
    verified = sum(1 for f in findings if f.get("verified"))
    doc.add_paragraph(
        f"场景包 {eng.pack.get('name', '')} · 生成时间 {time.strftime('%Y-%m-%d %H:%M:%S')} · "
        f"发现 {len(findings)} 项（已验证 {verified}）"
    )
    scope = eng.cfg.get("scope", {})
    scope_desc = ", ".join(
        (scope.get("domains") or []) + (scope.get("cidrs") or []) + (scope.get("ips") or [])
    ) or "（未声明）"
    doc.add_paragraph(f"授权范围: {scope_desc}")

    doc.add_heading("发现清单", level=1)
    table = doc.add_table(rows=1, cols=6)
    table.style = "Table Grid"
    for cell, text in zip(table.rows[0].cells, ("ID", "类型", "严重度", "目标", "详情", "已验证")):
        cell.text = text
    for f in findings:
        row = table.add_row().cells
        row[0].text = f.get("id", "")
        row[1].text = f.get("kind", "")
        row[2].text = f.get("severity", "")
        row[3].text = f.get("target", "")
        row[4].text = f.get("detail", "")
        row[5].text = "是" if f.get("verified") else "否"

    doc.add_heading("动作审计", level=1)
    ok_chain, bad = eng.audit.verify(anchors=eng.db.load_audit_anchors())
    chain_desc = "完整（哈希链校验通过）" if ok_chain else f"断裂于第 {bad} 行"
    doc.add_paragraph(f"审计链: {chain_desc}；完整记录: {eng.audit.path}")
    doc.save(str(path))
    eng.anchor_audit()  # 报告生成时锚定审计链（count, head_hash）
    return str(path)
