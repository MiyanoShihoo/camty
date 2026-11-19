"""黑板继承 + 台账压缩摘要（ARTEX blackboard/compaction 语义的 Camty 落地）。

- Blackboard：跨唤醒/跨 worker 的持久观察（WAF 检出、限流节奏、登录态失效…）。
  planner 每轮唤醒都能看到全部历史观察（继承）；worker 通过 blackboard-note 工具写入，
  后续意图与规划轮共享。持久在 state.db，断点续跑不丢。
- ledger_digest：台账无损压缩视图。小台账给全量；大台账（> limit_full）按
  verified 优先、严重度排序给出头部明细 + 全量聚合计数 + 血缘链，
  替代此前 `summary()[:1500]` 的硬截断（长交战下后面的 finding 会整条丢失）。
"""

from __future__ import annotations

from camty.agent.state import Engagement

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Blackboard:
    """跨唤醒持久观察板：planner/worker/retester 共享继承。"""

    def __init__(self, eng: Engagement):
        self.eng = eng
        self.db = eng.db

    def add(self, kind: str, note: str, source: str | None = None) -> int:
        return self.db.add_note(kind, note[:800], source)

    def notes(self, kind: str | None = None, limit: int = 50) -> list[dict]:
        return self.db.load_notes(kind, limit=limit)

    def summary(self, limit: int = 12) -> str:
        """注入决策面的紧凑视图：最近的观察在最后（时间正序展示）。"""
        notes = list(reversed(self.db.load_notes(limit=limit)))
        if not notes:
            return ""
        lines = [f"[{n['kind']}] {n['note']}" for n in notes]
        return "黑板（跨意图持久观察，规划与执行必须先看它）:\n" + "\n".join(lines)


def ledger_digest(eng: Engagement, limit_full: int = 20, limit_head: int = 12) -> str:
    """台账压缩视图：小台账全量；大台账头部明细 + 聚合计数 + 血缘。

    与 `summary()[:N]` 的区别：任何 finding 都至少计入聚合计数，
    高危/verified 永远保留明细——不再无感丢失后面的发现。
    """
    findings = eng.ledger.findings
    if len(findings) <= limit_full:
        return eng.ledger.summary()
    verified = [f for f in findings if f.verified]
    # 明细头部：verified 优先，同组内按严重度
    head = sorted(verified, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))[:limit_head]
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    sev_stats = "，".join(f"{sev}×{n}" for sev, n in
                         sorted(by_sev.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))
    lines = [
        f"台账共 {len(findings)} 项（verified {len(verified)}/{len(findings)}；{sev_stats}）——已压缩，明细只列最重要的 {len(head)} 项："
    ]
    for f in head:
        chain = f" ←{'←'.join(f.derived_from)}" if f.derived_from else ""
        lines.append(f"{f.id} [{f.kind}][{f.severity}] {f.target} - {f.detail}{chain}")
    lineage = eng.ledger.lineage_summary()
    if lineage and lineage != "（无派生链）":
        lines.append(f"血缘链:\n{lineage[:600]}")
    return "\n".join(lines)
