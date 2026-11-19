"""交战状态：Engagement（配置+上下文+台账）、Ledger（证据台账）。"""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from camty.adapters.base import RunContext
from camty.guardrail.audit import Audit
from camty.guardrail.scope import Scope
from camty.storage import StateDB

FINDING_KINDS = ("recon", "fingerprint", "vuln", "access", "persist")


@dataclass
class Finding:
    id: str
    kind: str
    target: str
    detail: str
    severity: str = "info"
    evidence: str | None = None
    verified: bool = False
    created_ts: str = ""
    derived_from: list[str] = field(default_factory=list)  # 血缘：本 finding 派生自哪些 finding
    disposal: str = "open"  # 处置状态：open / fixed（复测判定已修复）


class Ledger:
    """证据台账。利用级动作必须引用这里的 verified finding ID；
    derived_from 记录利用链血缘（验证 → 利用 → 后渗透的派生关系）。"""

    def __init__(self, findings: list[Finding] | None = None):
        self.findings = findings or []
        self._lock = threading.Lock()

    def add(
        self,
        kind: str,
        target: str,
        detail: str,
        severity: str = "info",
        evidence: str | None = None,
        verified: bool = False,
        derived_from: list[str] | None = None,
    ) -> str:
        import time

        with self._lock:  # 并行批下防 F-ID 冲突
            fid = f"F-{len(self.findings) + 1:03d}"
            self.findings.append(
                Finding(fid, kind, target, detail, severity, evidence, verified,
                        time.strftime("%Y-%m-%d %H:%M:%S"), list(derived_from or []))
            )
        return fid

    def verified_ids(self) -> set[str]:
        return {f.id for f in self.findings if f.verified}

    def lineage_summary(self) -> str:
        """血缘链视图：F-003 ← F-001（利用链派生关系）。"""
        lines = []
        for f in self.findings:
            if f.derived_from:
                lines.append(f"{f.id} ← {' ← '.join(f.derived_from)}  [{f.detail[:60]}]")
        return "\n".join(lines) if lines else "（无派生链）"

    def summary(self) -> str:
        if not self.findings:
            return "（暂无发现）"
        rows = []
        for f in self.findings:
            chain = f"  ←{'←'.join(f.derived_from)}" if f.derived_from else ""
            rows.append(f"{f.id} [{f.kind}][{f.severity}] {f.target} - {f.detail}{chain}")
        return "\n".join(rows)


class Engagement:
    """一次交战：配置 + 运行上下文 + 台账 + 护栏 + SQLite 断点。"""

    def __init__(self, cfg_path: str | Path):
        self.cfg_path = Path(cfg_path)
        self.cfg = yaml.safe_load(self.cfg_path.read_text(encoding="utf-8"))
        self.name = self.cfg.get("name", self.cfg_path.stem)
        self.dir = self.cfg_path.parent / self.name
        self.pack = self._load_pack(self.cfg["pack"])
        self.context: dict = {
            k: v for k, v in self.cfg.items() if isinstance(v, (str, int, float, bool))
        }
        self.ledger = Ledger()
        self.scope = Scope(self.cfg.get("scope", {}))
        self.audit = Audit(self.dir / "audit.jsonl")
        self.db = StateDB(self.dir / "state.db")
        from camty.agent.assets import AssetGraph

        self.assets = AssetGraph(self.db)
        self.ctx = RunContext(self.scope, self.audit, self.dir / "evidence", ledger=self.ledger, eng=self)
        self._load_state()

    def _load_pack(self, pack_name: str) -> dict:
        for root in (self.cfg_path.parent.parent, Path.cwd()):
            path = root / "packs" / pack_name / "pack.yaml"
            if path.exists():
                return yaml.safe_load(path.read_text(encoding="utf-8"))
        raise FileNotFoundError(f"找不到场景包 packs/{pack_name}/pack.yaml")

    def phase(self, phase_id: str) -> dict:
        for ph in self.pack["phases"]:
            if ph["id"] == phase_id:
                return ph
        available = [p["id"] for p in self.pack["phases"]]
        raise KeyError(f"场景包 {self.pack['name']} 无阶段 {phase_id}，可用: {available}")

    def _load_state(self) -> None:
        self.context.update(self.db.load_context())
        self.ledger.findings = [Finding(**f) for f in self.db.load_findings()]

    def save_state(self) -> None:
        self.db.update_context(self.context)
        self.db.sync_findings([asdict(f) for f in self.ledger.findings])

    def mark_step(self, phase_id: str, step_index: int, status: str = "done") -> None:
        self.db.mark_step(phase_id, step_index, status)

    def completed_steps(self, phase_id: str) -> dict[int, str]:
        return self.db.completed_steps(phase_id)

    def clear_phase(self, phase_id: str) -> None:
        self.db.clear_phase(phase_id)

    def close(self) -> None:
        self.db.close()
