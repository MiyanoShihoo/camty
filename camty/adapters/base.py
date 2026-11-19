"""ToolAdapter 协议与运行上下文。"""

from __future__ import annotations

import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from camty.tools import ToolUnavailable, find_tool


@dataclass
class ToolResult:
    summary: str
    data: dict = field(default_factory=dict)
    evidence: str | None = None


class RunContext:
    """适配器运行时依赖：范围校验、审计留痕、证据归档、台账与交战引用。"""

    def __init__(self, scope, audit, evidence_dir, ledger=None, eng=None):
        self.scope = scope
        self.audit = audit
        self.evidence_dir = Path(evidence_dir)
        self.ledger = ledger
        self.eng = eng

    def save_evidence(self, adapter_name: str, content: str) -> str:
        import re

        stamp = time.strftime("%Y%m%d-%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(adapter_name))  # Windows 文件名净化
        out = self.evidence_dir / f"{stamp}-{safe}.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        return str(out)


class ToolAdapter(ABC):
    name: str = ""
    tool_name: str = ""          # 实际二进制名，默认与 name 相同
    description: str = ""
    requires_confirm: bool = False
    requires_finding: bool = False   # 利用级：必须引用台账 verified finding

    @abstractmethod
    def tool_schema(self) -> dict:
        """JSON Schema 参数定义（不含 name/description）。"""

    @property
    def binary_name(self) -> str:
        return self.tool_name or self.name

    def binary(self) -> str:
        """解析工具路径，找不到给出明确指引。"""
        resolved = find_tool(self.binary_name)
        if not resolved:
            raise ToolUnavailable(
                f"工具未安装: {self.binary_name}（搜索目录与 PATH，见 camty/tools.py）"
            )
        return resolved

    def available(self) -> bool:
        return find_tool(self.binary_name) is not None

    @abstractmethod
    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        ...

    def tool_def(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.tool_schema(),
            },
        }


ANSI_RE = __import__("re").compile(r"\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """剥 ANSI 颜色码（PD 系工具即使 -silent 也可能输出颜色）。"""
    return ANSI_RE.sub("", text)


def run_cmd(cmd: list[str], timeout: int = 1800) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    output = proc.stdout or ""
    if proc.stderr and proc.stderr.strip():
        output += "\n[stderr]\n" + proc.stderr
    return proc.returncode, output
