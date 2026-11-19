"""ASCII 启动横幅与状态面板。"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

RED = "\033[31m"
GRAY = "\033[90m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"

LOGO = r"""
 ██████╗  █████╗ ███╗   ███╗ ███████╗ ██╗   ██╗
██╔════╝ ██╔══██╗████╗ ████║╚══██╔══╝ ╚██╗ ██╔╝
██║      ███████║██╔████╔██║   ██║     ╚████╔╝
██║      ██╔══██║██║╚██╔╝██║   ██║      ╚██╔╝
╚██████╗ ██║  ██║██║ ╚═╝ ██║   ██║       ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝       ╚═╝
"""

TAGLINES = (
    "证据优先 · 断点续跑 · 全程留痕",
    "打点有痕 · 越界必拦 · 范围即法律",
    "让普通队员打出老手判断",
)


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _status_lines() -> list[str]:
    from camty import __version__
    from camty.adapters.registry import REGISTRY
    from camty.llm.router import LLMRouter

    ready = [a.name for a in REGISTRY.values() if a.available()]
    total = len(REGISTRY)
    try:
        providers = [
            f"{n}({c.kind})" for n, c in LLMRouter().providers.items()
        ] or ["未配置（python -m camty keys set）"]
    except Exception:  # noqa: BLE001 - 加密 vault 无主密钥等，不阻塞启动
        providers = ["vault 加密，需 CAMTY_MASTER_KEY"]
    engagements_dir = Path("engagements")
    n_eng = len(list(engagements_dir.glob("*.yaml"))) if engagements_dir.is_dir() else 0
    tagline = TAGLINES[int(time.strftime("%j")) % len(TAGLINES)]
    tools_desc = ", ".join(ready) if ready else "无（外部工具放 E:/AI tools 或设 CAMTY_TOOLS_DIR）"
    return [
        f"Camty v{__version__} · 红队交战工作台 · {tagline}",
        f"[工具] {len(ready)}/{total} 就绪: {tools_desc}",
        f"[模型] {', '.join(providers)}",
        f"[交战] {n_eng} 个配置（engagements/）",
    ]


def show(no_banner: bool = False) -> None:
    if no_banner or os.environ.get("CAMTY_NO_BANNER"):
        return
    color = _use_color()
    logo = f"{RED}{BOLD}{LOGO}{RESET}" if color else LOGO
    lines = _status_lines()
    if color:
        lines = [f"{CYAN}{line}{RESET}" if i == 0 else f"{GRAY}{line}{RESET}" for i, line in enumerate(lines)]
    print(logo)
    print("\n".join(lines))
    print()
