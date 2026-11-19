"""外部工具解析：工具目录 → 用户 pip Scripts → PATH。

工具目录来自环境变量 CAMTY_TOOLS_DIR（os.pathsep 分隔多个目录：
Windows 为 ;，POSIX 为 :），未设置时无默认目录。另自动纳入用户
site 的脚本目录（Windows Scripts / POSIX bin，pip --user 安装的
安全工具脚本，如 impacket 的 GetUserSPNs.py）。
"""

from __future__ import annotations

import os
import shutil
import site
from pathlib import Path

DEFAULT_TOOLS_DIRS = []


class ToolUnavailable(RuntimeError):
    pass


def _user_scripts_dir() -> Path | None:
    try:
        if os.name == "nt":
            candidate = Path(site.USER_SITE).parent / "Scripts"
        else:
            candidate = Path(site.USER_BASE) / "bin"  # Linux: ~/.local/bin
        return candidate if candidate.is_dir() else None
    except Exception:  # noqa: BLE001 - site 布局差异/-S 下 USER_BASE 为 None 等不阻塞
        return None


def _vendor_bin_dir() -> Path | None:
    """vendor 化依赖的脚本目录（pip --target 落点）。"""
    candidate = Path(__file__).resolve().parent.parent / "vendor" / "bin"
    return candidate if candidate.is_dir() else None


def tools_dirs() -> list[Path]:
    raw = os.environ.get("CAMTY_TOOLS_DIR", "")
    if raw.strip():
        dirs = [Path(p.strip()) for p in raw.split(os.pathsep) if p.strip()]
    else:
        dirs = [Path(d) for d in DEFAULT_TOOLS_DIRS]
    for extra in (_vendor_bin_dir(), _user_scripts_dir()):
        if extra and extra not in dirs:
            dirs.append(extra)
    return dirs


def find_tool(name: str) -> str | None:
    """返回工具可执行文件路径；工具目录（根 + 一层子目录）找不到再查 PATH。"""
    exe = name if name.lower().endswith(".exe") or "." in name else (
        name + (".exe" if os.name == "nt" else "")
    )
    for base in tools_dirs():
        if not base.is_dir():
            continue
        direct = base / exe
        if direct.is_file():
            return str(direct)
        for sub in base.iterdir():
            if sub.is_dir():
                cand = sub / exe
                if cand.is_file():
                    return str(cand)
                script = sub / name
                if name.lower().endswith(".py") and script.is_file():
                    return str(script)
    found = shutil.which(name)
    return str(found) if found else None
