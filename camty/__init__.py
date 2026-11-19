"""Camty — 红队交战工作台."""

from __future__ import annotations

import os
import sys
from pathlib import Path

__version__ = "0.2.0"

# vendor 依赖挂载：pip --target 装进仓库 vendor/ 的依赖优先于全局/用户 site
# （CAMTY_NO_VENDOR=1 临时禁用，回退系统环境）
_VENDOR = Path(__file__).resolve().parent.parent / "vendor"
if _VENDOR.is_dir() and not os.environ.get("CAMTY_NO_VENDOR"):
    _vendor_str = str(_VENDOR)
    if _vendor_str not in sys.path:
        sys.path.insert(0, _vendor_str)
