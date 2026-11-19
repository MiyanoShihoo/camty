"""打包交付：zipapp（默认，纯标准库免安装）或 PyInstaller 单文件 exe。

用法:
    python scripts/build_dist.py                # dist/camty-<ver>.pyz
    python scripts/build_dist.py --mode exe     # dist/camty-<ver>.exe（需 pyinstaller）

zipapp 产物: `python camty-<ver>.pyz <子命令>`，任意 Python 3.11+ 可跑；
vendor 依赖打进包内（zipimport 支持 archive/subdir 路径项）。
engagements/ 与 packs/ 不打进包（用户工作区数据），运行目录需有 packs/，
或从 warroom 仓库根目录跑（packs 按 CWD 解析）。
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_BOOTSTRAP = '''\
import os
import sys
from pathlib import Path

# zipimport 允许 sys.path 项指向 archive 内子目录
_vendor = str(Path(__file__).parent / "vendor")
if _vendor not in sys.path:
    sys.path.insert(0, _vendor)
os.environ.setdefault("CAMTY_NO_VENDOR", "1")  # 包内 vendor 优先，跳过仓库级挂载

from camty.cli import main

main()
'''


def _stage(root_src: Path, version: str) -> Path:
    """组装 dist 临时目录：camty + vendor + packs/playbooks + __main__.py。"""
    stage = Path(tempfile.mkdtemp(prefix="camty-dist-"))
    shutil.copytree(root_src / "camty", stage / "camty",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    if (root_src / "vendor").is_dir():
        shutil.copytree(root_src / "vendor", stage / "vendor",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    else:
        (stage / "vendor").mkdir()
    for data_dir in ("packs", "playbooks"):
        if (root_src / data_dir).is_dir():
            shutil.copytree(root_src / data_dir, stage / data_dir,
                            ignore=shutil.ignore_patterns("__pycache__"))
    (stage / "__main__.py").write_text(_BOOTSTRAP, encoding="utf-8")
    (stage / "VERSION").write_text(version, encoding="utf-8")
    return stage


def build_pyz(version: str) -> Path:
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    stage = _stage(ROOT, version)
    target = dist / f"camty-{version}.pyz"
    try:
        zipapp.create_archive(str(stage), str(target),
                              interpreter=None, compressed=True)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    print(f"zipapp: {target}（{target.stat().st_size / 1e6:.1f} MB）")
    return target


def build_exe(version: str) -> Path:
    try:
        import PyInstaller  # noqa: F401
    except ImportError as exc:
        raise SystemExit(f"缺 PyInstaller: {exc}（pip install pyinstaller）") from exc
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    stage = _stage(ROOT, version)
    try:
        import subprocess

        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--noconfirm", "--clean", "--onefile",
            "--name", f"camty-{version}",
            "--paths", str(stage),          # vendor + camty 在 stage 内
            "--distpath", str(dist),
            "--workpath", str(dist / "build"),
            "--specpath", str(dist),
            str(stage / "__main__.py"),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(result.stdout[-3000:])
            print(result.stderr[-3000:])
            raise SystemExit("PyInstaller 构建失败")
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(dist / "build", ignore_errors=True)
        spec = dist / f"camty-{version}.spec"
        if spec.exists():
            spec.unlink()
    target = dist / f"camty-{version}.exe"
    print(f"exe: {target}（{target.stat().st_size / 1e6:.1f} MB）")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description="Camty 打包")
    parser.add_argument("--mode", choices=["pyz", "exe"], default="pyz")
    parser.add_argument("--version", default=None)
    args = parser.parse_args()
    version = args.version or ROOT.joinpath("camty", "__init__.py").read_text(
        encoding="utf-8").split('__version__ = "')[1].split('"')[0]
    print(f"打包 Camty v{version}（mode={args.mode}）")
    if args.mode == "exe":
        build_exe(version)
    else:
        build_pyz(version)


if __name__ == "__main__":
    main()
