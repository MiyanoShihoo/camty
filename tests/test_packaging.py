"""打包测试：zipapp 构建产物自举（构建 → 归档校验 → CLI 冒烟）。"""

from __future__ import annotations

import runpy
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestPackaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scripts.build_dist import build_pyz

        cls.target = build_pyz("test")  # dist/camty-test.pyz（不复用正式版本号）

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "target", None) and cls.target.exists():
            cls.target.unlink()

    def test_archive_layout(self):
        with zipfile.ZipFile(self.target) as zf:
            names = zf.namelist()
            self.assertIn("__main__.py", names)
            self.assertTrue(any(n.startswith("camty/cli.py") for n in names),
                            "camty 包应在归档内")
            self.assertTrue(any(n.startswith("vendor/") for n in names),
                            "vendor 依赖应在归档内")
            self.assertTrue(any(n.startswith("packs/") for n in names))

    def test_cli_smoke_via_runpy(self):
        """zipapp 自举：vendor 挂载 + CLI 子命令可跑（等价 python camty.pyz keys list）。"""
        saved_argv = list(sys.argv)
        try:
            sys.argv = ["camty-test.pyz", "--no-banner", "keys", "list"]
            runpy.run_path(str(self.target), run_name="__main__")
        finally:
            sys.argv = saved_argv

    def test_bootstrap_sets_vendor(self):
        with zipfile.ZipFile(self.target) as zf:
            bootstrap = zf.read("__main__.py").decode("utf-8")
        self.assertIn("vendor", bootstrap)
        self.assertIn("camty.cli", bootstrap)


if __name__ == "__main__":
    unittest.main()
