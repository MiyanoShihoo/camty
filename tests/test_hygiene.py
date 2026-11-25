"""测试卫生守卫：tests/ 内禁止 Windows 盘符字面量（大写字母+冒号+反斜杠）。

盘符路径把某台机器的绝对路径焊进测试，Linux/CI 上语义漂移（反斜杠被
当作文件名的一部分），造成平台性红绿差异。R3 批次已清理两处：docstring
里的工具安装目录、vendor 根路径断言（后者改用 tempfile/Path 平台原生
构造）。确需 Windows 盘符字面量的测试必须进 DRIVE_LETTER_WHITELIST，
且被豁免文件内必须带 skipUnless(os.name == "nt") 或等价平台防护。
"""

import re
import unittest
from pathlib import Path

DRIVE_LETTER_RE = re.compile(r"[A-Z]:\\")

# 显式白名单：{相对 tests/ 的 posix 路径: 豁免原因}。当前为空。
# 被豁免文件必须含 skipUnless（或等价平台防护），守卫会做文本检查；
# 白名单不是绕过守卫的口子，而是给"确需 Windows 字面量"的测试留的
# 显式登记位。
DRIVE_LETTER_WHITELIST = {}


class TestDriveLetterHygiene(unittest.TestCase):
    def test_no_drive_letter_literals(self):
        base = Path(__file__).resolve().parent
        offenders = []
        for path in sorted(base.rglob("*.py")):
            rel = path.relative_to(base).as_posix()
            text = path.read_text(encoding="utf-8", errors="replace")
            if rel in DRIVE_LETTER_WHITELIST:
                self.assertIn(
                    "skipUnless", text,
                    f"白名单文件 {rel} 必须包含 skipUnless 平台防护")
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if DRIVE_LETTER_RE.search(line):
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
        self.assertEqual(
            offenders, [],
            "tests/ 内发现 Windows 盘符字面量（跨平台语义漂移，见文件头"
            "docstring）：\n" + "\n".join(offenders) + "\n如确需保留，请加入 "
            "DRIVE_LETTER_WHITELIST 并给该文件加 skipUnless 防护。")


class TestReadmeCountConsistency(unittest.TestCase):
    """README 的 tests badge 与正文计数必须一致（防单边更新漂移）。

    权威计数以全依赖主环境为准；本守卫做静态一致性：
    badge 数字 == 正文两处测试计数；正文套件数 == tests/ 实际文件数。
    增删测试文件时 README 两处需同步——守卫保证漏改必红。
    """

    def _readme(self, name):
        root = Path(__file__).resolve().parent.parent
        return (root / name).read_text(encoding="utf-8")

    def test_badge_matches_body_counts(self):
        for name, pats in (
            ("README.md", [r"tests-(\d+)%20passed", r"(\d+) 项自检", r"(\d+) 项测试"]),
            ("README.en.md", [r"tests-(\d+)%20passed", r"(\d+)-test self check", r"(\d+) tests \("]),
        ):
            text = self._readme(name)
            counts = set()
            for pat in pats:
                m = re.search(pat, text)
                self.assertIsNotNone(m, f"{name} 未找到计数: {pat}")
                counts.add(int(m.group(1)))
            self.assertEqual(len(counts), 1, f"{name} badge 与正文计数不一致: {sorted(counts)}")

    def test_suite_count_matches_files(self):
        root = Path(__file__).resolve().parent.parent
        n_files = len(list((root / "tests").glob("test_*.py")))
        for name, pat in (
            ("README.md", r"(\d+) 个套件"),
            ("README.en.md", r"(\d+) suites"),
        ):
            m = re.search(pat, self._readme(name))
            self.assertIsNotNone(m, f"{name} 未找到套件数")
            self.assertEqual(int(m.group(1)), n_files,
                             f"{name} 套件数与 tests/ 文件数({n_files})不一致")


if __name__ == "__main__":
    unittest.main()
