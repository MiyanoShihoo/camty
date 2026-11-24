"""C2 植入体/服务端加固回归守卫。

C 侧（beacon.c / crypto.c）在 Linux CI 上无法编译 Win32 目标，pytest 用例
用源码级断言锁定关键安全语义（同类做法见 tests/test_panel.py 的静态插值清单）；
运行时验证由本机构建 + 真实 E2E（tests/test_c2_implant.py）覆盖。
"""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BEACON_C = ROOT / "c2" / "implant" / "beacon.c"
CRYPTO_C = ROOT / "c2" / "implant" / "crypto.c"
CRYPTO_H = ROOT / "c2" / "implant" / "crypto.h"
BUILD_PS1 = ROOT / "c2" / "implant" / "build.ps1"
BUILD_PY = ROOT / "c2" / "implant" / "build_beacon.py"
DESIGN = ROOT / "docs" / "c2-design.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class TestCsprngSubstitution(unittest.TestCase):
    """P1-6：IV 与 beacon id 的随机源必须换出 rand()（多植入体共享 PSK 时 IV 复用风险）。

    协议字节格式保持不变：IV 仍 16 字节、beacon id 仍为 host-%04X（16 位十六进制）。
    """

    def test_iv_uses_csprng(self):
        src = read(CRYPTO_C)
        self.assertIn("int cmt1_random_bytes(uint8_t *buf, size_t n)", src)
        self.assertIn(
            "if (cmt1_random_bytes(iv, CMT1_IV_LEN) != 0) return -1;", src,
            "cmt1_seal 的 IV 必须经 cmt1_random_bytes 填充（fail-closed）",
        )
        self.assertNotIn("iv[i] = (uint8_t)rand()", src, "IV 不得再来自 rand()")

    def test_csprng_sources(self):
        src = read(CRYPTO_C)
        self.assertIn("BCryptGenRandom", src, "主随机源必须是 BCryptGenRandom")
        self.assertIn("SystemFunction036", src, "兜底随机源必须是 RtlGenRandom/SystemFunction036")
        self.assertIn("CMT1_NO_BCRYPT", src, "必须支持构建链不支持 bcrypt 时的编译期回退")

    def test_header_declares_csprng(self):
        src = read(CRYPTO_H)
        self.assertIn("int cmt1_random_bytes(uint8_t *buf, size_t n);", src)

    def test_beacon_id_uses_csprng(self):
        src = read(BEACON_C)
        self.assertIn(
            "if (cmt1_random_bytes(id_rand, sizeof id_rand) != 0) return 1;", src,
            "beacon id 随机字节必须经 cmt1_random_bytes",
        )
        self.assertIn('snprintf(id, sizeof id, "%s-%04X", host,', src,
                      "beacon id 的线上格式必须保持 host-%04X")
        self.assertNotIn('(unsigned)rand() & 0xFFFF', src, "beacon id 不得再来自 rand()")

    def test_rand_only_for_jitter(self):
        import re

        code = re.sub(r"/\*.*?\*/", "", read(BEACON_C), flags=re.S)  # 去块注释
        code = re.sub(r"//[^\n]*", "", code)                          # 去行注释
        self.assertEqual(1, code.count("srand("), "srand 应只播种一次（jitter 用）")
        self.assertEqual(1, code.count("rand()"), "rand() 应只出现一次")
        idx = code.index("rand()")
        self.assertTrue(code.index("DWORD jitter") < idx < code.index("Sleep(jitter)"),
                        "rand() 必须只出现在 jitter 计算里")

    def test_build_scripts_link_bcrypt_with_fallback(self):
        for path, libline in ((BUILD_PS1, "-lws2_32 -lwinhttp -lbcrypt -ladvapi32"),
                              (BUILD_PY, '"-lws2_32", "-lwinhttp", "-lbcrypt", "-ladvapi32"')):
            src = read(path)
            self.assertIn(libline, src, f"{path.name} 必须链接 bcrypt/advapi32")
            self.assertIn("CMT1_NO_BCRYPT", src, f"{path.name} 必须带 bcrypt 不可用时的回退")

    def test_design_doc_boundary_updated(self):
        src = read(DESIGN)
        self.assertNotIn("IV 来自 `rand()`", src)
        self.assertIn("BCryptGenRandom", src)


if __name__ == "__main__":
    unittest.main()
