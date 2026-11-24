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


class TestRunCmdRobustness(unittest.TestCase):
    """P2-7：run_cmd 输出满 64KB 后继续 drain 管道；60s 超时杀进程并标注；259 不当退出码。"""

    def test_drains_pipe_after_buffer_full(self):
        src = read(BEACON_C)
        self.assertIn("static int pipe_read_once", src)
        self.assertIn("PeekNamedPipe(out_rd, NULL, 0, NULL, &avail, NULL)", src,
                      "读循环必须经 PeekNamedPipe 探测（轮询结构才能带截止时间）")
        self.assertIn("dst = discard;", src, "缓冲写满后必须读入 discard 丢弃（drain）")
        self.assertIn("if (dst != discard) *total += n;", src,
                      "丢弃路径不得推进输出长度")

    def test_timeout_kills_and_annotates(self):
        src = read(BEACON_C)
        self.assertIn("#define CMD_TIMEOUT_MS 60000", src)
        self.assertIn("DWORD deadline = GetTickCount() + CMD_TIMEOUT_MS;", src)
        self.assertIn("TerminateProcess(pi.hProcess, (UINT)-1);", src,
                      "超时后必须终止子进程（避免僵尸/永久占用信标线程）")
        self.assertIn('"\\n(timeout killed)"', src)
        self.assertIn("(timeout killed)", src, "输出必须标注超时杀死")

    def test_still_active_not_reported_as_exit_code(self):
        src = read(BEACON_C)
        self.assertIn("(code == STILL_ACTIVE) ? -1 : (int)code", src,
                      "STILL_ACTIVE(259) 是运行中哨兵值，不得当真实退出码上报")
        self.assertIn("*exit_code = -1;", src, "超时路径没有可信退出码，上报 -1")

    def test_build_beacon_json_escapes_all_fields(self):
        src = read(BEACON_C)
        func = src[src.index("static void build_beacon_json"):src.index("int main(void)")]
        for field in ("e_host", "e_user", "e_arch", "e_id"):
            self.assertIn(f"json_escape(", func)
            self.assertIn(field, func, f"build_beacon_json 必须转义后使用 {field}")
        # snprintf 只允许吃转义后的变量（格式串按 C 源码原样匹配）
        fmt = r'"{\"id\":\"%s\",\"host\":\"%s\",\"user\":\"%s\",\"arch\":\"%s\",\"sleep\":%d}"'
        self.assertIn(fmt, func)
        self.assertIn("e_id, e_host, e_user, e_arch, sleep)", func)
        # 恶意主机/用户名转义后可能变长：beacon_json 缓冲相应放大，sleep 字段不被截断
        self.assertIn("char *beacon_json = (char *)malloc(4096);", src)
        self.assertIn("build_beacon_json(beacon_json, 4096,", src)


class TestApiTokenCompare(unittest.TestCase):
    """P2-8：operator API token 比较改恒时（hmac.compare_digest，UTF-8 字节）。"""

    @staticmethod
    def _handler(auth_value):
        import types

        import sys as _sys
        from pathlib import Path as _Path

        _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent / "c2" / "server"))
        import camty_c2

        handler = camty_c2.ApiHandler.__new__(camty_c2.ApiHandler)  # 跳过 socket 初始化
        handler.headers = {"Authorization": auth_value} if auth_value is not None else {}
        handler.server = types.SimpleNamespace(token="sekret-token-123")
        return handler

    def test_compare_digest_in_source(self):
        src = read(ROOT / "c2" / "server" / "camty_c2.py")
        self.assertIn("import hmac", src)
        self.assertIn("hmac.compare_digest(", src, "token 比较必须恒时")
        self.assertIn('auth.encode("utf-8")', src,
                      "必须按 UTF-8 字节比较（compare_digest 的 str 形式对非 ASCII 会 TypeError）")

    def test_authorized_exact_match(self):
        self.assertTrue(self._handler("Bearer sekret-token-123")._authorized())

    def test_authorized_rejects_variants(self):
        for header in ("Bearer sekret-token-124", "Bearer sekret", "",
                       "bearer sekret-token-123", "Bearer  sekret-token-123", None):
            self.assertFalse(self._handler(header)._authorized(), f"应拒绝 {header!r}")

    def test_authorized_non_ascii_no_500(self):
        """非 ASCII 头按字节比较返回 False，不得抛 TypeError（否则对应 500）。"""
        self.assertFalse(self._handler("Bearer tokén")._authorized())


if __name__ == "__main__":
    unittest.main()
