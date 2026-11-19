"""密钥 vault 加密（需 cryptography 包；未安装时明文兜底并提示风险）。

格式：{"encrypted": true, "salt": <b64>, "payload": <fernet token>}
主密钥来自环境变量 CAMTY_MASTER_KEY。
"""

from __future__ import annotations

import base64
import hashlib
import os

PBKDF2_ROUNDS = 600_000


def _fernet_cls():
    try:
        from cryptography.fernet import Fernet

        return Fernet
    except ImportError:
        return None


HAS_CRYPTO = _fernet_cls() is not None


def _derive_key(master: str, salt: bytes) -> bytes:
    raw = hashlib.pbkdf2_hmac("sha256", master.encode("utf-8"), salt, PBKDF2_ROUNDS, 32)
    return base64.urlsafe_b64encode(raw)


def encrypt_text(text: str, master: str) -> dict:
    Fernet = _fernet_cls()
    if Fernet is None:
        raise RuntimeError("cryptography 未安装: pip install cryptography")
    salt = os.urandom(16)
    token = Fernet(_derive_key(master, salt)).encrypt(text.encode("utf-8")).decode("ascii")
    return {"encrypted": True, "salt": base64.b64encode(salt).decode("ascii"), "payload": token}


def decrypt_text(blob: dict, master: str) -> str:
    Fernet = _fernet_cls()
    if Fernet is None:
        raise RuntimeError("vault 已加密但本机未安装 cryptography: pip install cryptography")
    salt = base64.b64decode(blob["salt"])
    return Fernet(_derive_key(master, salt)).decrypt(blob["payload"].encode("ascii")).decode("utf-8")
