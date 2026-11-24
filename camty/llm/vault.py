"""密钥 vault 加密（需 cryptography 包）。

格式：{"encrypted": true, "salt": <b64>, "payload": <fernet token>}
主密钥来自环境变量 CAMTY_MASTER_KEY。

写入语义（P2-8 收紧）：cryptography 缺失时默认拒绝写入新密钥（RuntimeError，
提示安装 cryptography）；仅当显式设置 CAMTY_ALLOW_PLAINTEXT_KEYS=1 才允许
明文兜底（返回 {"encrypted": false, "payload": ...} 标记 blob 并发 warning）。
已加密 vault 拒绝降级为明文的既有行为（router.save 的 was_encrypted 检查）不变。
"""

from __future__ import annotations

import base64
import hashlib
import os
import warnings

PLAINTEXT_ENV = "CAMTY_ALLOW_PLAINTEXT_KEYS"
PBKDF2_ROUNDS = 600_000


def _fernet_cls():
    try:
        from cryptography.fernet import Fernet

        return Fernet
    except ImportError:
        return None


HAS_CRYPTO = _fernet_cls() is not None


def plaintext_fallback_allowed() -> bool:
    """明文兜底必须显式 opt-in：仅当 CAMTY_ALLOW_PLAINTEXT_KEYS 恰为 "1"。"""
    return os.environ.get(PLAINTEXT_ENV, "") == "1"


def _derive_key(master: str, salt: bytes) -> bytes:
    raw = hashlib.pbkdf2_hmac("sha256", master.encode("utf-8"), salt, PBKDF2_ROUNDS, 32)
    return base64.urlsafe_b64encode(raw)


def encrypt_text(text: str, master: str) -> dict:
    Fernet = _fernet_cls()
    if Fernet is None:
        if plaintext_fallback_allowed():
            warnings.warn(
                f"cryptography 未安装，密钥将以明文写入（{PLAINTEXT_ENV}=1）；"
                "请尽快安装 cryptography 并加密 vault",
                stacklevel=2,
            )
            return {"encrypted": False,
                    "warning": f"明文存储（{PLAINTEXT_ENV}=1）",
                    "payload": text}
        raise RuntimeError(
            "cryptography 未安装，默认拒绝以明文写入密钥: pip install cryptography；"
            f"如确需明文兜底，显式设置 {PLAINTEXT_ENV}=1"
        )
    salt = os.urandom(16)
    token = Fernet(_derive_key(master, salt)).encrypt(text.encode("utf-8")).decode("ascii")
    return {"encrypted": True, "salt": base64.b64encode(salt).decode("ascii"), "payload": token}


def decrypt_text(blob: dict, master: str) -> str:
    if blob.get("encrypted") is False:
        # encrypt_text 明文兜底产生的标记 blob：写入时已获显式同意，读取不设二次门禁
        return blob["payload"]
    Fernet = _fernet_cls()
    if Fernet is None:
        raise RuntimeError("vault 已加密但本机未安装 cryptography: pip install cryptography")
    salt = base64.b64decode(blob["salt"])
    return Fernet(_derive_key(master, salt)).decrypt(blob["payload"].encode("ascii")).decode("utf-8")
