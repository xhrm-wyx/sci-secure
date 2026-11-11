"""玄印（sci-secure）v4 信封跨语言实现（Python 版）
================================================================

与 JavaScript 版 sci-secure-core.js 完全互通：

    IKM        = PBKDF2-HMAC-SHA256(password, accountSalt, iterations, 32)
    sessionKey = HKDF-SHA256(IKM,        salt=空,     info="sci-session-v1", 32)
    fileKey    = HKDF-SHA256(sessionKey, salt=文件盐, info="sci-file-v4",    32)
    AAD        = 固定键序的元数据 JSON
    密文        = AES-256-GCM(fileKey, iv, plaintext, AAD)，输出 密文||16字节tag

依赖：cryptography（仅用于 AES-GCM；PBKDF2 与 HKDF 均可用标准库替代，见下）
安装：pip install cryptography

用法：
    import sci_secure
    plain = sci_secure.decrypt_v4_json(open('a.sci.json', encoding='utf-8').read(), '密码')
    blob  = sci_secure.encrypt_v4('你好'.encode('utf-8'), '密码', 'alice')
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MIN_ITERATIONS = 50_000
MAX_ITERATIONS = 1_000_000
DEFAULT_ITERATIONS = 600_000
TAG_LEN = 16
KEY_LEN = 32

SESSION_INFO = b"sci-session-v1"
FILE_INFO = b"sci-file-v4"


class SciSecureError(Exception):
    """解密或参数错误。认证失败（密码错/被篡改）会抛出 AUTH_FAILED 前缀的异常。"""


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SciSecureError(f"不是合法 base64: {exc}") from exc


def clamp_iterations(n: int) -> int:
    """迭代次数钳制到 [50000, 1000000]，防止恶意信封让客户端卡死。"""
    return max(MIN_ITERATIONS, min(MAX_ITERATIONS, int(n)))


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int = KEY_LEN) -> bytes:
    """标准 RFC 5869 HKDF-SHA256（不引入第三方实现，便于跨语言对照）。"""
    salt = salt or b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def build_aad(username: str, account_salt: str, salt: str, iv: str,
              iterations: int, saved_at: int) -> bytes:
    """构造 AAD。

    键序固定为 v / username / accountSalt / salt / iv / iterations / savedAt。
    用 ensure_ascii=False 且紧凑分隔符，使其与 JS 的 JSON.stringify 逐字节一致。
    """
    payload = {
        "v": 4,
        "username": username,
        "accountSalt": account_salt,
        "salt": salt,
        "iv": iv,
        "iterations": iterations,
        "savedAt": saved_at,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def derive_keys(password: str, account_salt_b64: str, iterations: int,
                file_salt_b64: str) -> Tuple[bytes, bytes, bytes]:
    """三级派生，返回 (ikm, sessionKey, fileKey)。"""
    acct_salt = _b64d(account_salt_b64)
    file_salt = _b64d(file_salt_b64)
    it = clamp_iterations(iterations)

    ikm = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), acct_salt, it, KEY_LEN)
    session = hkdf_sha256(ikm, None, SESSION_INFO)
    file_key = hkdf_sha256(session, file_salt, FILE_INFO)
    return ikm, session, file_key


def parse_envelope(data: str | bytes) -> Dict[str, Any]:
    """解析信封 JSON，校验版本。"""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    try:
        env = json.loads(data)
    except json.JSONDecodeError as exc:
        raise SciSecureError(f"信封 JSON 解析失败: {exc}") from exc
    if not isinstance(env, dict):
        raise SciSecureError("信封必须是一个 JSON 对象")
    if env.get("v") != 4:
        raise SciSecureError(f"不支持的信封版本 v{env.get('v')}（本实现仅支持 v4）")
    for k in ("accountSalt", "salt", "iv", "data"):
        if not isinstance(env.get(k), str):
            raise SciSecureError(f"信封缺少字段 {k}")
    return env


def decrypt_v4(env: Dict[str, Any], password: str) -> bytes:
    """解密 v4 信封，返回明文字节。密码错误或数据被篡改时抛 SciSecureError。"""
    if env.get("v") != 4:
        raise SciSecureError(f"不支持的信封版本 v{env.get('v')}（本实现仅支持 v4）")

    _, _, file_key = derive_keys(password, env["accountSalt"], env.get("iterations", DEFAULT_ITERATIONS),
                                 env["salt"])
    iv = _b64d(env["iv"])
    if len(iv) != 12:
        raise SciSecureError(f"iv 应为 12 字节，实际 {len(iv)}")
    blob = _b64d(env["data"])
    if len(blob) < TAG_LEN:
        raise SciSecureError("密文长度不足，缺少认证标签")

    aad = build_aad(env.get("username", ""), env["accountSalt"], env["salt"], env["iv"],
                    int(env.get("iterations", DEFAULT_ITERATIONS)), int(env.get("savedAt", 0)))
    try:
        return AESGCM(file_key).decrypt(iv, blob, aad)
    except Exception as exc:  # noqa: BLE001
        raise SciSecureError("认证失败：密码错误或数据已被篡改") from exc


def decrypt_v4_json(envelope_json: str | bytes, password: str) -> bytes:
    """便捷函数：信封 JSON 文本 + 密码 → 明文。"""
    return decrypt_v4(parse_envelope(envelope_json), password)


def encrypt_v4(plain: bytes, password: str, username: str = "",
               iterations: int = DEFAULT_ITERATIONS, saved_at: int | None = None) -> str:
    """加密为 v4 信封 JSON（缩进两格）。"""
    it = clamp_iterations(iterations if iterations > 0 else DEFAULT_ITERATIONS)
    if saved_at is None:
        saved_at = int(time.time() * 1000)

    acct_salt = os.urandom(16)
    file_salt = os.urandom(32)
    iv = os.urandom(12)

    acct_b64 = _b64e(acct_salt)
    salt_b64 = _b64e(file_salt)
    iv_b64 = _b64e(iv)

    _, _, file_key = derive_keys(password, acct_b64, it, salt_b64)
    aad = build_aad(username, acct_b64, salt_b64, iv_b64, it, saved_at)
    sealed = AESGCM(file_key).encrypt(iv, plain, aad)

    env = {
        "v": 4,
        "username": username,
        "accountSalt": acct_b64,
        "salt": salt_b64,
        "iv": iv_b64,
        "iterations": it,
        "savedAt": saved_at,
        "data": _b64e(sealed),
    }
    return json.dumps(env, ensure_ascii=False, indent=2)
