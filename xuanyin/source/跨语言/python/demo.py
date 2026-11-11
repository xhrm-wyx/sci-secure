"""demo — 跨语言互通验证（Python 版）

用法：
    python demo.py ../envelope.json "CrossLang-测试123"
    python demo.py ../envelope.json "hex:43726f73..."
"""

import hashlib
import json
import sys

import sci_secure as sci


def decode_password(arg: str) -> str:
    if not arg.startswith("hex:"):
        return arg
    return bytes.fromhex(arg[4:]).decode("utf-8")


def main() -> int:
    if len(sys.argv) < 3:
        print("用法: demo.py <envelope.json> <密码|hex:...>")
        return 1

    with open(sys.argv[1], encoding="utf-8") as f:
        envelope_json = f.read()
    password = decode_password(sys.argv[2])

    env = sci.parse_envelope(envelope_json)

    ikm, session, file_key = sci.derive_keys(password, env["accountSalt"],
                                             env["iterations"], env["salt"])
    print("ikm       :", ikm.hex())
    print("sessionKey:", session.hex())
    print("fileKey   :", file_key.hex())

    try:
        plain = sci.decrypt_v4(env, password)
    except sci.SciSecureError as exc:
        print("解密失败:", exc)
        return 4

    print("plainLen  :", len(plain))
    print("plainSha  :", hashlib.sha256(plain).hexdigest())
    with open("out.txt", "wb") as f:
        f.write(plain)
    print("plaintext :", plain.decode("utf-8", "replace"))

    want = '{"roundtrip":"python","n":7}'
    env2 = sci.encrypt_v4(want.encode("utf-8"), password, "python-demo", 600_000)
    with open("roundtrip_envelope.json", "w", encoding="utf-8") as f:
        f.write(env2)
    back = sci.decrypt_v4_json(env2, password).decode("utf-8")
    print("roundtrip :", back)
    print("OK        :", back == want)
    return 0


if __name__ == "__main__":
    sys.exit(main())
