# -*- coding: utf-8 -*-
# Python 参考实现：严格按 FORMAT-SPEC.md 实现 sci-secure v4 信封解密
# 目标：读取 JS 生成的 vector-js.json，验证密钥派生链逐字节一致，并成功解密密文。
import json, base64, hashlib, sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64d(s): return base64.b64decode(s)
def b64e(b): return base64.b64encode(b).decode('ascii')
def hexb(b): return b.hex()

def hkdf_sha256(ikm, salt, info, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length,
                salt=salt if salt else None, info=info).derive(ikm)

def main(path):
    doc = json.load(open(path, encoding='utf-8'))
    env, vec = doc['envelope'], doc['vectors']
    results = []
    def check(name, got, want):
        ok = (got == want)
        results.append((ok, name))
        print(('PASS ' if ok else 'FAIL ') + name)
        if not ok:
            print('  got :', got)
            print('  want:', want)
        return ok

    # 1) PBKDF2 -> IKM
    ikm = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=bytes.fromhex(vec['accountSaltBytes']),
                     iterations=env['iterations']).derive(vec['password'].encode('utf-8'))
    check('IKM 派生 (PBKDF2-HMAC-SHA256)', hexb(ikm), vec['ikm'])

    # 2) HKDF -> session key (salt=None 等价 0 字节, info=sci-session-v1)
    sk = hkdf_sha256(ikm, None, b'sci-session-v1')
    check('会话密钥派生 (HKDF salt=空)', hexb(sk), vec['sessionKey'])

    # 3) HKDF -> file key (salt=文件盐, info=sci-file-v4)
    fk = hkdf_sha256(sk, bytes.fromhex(vec['fileSalt']), b'sci-file-v4')
    check('文件密钥派生 (HKDF info=sci-file-v4)', hexb(fk), vec['fileKey'])

    # 4) verifier = SHA256("sci-verify-v1" || IKM)
    verifier = b64e(hashlib.sha256(b'sci-verify-v1' + ikm).digest())
    check('验证值派生 (SHA256 拼接)', verifier, vec['verifier'])

    # 5) AAD 规范化重建（键顺序固定，数字不带引号，无空格）
    aad_json = ('{"v":4,"username":"%s","accountSalt":"%s","salt":"%s","iv":"%s",'
                '"iterations":%d,"savedAt":%d}') % (
        env['username'], env['accountSalt'], env['salt'], env['iv'],
        env['iterations'], env['savedAt'])
    aad = aad_json.encode('utf-8')

    # 6) AES-256-GCM 解密
    pt = AESGCM(fk).decrypt(base64.b64decode(env['iv']), base64.b64decode(env['data']), aad)
    pt_str = pt.decode('utf-8')
    check('密文解密还原', pt_str, vec['plaintextJson'])
    data_obj = json.loads(pt_str)
    check('明文 JSON 结构', data_obj, json.loads(vec['plaintextJson']))

    # 7) 篡改 AAD 必须失败
    tampered_aad = aad_json.replace('"iterations":310000', '"iterations":310001').encode('utf-8')
    try:
        AESGCM(fk).decrypt(base64.b64decode(env['iv']), base64.b64decode(env['data']), tampered_aad)
        check('AAD 篡改被拒', False, True)
    except Exception:
        check('AAD 篡改被拒', True, True)

    n_pass = sum(1 for ok, _ in results if ok)
    print('\n=== Python 解密侧: %d/%d 通过 ===' % (n_pass, len(results)))
    sys.exit(0 if n_pass == len(results) else 1)

if __name__ == '__main__':
    main(sys.argv[1])
