# sci-secure-core — 理科安全核心（纯算法层）

从「理科计算器·验证器」安全模块中剥离出的**纯加密算法函数集**，零依赖、可独立使用。

## 特点

- **零依赖**：只用 Web Crypto API（`crypto.subtle` / `getRandomValues`），不依赖任何 UI、DOM、localStorage 或宿主逻辑。
- **原文件不动**：本模块是「另编一套」的独立产物，与原 `index.html` 完全解耦。
- **可嵌套**：任何 Web 程序用 `<script type="module">` 引入即可复用同样的加密能力。

## 文件

| 文件 | 说明 |
|---|---|
| `sci-secure-core.js` | 核心模块（ES Module） |
| `test.html` | 独立测试页（8 项自检，浏览器打开即可验证） |
| `FORMAT-SPEC.md` | **跨语言数据格式规范**（信封结构/密钥派生链/实测向量，Python 等语言照此实现可互操作） |
| `reference-impl-python.py` | Python 参考实现（照 FORMAT-SPEC 编写，已交叉验证） |
| `README.md` | 本文件 |

## 版本说明 v1.1.0

- PBKDF2 默认迭代 **310000 → 600000**（OWASP 2023 建议值）。**向后兼容**：信封内自存 `iterations`，旧数据按其记录值解密，不受影响。
- 新增 **v5 信封（Argon2id）**：内存密集型 KDF，抗 GPU/ASIC 离线爆破。WebCrypto 不支持 Argon2，需宿主注入实现：
  ```js
  import * as sci from './sci-secure-core.js'
  sci.setArgon2Impl(async (pw, salt, opts) => {
    const r = await argon2id({ pass: pw, salt, mem: opts.memoryKiB, time: opts.passes, parallelism: opts.parallelism, hashLen: 32, type: 2 })
    return r.hash
  })
  const v5 = await sci.encryptEnvelopeV5(data, password, username)
  ```
  未注入时 `encryptEnvelopeV5` 抛错、不静默回退（防误以为已加固）。
- 新增 **防钓鱼安全短语** `securityPhrase(verifierB64)` → 形如「青柠·远山·星轨」。短语只绑定密码派生的验证值，钓鱼站伪造不出；用户登录后比对即可识别假站。
- 新增 `zeroize(buf)` 清零二进制缓冲区（JS 字符串不可清零，见安全设计要点）。

## 快速使用

```js
import * as sci from './sci-secure-core.js'

// 1. 密码信封加密（最简单）
const env = await sci.encryptWithPassword({ name: '张三', value: 42 }, '我的密码')
const back = await sci.decryptWithPassword(env, '我的密码')

// 2. 会话密钥 + v4 信封加密（更安全，含 AAD 元数据认证）
const sessionKey = await sci.deriveSessionKey('密码', saltB64, 310000)
const blob = await sci.encryptEnvelopeV4(data, sessionKey, '用户名', accountSaltB64)
const plain = await sci.decryptEnvelopeV4WithKey(blob, sessionKey)
```

## 主要 API

### 环境检测
- `checkCryptoSupport()` → 是否支持 Web Crypto

### 编码转换
- `bufToB64(buf)` / `b64ToBuf(b64)`
- `utf8ToB64(str)` / `b64ToUtf8(b64)`

### 密钥派生
- `pbkdf2Bits(password, salt, iterations)` → 256-bit 原始字节
- `pbkdf2AesKey(password, salt, iterations)` → AES-GCM 密钥
- `deriveIkmBits(password, saltB64, iterations)` → 中间密钥材料
- `verifierForIkm(raw)` → 验证值（与密钥分离）
- `sessionForIkm(raw)` / `deriveSessionKey(password, saltB64, iterations)` → 会话密钥

### HKDF 域分离
- `hkdfFileKeyV4(sessionKey, fileSalt)` → v4 文件密钥
- `hkdfFileKey(kdfKey, fileSalt)` → v3 文件密钥
- `hkdfTotpKey(sessionKey, salt)` → TOTP 密钥

### 信封加密
- `sealWithKey(data, key, aad)` / `openWithKey(envelope, key, aad)` — 通用
- `encryptWithPassword(data, password)` / `decryptWithPassword(envelope, password)` — 密码版（600k 迭代）
- `encryptEnvelopeV4` / `decryptEnvelopeV4WithKey` / `decryptEnvelopeV4` — v4 文件格式
- `encryptEnvelopeV5` / `decryptEnvelopeV5` — v5（Argon2id，需 `setArgon2Impl`）
- `setArgon2Impl(fn)` / `isArgon2Available()` — Argon2id 实现注入与探测
- `encryptEnvelopeV3` / `decryptEnvelopeV3WithKey` / `decryptEnvelopeV3` — v3 兼容
- `encryptTotpStore(accountsArr, sessionKey)` / `decryptTotpStore(raw, sessionKey)` — TOTP

### 防钓鱼与内存清理
- `securityPhrase(verifierB64)` → 3 词安全短语（防钓鱼）
- `zeroize(buf)` — 清零 Uint8Array/ArrayBuffer
- 常量：`PBKDF2_ITER_CURRENT`（600000）、`ARGON2_DEFAULTS`、`PHRASE_WORDS`

## 安全设计要点

1. **验证值与密钥分离**：`verifierForIkm` 用加标签的 KDF（`sci-verify-v1`），与 `sessionForIkm` 的派生输入不同，拿到验证值无法反推会话密钥。
2. **HKDF 域分离**：会话密钥、文件密钥、TOTP 密钥分别用不同的 `info` 标签（`sci-session-v1` / `sci-file-v4` / `sci-totp-v1`），防止密钥材料跨用途混淆。
3. **AAD 认证**：v4 信封把 `username/salt/iv/iterations/savedAt` 等元数据作为 GCM 附加认证数据，篡改任一字段即解密失败。
4. **密钥清零**：派生出的中间字节在导入为不可导出的 CryptoKey 后立即 `fill(0)`，减少密钥残留。

## 安全使用约定（宿主必须遵守）

1. **必须通过 HTTPS 或 file:// 运行**，纯 http 下 Web Crypto 不可用。
2. **密钥对象不可导出**：会话密钥是不可导出的 CryptoKey，宿主不应尝试导出或序列化它。
3. **密文不落明文日志**：不要在日志、错误提示中输出明文或密码。
4. **密码用完即弃**：宿主应遵循「按需密码」原则，加密完成后清除内存中的明文密码。

## 与原程序的对应关系

本模块的函数对应原 `index.html` 中以下函数（已原样抽取并去耦合）：

`checkCryptoSupport`、`bufToB64`、`b64ToBuf`、`utf8ToB64`、`b64ToUtf8`、`pbkdf2Bits`、`pbkdf2AesKey`、`deriveIkmBits`、`verifierForIkm`、`sessionForIkm`、`deriveSessionKey`、`hkdfFileKeyV4`、`hkdfFileKey`、`hkdfTotpKey`、`encryptTotpStore`、`decryptTotpStore`、`encryptBackupV4`（→`encryptEnvelopeV4`）、`decryptBackupV4WithKey`（→`decryptEnvelopeV4WithKey`）、`decryptBackupV4`（→`decryptEnvelopeV4`）、`encryptBackupV3`（→`encryptEnvelopeV3`）、`decryptBackupV3WithKey`（→`decryptEnvelopeV3WithKey`）、`decryptBackupV3`（→`decryptEnvelopeV3`）。
