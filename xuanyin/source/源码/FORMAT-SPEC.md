# 玄印（sci-secure）跨语言数据格式规范 v1.0

> 本文档定义 `sci-secure-core` / `sci-secure-lib` 产生的密文**二进制/JSON 数据格式**与**密码学参数**，
> 目标是让**任何语言**（Python / C / Java / Go / Rust / …）都能实现与浏览器端**完全互操作**的加解密。
>
> 对应实现：`sci-secure-core.js`（Web Crypto）· 主程序「理科计算器·验证器」v3.5.x。

---

## 0. 术语与约定

| 术语 | 含义 |
|---|---|
| **信封（envelope）** | 一个自描述的密文 JSON 对象，包含算法版本、盐、IV、密文等所有解密所需元数据 |
| **IKM** | Input Keying Material，PBKDF2 派生的中间密钥材料 |
| **会话密钥（session key）** | 由 IKM 经 HKDF 派生的不可导出密钥，用于派生文件/TOTP 子密钥 |
| **AAD** | Additional Authenticated Data，AES-GCM 的附加认证数据，用于绑定元数据防篡改 |
| **Base64** | 标准 Base64（RFC 4648），字符集 `A-Za-z0-9+/`，必要时 `=` 填充 |

**字节序**：所有字节序列均为**大端序（big-endian）网络序**；本规范涉及的所有"拼接"均指**字节串直接连接**（`||`）。

**字符编码**：所有字符串字段（密码、用户名、JSON）均使用 **UTF-8**。

---

## 1. 密码学原语与参数（固定不变）

| 项 | 值 |
|---|---|
| 密码 KDF | **PBKDF2-HMAC-SHA256** |
| PBKDF2 迭代次数 | **310000**（写入信封的 `iterations` 字段，读取时钳制在 `[50000, 1000000]`） |
| PBKDF2 输出长度 | 256 bit（32 字节） |
| 子密钥 KDF | **HKDF-SHA256** |
| 数据加密算法 | **AES-256-GCM** |
| AES-GCM IV 长度 | **96 bit（12 字节）** |
| AES-GCM tag 长度 | **128 bit（16 字节）**（WebCrypto 默认） |
| 盐长度 | 文件盐 32 字节；密码盐 16 字节 |
| 会话密钥派生 info | `"sci-session-v1"`（UTF-8） |
| 验证值派生方式 | `SHA256("sci-verify-v1" || IKM)`（不是 HKDF，见 §4） |

---

## 2. 信封 JSON 结构

### 2.1 v4 信封（当前版本，`encryptEnvelopeV4`）

```json
{
  "v": 4,
  "username": "alice",
  "accountSalt": "<Base64>",
  "salt": "<Base64: 32字节文件盐>",
  "iv": "<Base64: 12字节IV>",
  "iterations": 310000,
  "savedAt": 1699000000000,
  "data": "<Base64: 密文（含16字节GCM tag）>"
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `v` | int | 格式版本号，恒为 `4` |
| `username` | string | 用户名（参与 AAD） |
| `accountSalt` | string(Base64) | 账号盐，用于派生会话密钥（见 §3） |
| `salt` | string(Base64) | 文件盐（32 字节），作为 HKDF 的 salt |
| `iv` | string(Base64) | AES-GCM IV（12 字节） |
| `iterations` | int | PBKDF2 迭代次数 |
| `savedAt` | int | 保存时间戳（毫秒，Unix epoch），参与 AAD |
| `data` | string(Base64) | 密文 = `AES-GCM-Encrypt(plaintext) || 16字节tag` |

**明文**：`data` 解密后是 **UTF-8 编码的 JSON 字符串**（即加密前对数据对象做了 `JSON.stringify`）。

### 2.2 v3 信封（旧格式，兼容保留）

与 v4 结构**完全相同**，仅 `"v": 3`，且子密钥派生的 HKDF info 为 `"sci-file-v3"`（见 §3.2）。其余字段一致。

### 2.3 密码直密格式（`encryptWithPassword`，无会话层）

```json
{
  "kdf": "pbkdf2-sha256",
  "iterations": 310000,
  "salt": "<Base64: 16字节>",
  "iv": "<Base64: 12字节>",
  "data": "<Base64: 密文>"
}
```

此格式**不经过 HKDF**，直接用 `PBKDF2(password, salt, iter) → AES-256 密钥` 加密。明文是 UTF-8 JSON 字符串。

### 2.4 TOTP 存储信封（`encryptTotpStore`）

```json
{
  "v": 1,
  "kdf": "session-hkdf",
  "salt": "<Base64: 16字节>",
  "iv": "<Base64: 12字节>",
  "data": "<Base64: 密文>",
  "locked": false
}
```

明文是 TOTP 账号数组的 UTF-8 JSON。子密钥派生见 §3.4。

### 2.5 v5 信封（Argon2id，可选高级格式）

```json
{
  "v": 5,
  "kdf": "argon2id",
  "memoryKiB": 19456,
  "passes": 2,
  "parallelism": 1,
  "username": "alice",
  "salt": "<Base64: 32字节（同时作为 Argon2 盐与 HKDF 盐）>",
  "iv": "<Base64: 12字节>",
  "savedAt": 1699000000000,
  "data": "<Base64: 密文>"
}
```

派生链：`master = Argon2id(password, salt, {memoryKiB, passes, parallelism})`（32 字节）
→ `fileKey = HKDF-SHA256(master, salt, info="sci-file-v5")` → AES-256-GCM。
AAD 为规范化元数据（键顺序：`v, kdf, memoryKiB, passes, parallelism, username, salt, iv, savedAt`）。
主密钥在派生后立即清零。

---

## 3. 密钥派生算法链（实现互操作的关键）

### 3.1 由密码派生会话密钥

```
IKM = PBKDF2-HMAC-SHA256(password, salt=accountSalt字节, iterations, dkLen=32字节)
sessionKey = HKDF-SHA256(IKM, salt=空(0字节), info="sci-session-v1", L=32字节)
```

> **注意**：`accountSalt` 是 Base64 字符串，实现时先 `base64_decode` 得到原始字节再作为 PBKDF2 的 salt。
> `iterations` 取信封中的值，并钳制到 `[50000, 1000000]`。

### 3.2 由会话密钥派生文件密钥（v4）

```
fileKey = HKDF-SHA256(sessionKey, salt=文件salt字节, info="sci-file-v4", L=32字节)
```

HKDF 的 `info` 分别为：
- v4：`"sci-file-v4"`
- v3：`"sci-file-v3"`

### 3.3 会话密钥在 HKDF 中的角色

`sessionKey` 本身是 HKDF 的 **IKM 输入**（即 `HKDF-Extract` 的输入密钥材料）。在 WebCrypto 中它被 `importKey` 为一个 HKDF 密钥，然后 `deriveKey(..., {name:'AES-GCM',length:256})`。

> 跨语言实现要点：HKDF 的 **Extract 阶段 salt 是「文件盐」**，**info 是 `"sci-file-v4"`**，**输出 32 字节**作为 AES-256 密钥。

### 3.4 TOTP 子密钥

```
totpKey = HKDF-SHA256(sessionKey, salt=TOTP盐字节, info="sci-totp-v1", L=32字节)
```

---

## 4. 验证值（verifier）派生

验证值**不是**用 HKDF 派生的，而是：

```
verifier = Base64( SHA256( "sci-verify-v1"(UTF-8) || IKM ) )
```

用途：服务端/本地只存 `verifier`，凭它可**校验密码正确性**却**无法反推会话密钥**（单向、域分离）。校验密码时：用输入的密码重新派生 IKM → 计算 verifier → 与存储值比对。

---

## 5. AES-GCM 加密/解密细节

### 加密（encrypt）

```
plaintext = UTF8(JSON.stringify(dataObj))
iv = Random(12字节)
aad = UTF8(canonicalMeta)      # 见 §5.3
ciphertext = AES-256-GCM-Encrypt(key=fileKey, iv, plaintext, aad)  # 输出含16字节tag
envelope.data = Base64(ciphertext)
```

### 解密（decrypt）

```
重建 aad（用信封里的元数据，见 §5.3）
plaintext = AES-256-GCM-Decrypt(key=fileKey, iv, envelope.data, aad)
dataObj = JSON.parse(UTF8(plaintext))
```

**任何 AAD 不匹配、密文被篡改、tag 校验失败，解密必须失败并报错**（这正是防篡改的核心）。

### 5.3 AAD 的精确字节构造（互操作最关键点）

AAD 是**规范化元数据**的 UTF-8 字节。规范化的关键在于：**字段顺序、字段名、数值类型必须与下列模板严格一致**。

v4 的 AAD = UTF8 编码的以下 JSON（键顺序固定）：

```json
{"v":4,"username":"<原样>","accountSalt":"<原样Base64>","salt":"<原样Base64>","iv":"<原样Base64>","iterations":310000,"savedAt":1699000000000}
```

> 实现要点：
> 1. **键顺序固定**为 `v, username, accountSalt, salt, iv, iterations, savedAt`（与 JS `meta` 对象字面量顺序一致）。
> 2. `iterations` 是**数字**（不带引号）；`savedAt` 是**数字**（不带引号）。
> 3. 字符串值**原样保留**（不要二次 base64 解码，直接用信封里的字符串）。
> 4. **不要**添加多余空格、不要改变键名拼写。
> 5. v3 的 AAD 仅 `v` 为 `3`，其余相同。

> 若你的语言用「有序 JSON 序列化」而非逐字节拼字符串，务必确保与上述模板**逐字节相等**（含无空格）。最稳妥的做法是**手动拼接字符串**而非依赖 JSON 库的序列化顺序。

---

## 6. 完整性校验（Ed25519，独立于信封）

主程序另有 Ed25519 数字签名用于**发布包完整性**校验（`integrity.txt` / SRI），它**独立于**本信封格式，属于部署层而非数据层。跨语言接入信封加密**不需要**实现 Ed25519。

---

## 7. 互操作测试向量（自检用）

> 以下向量为**真实实测值**（由本库生成，并经 Python `cryptography` 50.0.2 交叉验证通过）。
> 实现者可用它们逐步自检派生链。所有字节序列均为十六进制（`hex`）。

**测试向量 A —— PBKDF2 派生：**

```
password   = "interop-test-密码"  (UTF-8)
salt       = 202122232425262728292a2b2c2d2e2f  (16字节)
iterations = 310000
IKM = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
    = 6c4df6bbbf74ea9ee7eef87563bd07798f1cb510d8435cea2b23d4c4ba30d8f2
```

**测试向量 B —— HKDF 会话密钥与文件密钥：**

```
sessionKey = HKDF-SHA256(IKM, salt=空, info="sci-session-v1", L=32)
           = 71be251131673a25a0da730b36cecb07e05317e1c4fe8ba4d8afbc5b236e12df

fileSalt   = 000102...1f  (32字节: 0x00 递增到 0x1f)
fileKey    = HKDF-SHA256(sessionKey, salt=fileSalt, info="sci-file-v4", L=32)
           = cac4bc4bc8bbc1cb291706c53d70df9827f8e2f612ae9f7efa3b5bbcb3b4ca77
```

**测试向量 C —— 验证值：**

```
verifier = Base64( SHA256("sci-verify-v1" || IKM) )
         = LjYN1CSrR0RXAPPn7cjbh4gVkS3HAXn70x2IFGLCJWM=
```

> 互操作验证记录（2026-11-03）：
> - JS → Python：IKM / sessionKey / fileKey / verifier 四个中间向量逐字节一致，
>   AES-256-GCM 解密还原成功，AAD 篡改被拒。**7/7 通过**。
> - Python → JS（库正式 API `decryptEnvelopeV4`）：解密成功，错误密码被拒。**2/2 通过**。
> - 密码直密格式与 TOTP 信封格式：Python 侧独立实现解密成功。**2/2 通过**。

---

## 8. 安全注意事项（跨语言实现必读）

1. **盐必须唯一**：每次加密都生成新的随机盐/IV，绝不复用（IV 复用 + AES-GCM 会直接灾难）。
2. **密钥材料用完清零**：IKM、派生的中间字节在内存中用完立即 `fill(0)` 或等价清零。
3. **会话密钥不可导出**：本格式的 `sessionKey` 仅存在于内存，任何实现都**不要**把它持久化或序列化。
4. **比对验证值用恒定时间比较**：校验 verifier 时避免普通 `==`，用恒定时间比较防时序侧信道。
5. **AAD 逐字节一致**：§5.3 的规范是互操作的命门，任何 JSON 序列化顺序差异都会导致解密失败。
6. **不要降级**：不接受 `iterations < 50000`（读取时钳制，见 §3.1）。

---

## 附录：字段速查

| 信封版本 | 子密钥 info | 说明 |
|---|---|---|
| v5 | `sci-file-v5` | Argon2id KDF（需注入实现），抗 GPU 爆破 |
| v4 | `sci-file-v4` | 当前默认（PBKDF2 600000 迭代） |
| v3 | `sci-file-v3` | 旧格式（PBKDF2 310000 迭代），兼容 |
| 会话密钥 | `sci-session-v1` | 从 IKM 派生 |
| TOTP | `sci-totp-v1` | TOTP 子密钥 |
| 验证值 | `sci-verify-v1`（SHA256 拼接，非 HKDF） | 单向校验 |

> PBKDF2 迭代：v1.1.0 起默认 **600000**（OWASP 2023 建议）；信封自存 `iterations`，
> 读取时钳制在 `[50000, 1000000]`，旧信封按自身记录值解密，互不影响。
