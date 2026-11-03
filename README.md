# 理科安全（sci-secure）

从单文件离线应用「理科计算器·验证器」中**剥离**出来的加密模块，独立成库，供任何 Web 程序直接嵌套复用。

原程序是一份 ~950KB 的单 HTML 文件，安全逻辑与计算逻辑写在一起，无法复用。这里把其中的密码学部分完整抽出、重写成两个互不依赖宿主代码的包：一个纯算法层，一个带会话生命周期的完整安全库。

- **零依赖**：只用浏览器/Node 内置的 Web Crypto API，不引第三方密码库
- **零 DOM**：不碰界面、不碰 localStorage（除非你显式给它存储适配器）
- **可互操作**：数据格式有独立规范，Python 参考实现已交叉验证，不用 JS 也能解开

---

## 目录

| 路径 | 说明 |
|---|---|
| [`core/`](core/) | **sci-secure-core** — 纯算法层（L1），函数式调用，无状态 |
| [`lib/`](lib/) | **sci-secure-lib** — 完整三层安全库（L1+L2+L3），`SecureVault` 类 |
| [`core/FORMAT-SPEC.md`](core/FORMAT-SPEC.md) | 跨语言数据格式规范：信封结构、密钥派生链、实测向量 |
| [`core/reference-impl-python.py`](core/reference-impl-python.py) | Python 参考实现，照规范编写并已交叉验证 |
| [`dist/`](dist/) | npm 打包产物（`npm pack` 生成，可直接 `npm install ./xxx.tgz`） |
| [`index.html`](index.html) | 在线说明页，同时用作静态站点首页 |

两个包怎么选：

| | sci-secure-core | sci-secure-lib |
|---|---|---|
| 定位 | 纯算法函数集 | 完整安全库 |
| 用法 | 手动调加密函数 | 面向对象的 `SecureVault` |
| 状态 | 无状态，宿主自理 | 内置登录/锁定/会话密钥生命周期 |
| 存储 | 不管 | 可插拔存储适配器（默认 localStorage） |
| 适合 | 只想加解密一段数据 | 要做一套带账号的应用 |

---

## 密码学设计

| 环节 | 算法 / 参数 |
|---|---|
| 口令派生 | PBKDF2-HMAC-SHA256，**600000 次迭代**（OWASP 2023 建议值） |
| 密钥分离 | HKDF-SHA256，按用途分域（会话 / 文件 v3 / v4 / v5 / TOTP / Argon2id） |
| 对称加密 | AES-256-GCM，96 位 IV，128 位认证标签，**元数据走 AAD 认证** |
| 会话密钥 | 不可导出的 `CryptoKey`（`extractable: false`），JS 拿不到原始字节 |
| 校验口令 | 与加密密钥**分离派生**，验证值不可反推密钥 |
| 可选 KDF | Argon2id（内存密集，抗 GPU/ASIC），需宿主注入 WASM 实现 |
| 完整性 | Ed25519 签名（原程序发布包用，本仓库不含私钥） |

信封是**自描述**的：`iterations`、`salt`、`iv`、`version` 全部写在密文头部，所以升级 KDF 强度不会让旧数据失效——旧信封按它自己记录的迭代数解密，新信封用新强度。

版本对照：

| 版本 | 密钥来源 | 说明 |
|---|---|---|
| v2 | 口令直派生 | 最早期格式，仍可解 |
| v3 | 口令派生 + HKDF | 引入文件密钥分域 |
| v4 | 会话密钥 + AAD | 元数据参与认证，防篡改 |
| v5 | Argon2id | 内存密集，需注入实现 |

---

## 快速开始

### 纯算法层

```js
import * as sci from './core/sci-secure-core.js'

// 最简单的口令加密
const env = await sci.encryptWithPassword({ name: '张三', value: 42 }, '我的密码')
const back = await sci.decryptWithPassword(env, '我的密码')

// 会话密钥 + v4 信封（元数据受 AAD 保护）
const sessionKey = await sci.deriveSessionKey('密码', saltB64, 600000)
const blob = await sci.encryptEnvelopeV4(data, sessionKey, '用户名', accountSaltB64)
const plain = await sci.decryptEnvelopeV4WithKey(blob, sessionKey)
```

### 完整安全库

```js
import { SecureVault } from './lib/index.js'

const vault = new SecureVault({ storageKey: 'my-app-vault' })
await vault.register('alice', '密码123')          // 注册（新账号自动用 600000 迭代）
await vault.login('alice', '密码123')             // 登录，会话密钥进入内存

const blob = await vault.encrypt({ note: '机密内容' })
vault.lock()                                      // 锁定：丢弃会话密钥

await vault.login('alice', '密码123')
const data = await vault.decrypt(blob)
```

`SecureVault` 额外提供：登录失败指数退避、空闲/切后台自动锁定、防钓鱼安全短语、TOTP 密钥托管、Trusted Types 策略。

### 浏览器里直接验证

`core/test.html` 和 `lib/test.html` 是自包含测试页，用浏览器打开即跑，不需要装东西。

---

## 安全边界（请务必读）

这套东西保护的是**拿到密文的人**，不是拿到你设备的人。它做不到的事：

1. **JS 字符串无法清零**。`zeroize()` 只能清 `Uint8Array`，口令一旦变成 JS 字符串就交给 GC 了，清不掉。这是语言限制，不是实现偷懒。
2. **本机被控则无解**。内存里存在明文和会话密钥，浏览器扩展、注入脚本、调试端口都能读。
3. **登录退避可绕过**。退避记录在 localStorage，攻击者清掉记录或直接对着密文爆破即可跳过；真正的下限由 KDF 强度决定。
4. **Argon2id 默认未生效**。WebCrypto 没有 Argon2，必须自己注入 WASM 实现，否则用 PBKDF2。
5. **口令强度仍是最弱一环**。600000 次迭代只是把单次猜测成本提高约 2 倍，弱口令照样被字典打穿。
6. **需要 HTTPS**。Web Crypto 的 `crypto.subtle` 只在安全上下文可用（`localhost` 例外）。

---

## 版本

| 版本 | 变更 |
|---|---|
| 1.1.0 | PBKDF2 默认 310000 → 600000（向后兼容）；新增 v5/Argon2id 信封、防钓鱼安全短语、`zeroize`；lib 增加登录退避、自动锁定、`disposeTotp`、Trusted Types |
| 1.0.0 | 从主程序剥离，core 与 lib 双包成型 |

---

## 许可证

MIT，见 [LICENSE](LICENSE)。

---

## 说明

本仓库是独立产物，与主程序「理科计算器·验证器」互不依赖：主程序的 `index.html` 未因剥离而改动，两个包也不引用主程序的任何代码。剥离的目的是让这套加密逻辑能被别的程序复用，以及接受独立审查。
