# sci-secure-lib — 可嵌套的完整安全库

从「理科计算器·验证器」剥离出的**完整三层安全库**，供其他程序直接嵌套引用。原文件不动，本库是独立产物。

## 与 sci-secure-core 的区别

| | sci-secure-core | sci-secure-lib（本库） |
|---|---|---|
| 定位 | 纯算法函数集（L1） | 完整三层安全库（L1+L2+L3） |
| 用法 | 手动调用加密函数 | 面向对象的 `SecureVault` 类 |
| 状态管理 | 无（宿主自理） | 内置会话密钥生命周期（登录/锁定） |
| 存储 | 无 | 可插拔存储适配器 |

## 三层结构

- **L1 纯算法**：PBKDF2、HKDF、AES-GCM、验证值分离等密码学原语（内联在 index.js）
- **L2 会话管理**：`SecureVault` 类的登录/锁定/加密/解密，会话密钥是不可导出的 CryptoKey
- **L3 存储适配**：默认 localStorage，可传入自定义 storage 替换

## 快速使用

```js
import { SecureVault } from './index.js'

// 1. 创建一个保险库实例（可指定自己的存储键，避免与其他程序冲突）
const vault = new SecureVault({ storageKey: 'my-app-vault' })

// 2. 注册 / 登录
await vault.register('alice', '密码123')
// 或
await vault.login('alice', '密码123')

// 3. 加密数据（自动生成 v4 信封，含 AAD 认证）
const blob = await vault.encrypt({ note: '机密内容' })

// 4. 锁定（清除内存中的会话密钥和明文）
vault.lock()

// 5. 重新登录后解密
await vault.login('alice', '密码123')
const plain = await vault.decrypt(blob)   // { note: '机密内容' }

// 6. TOTP 账号加密存储
const enc = await vault.encryptTotp([{ id: 'a1', name: 'GitHub', secret: '...' }])
const accounts = await vault.decryptTotp(enc)
```

## 版本说明 v1.1.0

- **本地登录防爆破**：连续失败后指数退避（第 n 次等 `min(2^(n-1)s, 30s)`），失败记录持久化到存储适配器；正确登录自动清零。可用 `loginBackoff: false` 关闭。
- **自动锁定**：`idleTimeoutMs`（默认 10 分钟，0=禁用）空闲超时 + 切后台/切标签页即锁（`lockOnHidden`）；锁定原因（`manual`/`idle`/`hidden`）通过 `onLock` 回调通知宿主，宿主应在回调里清空界面上的明文 DOM。
- **防钓鱼安全短语**：`getSecurityPhrase(username)` → 形如「青柠·远山·星轨」。用户记住自己的短语，登录后比对，不一致说明在假站。
- **TOTP 明文用后清理**：`disposeTotp(arr)` 尽力破坏数组中的敏感字符串引用。
- **Trusted Types 支持**：`createTrustedTypesPolicy(name)` 配合 CSP `require-trusted-types-for 'script'` 从浏览器层面堵 DOM-XSS；不支持时返回 null 优雅降级。
- PBKDF2 默认迭代 310000 → **600000**（OWASP 2023 建议值），旧账号按各自存储值兼容。

## API 一览

| 方法 | 说明 |
|---|---|
| `new SecureVault({ storageKey, storage, idleTimeoutMs, lockOnHidden, loginBackoff, onLock })` | 构造实例 |
| `isSupported()` | 是否支持加密（需 HTTPS） |
| `register(username, password)` | 注册并建立会话 |
| `login(username, password)` | 登录（先查退避，再校验密码） |
| `verifyPassword(username, password)` | 仅校验密码（返回布尔值） |
| `lock(reason?)` | 锁定，清空内存密钥，触发 `onLock(reason)` |
| `isUnlocked()` | 是否已登录 |
| `getSecurityPhrase(username?)` | 当前账号的防钓鱼安全短语 |
| `disposeTotp(accountsArr)` | 尽力清除 TOTP 明文字符串引用 |
| `encrypt(dataObj)` | 加密数据（v4 信封，60 万迭代） |
| `decrypt(blob, password?)` | 解密（优先会话密钥，回退密码） |
| `encryptTotp(accountsArr)` | 加密 TOTP 账号数组 |
| `decryptTotp(raw)` | 解密 TOTP 账号数组 |
| `deleteAccount(username)` | 删除账号（含失败记录） |
| 属性 `locked` / `currentUser` | 当前状态 |

### 模块级导出
- `SecureVault`（默认导出）
- `createTrustedTypesPolicy(name)` — Trusted Types policy
- `securityPhrase(verifierB64)` — 由验证值派生 3 词安全短语
- `zeroize(buf)` — 清零二进制缓冲区

## 安全设计要点

1. **会话密钥不可导出**：`sessionKey` 是 `extractable: false` 的 CryptoKey，宿主无法导出。
2. **验证值与密钥分离**：存储的 `verifier` 用加标签 KDF（`sci-verify-v1`），与 `sessionKey` 派生输入不同。
3. **HKDF 域分离**：会话/文件/TOTP 分别用不同 `info` 标签。
4. **AAD 认证**：v4 信封元数据全部参与 GCM 认证，篡改即解密失败。
5. **锁定即清密钥**：`lock()` 把会话密钥和当前用户引用全部置空，明文密码不驻留。

## 安全使用约定（宿主必须遵守）

1. 通过 **HTTPS 或 file://** 运行。
2. **不要导出、序列化、打印** `sessionKey` 或明文密码。
3. 遵循「按需密码」：加密完成后尽快 `lock()`。
4. 如需替换存储，自定义 storage 必须实现 `getItem/setItem/removeItem`，且**不要记录明文**。
5. 本库负责「数据加密」；宿主仍需自行处理 CSP、防 XSS 等宿主级安全。

## 嵌套示例（完整 HTML）

```html
<script type="module">
  import { SecureVault } from './index.js'
  const vault = new SecureVault({ storageKey: 'your-app-vault' })
  await vault.register('user', 'secret123')
  const blob = await vault.encrypt({ data: 'protected' })
  console.log('密文：', blob.data.slice(0, 20) + '…')
</script>
```

## 与原程序的对应关系

本库对应原 `index.html` 中以下能力（去耦合后重新组织）：

- 密码派生：`pbkdf2Bits` / `deriveIkmBits` / `deriveSessionKey`
- 验证值：`verifierForIkm`（对应原 `verifyPasswordOnly` 的逻辑）
- 文件信封：`encryptBackupV4` / `decryptBackupV4WithKey` / `decryptBackupV4`（→ `encrypt` / `decrypt`）
- TOTP 信封：`encryptTotpStore` / `decryptTotpStore`（→ `encryptTotp` / `decryptTotp`）
- 会话生命周期：`registerUser` / `loginUser` / `lockNow`（→ `register` / `login` / `lock`）
