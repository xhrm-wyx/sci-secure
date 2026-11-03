/* =====================================================================
 * sci-secure-lib  —  可嵌套的完整安全库
 * ---------------------------------------------------------------------
 * 从「理科计算器·验证器」剥离出的完整三层安全库，供其他程序直接嵌套引用。
 *
 * 三层结构：
 *   L1 纯算法（crypto-core.js）         —— 密码学原语
 *   L2 会话管理（session.js）           —— 会话密钥生命周期 + 信封加解密
 *   L3 存储适配（storage.js）           —— 可插拔的存储接口（默认 localStorage）
 *
 * 对外统一入口（index.js）暴露一个 SecureVault 类：
 *
 *   import { SecureVault } from './index.js'
 *   const vault = new SecureVault({ storageKey: 'my-app-vault' })
 *   await vault.register('alice', '密码123')
 *   await vault.lock()                    // 锁定（清内存）
 *   await vault.unlock('alice', '密码123') // 解锁（重建会话密钥）
 *
 * 版本：v1.0.0（对应原程序 v3.5.5 的安全能力）
 * ===================================================================== */

/* ========================= L1 纯算法（内联） ========================= */

const PBKDF2_ITER = 310000;
/** 当前默认迭代（OWASP 2023 建议值）。旧账号按各自存储的 iterations 解密，不受影响 */
const PBKDF2_ITER_CURRENT = 600000;
const VERIFY_TAG = '\u0001sci-verify';
const INFO = {
  session: 'sci-session-v1',
  fileV3: 'sci-file-v3',
  fileV4: 'sci-file-v4',
  totp: 'sci-totp-v1',
};

/** 64 词防钓鱼安全短语词表（双字中文词，便于人眼比对） */
const PHRASE_WORDS = [
  '青柠', '远山', '星轨', '白鹭', '松果', '溪石', '暮云', '灯塔',
  '枫叶', '竹影', '海雾', '萤火', '麦田', '雪岭', '荷塘', '石墨',
  '晨露', '飞雁', '沙洲', '极光', '梧桐', '潮汐', '岩层', '炊烟',
  '冰川', '蝉鸣', '芦苇', '月桂', '峡谷', '银杏', '浪涛', '蜂巢',
  '苔原', '纸鸢', '琥珀', '雨林', '钟乳', '麋鹿', '沙丘', '曜石',
  '薄暮', '矢车', '虹桥', '陨石', '藤蔓', '鲸落', '杉林', '霜花',
  '砾石', '鹤唳', '珊瑚', '麦浪', '雾凇', '獐岛', '弦月', '溪谷',
  '槿花', '磷火', '峦嶂', '鸥群', '茜草', '湍流', '蓼蓝', '磐石',
];

/** 本地登录退避参数：第 n 次失败后等待 min(2^(n-1)s, 30s) */
const LOGIN_BACKOFF_BASE_MS = 1000;
const LOGIN_BACKOFF_MAX_MS = 30000;

function checkCryptoSupport() {
  return !!(typeof window !== 'undefined' && window.crypto && window.crypto.subtle && window.crypto.getRandomValues);
}

function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64ToBuf(b64) {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

/** 由验证值派生防钓鱼安全短语（3 词）。钓鱼站不知密码就伪造不出同一短语 */
async function securityPhrase(verifierB64) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', b64ToBuf(verifierB64)));
  const bits = (digest[0] << 16) | (digest[1] << 8) | digest[2];
  return PHRASE_WORDS[(bits >> 12) & 63] + '·' + PHRASE_WORDS[(bits >> 6) & 63] + '·' + PHRASE_WORDS[bits & 63];
}

/**
 * 创建 Trusted Types policy（浏览器支持时）。
 * 宿主配合 CSP `require-trusted-types-for 'script'` 使用，从浏览器层面堵死 DOM-XSS。
 * 不支持时返回 null（优雅降级）。
 */
export function createTrustedTypesPolicy(name) {
  if (typeof window === 'undefined' || !window.trustedTypes || !window.trustedTypes.createPolicy) return null;
  return window.trustedTypes.createPolicy(name || 'sci-secure', {
    createHTML: (s) => s,
    createScript: (s) => s,
    createScriptURL: (s) => s,
  });
}

/** 尽力清零二进制缓冲区（JS 字符串不可清零，见 README 说明） */
export function zeroize(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
  else if (buf instanceof ArrayBuffer) new Uint8Array(buf).fill(0);
}

function pbkdf2Bits(password, salt, iterations) {
  const enc = new TextEncoder();
  const saltBuf = salt instanceof Uint8Array ? salt : new Uint8Array(salt);
  return crypto.subtle
    .importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveBits'])
    .then((km) =>
      crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltBuf, iterations: iterations || PBKDF2_ITER_CURRENT, hash: 'SHA-256' },
        km,
        256
      )
    )
    .then((bits) => new Uint8Array(bits));
}

function deriveIkmBits(password, saltB64, iterations) {
  let it = parseInt(iterations, 10);
  if (!isFinite(it) || it < 50000) it = PBKDF2_ITER_CURRENT;
  if (it > 1000000) it = 1000000;
  const salt = b64ToBuf(saltB64);
  return crypto.subtle
    .importKey('raw', new TextEncoder().encode(String(password)), 'PBKDF2', false, ['deriveBits'])
    .then((km) => crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: it, hash: 'SHA-256' }, km, 256))
    .then((bits) => new Uint8Array(bits));
}

function verifierForIkm(raw) {
  const tag = new TextEncoder().encode('sci-verify-v1');
  const buf = new Uint8Array(tag.length + raw.length);
  buf.set(tag, 0);
  buf.set(raw, tag.length);
  return crypto.subtle.digest('SHA-256', buf).then((d) => bufToB64(new Uint8Array(d)));
}

function sessionForIkm(raw) {
  return crypto.subtle
    .importKey('raw', raw, 'HKDF', false, ['deriveBits'])
    .then((k) =>
      crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(INFO.session) },
        k,
        256
      )
    )
    .then((bits) => {
      const b = new Uint8Array(bits);
      return crypto.subtle.importKey('raw', b, 'HKDF', false, ['deriveKey', 'deriveBits']).then((k) => {
        b.fill(0);
        return k;
      });
    });
}

function deriveSessionKey(password, saltB64, iterations) {
  return deriveIkmBits(password, saltB64, iterations).then((raw) =>
    sessionForIkm(raw).then((k) => {
      raw.fill(0);
      return k;
    })
  );
}

function hkdfFileKeyV4(sessionKey, fileSalt) {
  const salt = fileSalt instanceof Uint8Array ? fileSalt : new Uint8Array(fileSalt);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(INFO.fileV4) },
    sessionKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function hkdfTotpKey(sessionKey, salt) {
  const s = salt instanceof Uint8Array ? salt : new Uint8Array(salt);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: s, info: new TextEncoder().encode(INFO.totp) },
    sessionKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function encryptEnvelopeV4(dataObj, sessionKey, username, accountSalt) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const meta = {
    v: 4,
    username: username || '',
    accountSalt: accountSalt || '',
    salt: bufToB64(salt),
    iv: bufToB64(iv),
    iterations: PBKDF2_ITER_CURRENT,
    savedAt: Date.now(),
  };
  const aad = enc.encode(JSON.stringify(meta));
  return hkdfFileKeyV4(sessionKey, salt).then((key) =>
    crypto.subtle
      .encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, enc.encode(JSON.stringify(dataObj)))
      .then((ct) => {
        meta.data = bufToB64(ct);
        return meta;
      })
  );
}

function decryptEnvelopeV4WithKey(blob, sessionKey) {
  return hkdfFileKeyV4(sessionKey, b64ToBuf(blob.salt)).then((key) => {
    const aad = new TextEncoder().encode(
      JSON.stringify({
        v: 4,
        username: blob.username || '',
        accountSalt: blob.accountSalt || '',
        salt: blob.salt,
        iv: blob.iv,
        iterations: blob.iterations,
        savedAt: blob.savedAt,
      })
    );
    return crypto.subtle
      .decrypt({ name: 'AES-GCM', iv: b64ToBuf(blob.iv), additionalData: aad }, key, b64ToBuf(blob.data))
      .then((pt) => JSON.parse(new TextDecoder().decode(pt)));
  });
}

function decryptEnvelopeV4(blob, password) {
  return deriveIkmBits(password, blob.accountSalt, blob.iterations).then((raw) =>
    sessionForIkm(raw).then((sk) => {
      raw.fill(0);
      return decryptEnvelopeV4WithKey(blob, sk);
    })
  );
}

function encryptTotpStore(accountsArr, sessionKey) {
  if (!sessionKey) return Promise.reject(new Error('no-key'));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  return hkdfTotpKey(sessionKey, salt).then((key) =>
    crypto.subtle
      .encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(accountsArr)))
      .then((ct) =>
        JSON.stringify({ v: 1, kdf: 'session-hkdf', salt: bufToB64(salt), iv: bufToB64(iv), data: bufToB64(new Uint8Array(ct)), locked: false })
      )
  );
}

function decryptTotpStore(raw, sessionKey) {
  let blob;
  try { blob = JSON.parse(raw); } catch (e) { return null; }
  if (!blob || blob.v !== 1 || blob.locked) return null;
  if (!sessionKey) return null;
  try {
    return hkdfTotpKey(sessionKey, b64ToBuf(blob.salt)).then((key) =>
      crypto.subtle
        .decrypt({ name: 'AES-GCM', iv: b64ToBuf(blob.iv) }, key, b64ToBuf(blob.data))
        .then((pt) => JSON.parse(new TextDecoder().decode(pt)))
        .catch(() => null)
    );
  } catch (e) { return null; }
}

/* ========================= L3 存储适配（可插拔） ========================= */

/**
 * 默认存储适配器：基于 localStorage。
 * 宿主可传入自定义 storage 对象（实现 getItem/setItem/removeItem）来替换。
 */
const DEFAULT_STORAGE = {
  getItem(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  setItem(k, v) { try { localStorage.setItem(k, v); } catch (e) { throw e; } },
  removeItem(k) { try { localStorage.removeItem(k); } catch (e) {} },
};

/* ========================= 统一入口 SecureVault ========================= */

export class SecureVault {
  /**
   * @param {object} options
   * @param {string} [options.storageKey] 存储键名（默认 'sci-secure-vault-v1'）
   * @param {object} [options.storage] 自定义存储适配器（默认 localStorage）
   * @param {number} [options.idleTimeoutMs] 空闲自动锁定毫秒数（默认 10 分钟，0=禁用）
   * @param {boolean} [options.lockOnHidden] 切后台/切标签页即锁（默认 true）
   * @param {boolean} [options.loginBackoff] 本地登录失败指数退避（默认 true）
   * @param {(reason:string)=>void} [options.onLock] 锁定回调，宿主应在此清空界面上的明文 DOM
   */
  constructor(options) {
    options = options || {};
    this.storageKey = options.storageKey || 'sci-secure-vault-v1';
    this.storage = options.storage || DEFAULT_STORAGE;
    this.idleTimeoutMs = options.idleTimeoutMs === undefined ? 10 * 60 * 1000 : options.idleTimeoutMs;
    this.lockOnHidden = options.lockOnHidden !== false;
    this.loginBackoff = options.loginBackoff !== false;
    this.onLock = typeof options.onLock === 'function' ? options.onLock : null;
    this._sessionKey = null;   // 会话密钥（不可导出 CryptoKey）
    this._currentUser = null;  // { username, salt, verifier, iterations }
    this._locked = true;
    this._lastActivity = Date.now();
    this._autoLockBound = false;
  }

  /** 是否支持加密（需 HTTPS/file://） */
  isSupported() { return checkCryptoSupport(); }

  /** 当前是否已锁定（无可用会话密钥） */
  get locked() { return this._locked; }

  /** 当前登录用户名（锁定时为 null） */
  get currentUser() { return this._currentUser ? this._currentUser.username : null; }

  /**
   * 注册新账号：创建账号盐、派生验证值并持久化，建立会话密钥。
   */
  async register(username, password) {
    username = String(username || '').trim();
    if (!checkCryptoSupport()) throw new Error('当前环境不支持加密，请使用 HTTPS 打开');
    if (String(password || '').length < 6) throw new Error('密码至少 6 位');
    if (String(password || '').length > 128) throw new Error('密码最多 128 位');
    // 已存在则拒绝
    if (this._loadUser(username)) throw new Error('账号已存在，请直接登录');

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const verifier = await pbkdf2Bits(password + VERIFY_TAG, salt, PBKDF2_ITER_CURRENT).then((v) => bufToB64(v));
    const u = {
      username,
      salt: bufToB64(salt),
      verifier,
      iterations: PBKDF2_ITER_CURRENT,
      createdAt: Date.now(),
    };
    this._saveUser(u);
    this._currentUser = u;
    this._sessionKey = await deriveSessionKey(password, u.salt, u.iterations);
    this._locked = false;
    this._clearFail(username);
    this._armAutoLock();
    return u;
  }

  /**
   * 登录：先查本地失败退避，再校验密码并建立会话密钥。
   */
  async login(username, password) {
    username = String(username || '').trim();
    if (!checkCryptoSupport()) throw new Error('当前环境不支持加密');
    if (this.loginBackoff) {
      const f = this._readFail(username);
      if (f && f.until > Date.now()) {
        throw new Error('尝试次数过多，请 ' + Math.ceil((f.until - Date.now()) / 1000) + ' 秒后再试');
      }
    }
    const u = this._loadUser(username);
    if (!u) throw new Error('本机没有该账号');
    const ok = await this._verifyPassword(u, password);
    if (!ok) {
      if (this.loginBackoff) this._noteFail(username);
      throw new Error('密码错误');
    }
    this._currentUser = u;
    this._sessionKey = await deriveSessionKey(password, u.salt, u.iterations);
    this._locked = false;
    this._clearFail(username);
    this._armAutoLock();
    return u;
  }

  /** 仅校验密码（不建立会话） */
  async verifyPassword(username, password) {
    const u = this._loadUser(String(username || '').trim());
    if (!u) throw new Error('本机没有该账号');
    return this._verifyPassword(u, password);
  }

  /**
   * 锁定：清除内存中的会话密钥和明文，但保留存储中的加密数据。
   * 锁定后所有需要密钥的操作都不可用，直到再次 login。
   * @param {string} [reason] 锁定原因（'manual' | 'idle' | 'hidden'），传给 onLock 回调
   */
  lock(reason) {
    reason = reason || 'manual';
    const wasLocked = this._locked;
    this._sessionKey = null;
    this._currentUser = null;
    this._locked = true;
    this._disarmAutoLock();
    if (!wasLocked && this.onLock) {
      try { this.onLock(reason); } catch (e) { /* 宿主回调异常不影响锁定 */ }
    }
  }

  /** 是否已登录（有可用会话密钥） */
  isUnlocked() { return !this._locked && !!this._sessionKey; }

  /**
   * 当前账号的防钓鱼安全短语（仅依赖已存储的验证值，无需密码/密钥）。
   * 用户记住自己的短语；登录后若显示的短语不同，说明在假站（钓鱼）输入了密码。
   * @param {string} [username] 缺省为当前账号
   */
  async getSecurityPhrase(username) {
    const u = this._loadUser(String(username || this.currentUser || '').trim());
    if (!u) throw new Error('账号不存在');
    return securityPhrase(u.verifier);
  }

  /**
   * 尽力清除 TOTP 明文数组的敏感字段引用。
   * 说明：JS 字符串不可变、GC 不可控，此操作只能破坏数组中持有的引用，
   * 无法保证内存中的字符串被真正擦除——这是 JS 的固有边界（见 README）。
   */
  disposeTotp(accountsArr) {
    if (!Array.isArray(accountsArr)) return;
    for (const item of accountsArr) {
      if (item && typeof item === 'object') {
        for (const k of Object.keys(item)) {
          if (typeof item[k] === 'string') item[k] = '';
        }
      }
    }
  }

  /**
   * 加密任意数据对象（需已登录/有会话密钥）。
   * @returns {Promise<object>} v4 信封
   */
  async encrypt(dataObj) {
    this._requireSession();
    return encryptEnvelopeV4(dataObj, this._sessionKey, this._currentUser.username, this._currentUser.salt);
  }

  /** 解密 v4 信封（优先会话密钥，回退密码） */
  async decrypt(blob, password) {
    if (blob && blob.v === 4 && blob.accountSalt) {
      if (this._sessionKey && this._currentUser && blob.accountSalt === this._currentUser.salt) {
        return decryptEnvelopeV4WithKey(blob, this._sessionKey).catch(() => this._decryptByPwd(blob, password));
      }
      return this._decryptByPwd(blob, password);
    }
    return this._decryptByPwd(blob, password);
  }

  /** 加密 TOTP 账号数组（需会话密钥） */
  async encryptTotp(accountsArr) {
    this._requireSession();
    return encryptTotpStore(accountsArr, this._sessionKey);
  }

  /** 解密 TOTP 账号数组 */
  async decryptTotp(raw) {
    if (!this._sessionKey) return null;
    return decryptTotpStore(raw, this._sessionKey);
  }

  /** 删除账号及其数据 */
  deleteAccount(username) {
    username = String(username || '').trim();
    this.storage.removeItem(this._userKey(username));
    this._clearFail(username);
    if (this._currentUser && this._currentUser.username === username) this.lock();
  }

  /* ------------------------- 内部方法：登录失败退避 ------------------------- */

  _failKey(username) { return this.storageKey + ':fail:' + username; }

  _readFail(username) {
    const raw = this.storage.getItem(this._failKey(username));
    if (!raw) return null;
    try { const f = JSON.parse(raw); if (f && typeof f.n === 'number') return f; } catch (e) {}
    return null;
  }

  _noteFail(username) {
    const now = Date.now();
    const f = this._readFail(username) || { n: 0, until: 0 };
    f.n++;
    f.until = now + Math.min(LOGIN_BACKOFF_BASE_MS * Math.pow(2, f.n - 1), LOGIN_BACKOFF_MAX_MS);
    this.storage.setItem(this._failKey(username), JSON.stringify(f));
  }

  _clearFail(username) {
    this.storage.removeItem(this._failKey(username));
  }

  /* ------------------------- 内部方法：自动锁定 ------------------------- */

  _armAutoLock() {
    if (typeof window === 'undefined' || this._autoLockBound) return;
    const hasEventTarget = typeof window.addEventListener === 'function';
    const doc = typeof document !== 'undefined' ? document : null;
    if (doc && this.lockOnHidden) {
      this._onVisChange = () => {
        if (doc.visibilityState === 'hidden' && this.isUnlocked()) this.lock('hidden');
      };
      doc.addEventListener('visibilitychange', this._onVisChange);
    }
    if (hasEventTarget) {
      this._onActivity = () => { this._lastActivity = Date.now(); };
      window.addEventListener('pointerdown', this._onActivity, { passive: true });
      window.addEventListener('keydown', this._onActivity, { passive: true });
    }
    if (this.idleTimeoutMs > 0) {
      this._idleTimer = setInterval(() => {
        if (this.isUnlocked() && Date.now() - this._lastActivity > this.idleTimeoutMs) {
          this.lock('idle');
        }
      }, 10000);
    }
    this._autoLockBound = true;
  }

  _disarmAutoLock() {
    if (!this._autoLockBound || typeof window === 'undefined') return;
    const doc = typeof document !== 'undefined' ? document : null;
    if (doc && this._onVisChange) doc.removeEventListener('visibilitychange', this._onVisChange);
    if (this._onActivity && typeof window.removeEventListener === 'function') {
      window.removeEventListener('pointerdown', this._onActivity);
      window.removeEventListener('keydown', this._onActivity);
    }
    if (this._idleTimer) { clearInterval(this._idleTimer); this._idleTimer = null; }
    this._autoLockBound = false;
  }

  /* ------------------------- 其他内部方法 ------------------------- */

  _requireSession() {
    if (this._locked || !this._sessionKey) throw new Error('请先登录账号');
  }

  _userKey(username) {
    return this.storageKey + ':user:' + username;
  }

  _loadUser(username) {
    const raw = this.storage.getItem(this._userKey(username));
    if (!raw) return null;
    try {
      const u = JSON.parse(raw);
      if (u && u.username === username && u.salt && u.verifier && u.iterations) return u;
    } catch (e) {}
    return null;
  }

  _saveUser(u) {
    this.storage.setItem(this._userKey(u.username), JSON.stringify(u));
  }

  async _verifyPassword(u, password) {
    const salt = b64ToBuf(u.salt);
    const it = u.iterations || PBKDF2_ITER;
    const v = await pbkdf2Bits(password + VERIFY_TAG, salt, it);
    if (bufToB64(v) === u.verifier) return true;
    // 兼容旧格式（无 VERIFY_TAG）
    const v0 = await pbkdf2Bits(password, salt, it);
    if (bufToB64(v0) === u.verifier) return true;
    return false;
  }

  async _decryptByPwd(blob, password) {
    if (!password) throw new Error('请提供密码');
    return decryptEnvelopeV4(blob, password);
  }
}

export default SecureVault;
export { securityPhrase };
