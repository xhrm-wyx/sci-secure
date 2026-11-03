/* =====================================================================
 * sci-secure-core.js  —  理科安全核心（纯算法层，零依赖）
 * ---------------------------------------------------------------------
 * 从「理科计算器·验证器」的安全模块中剥离出的纯加密算法函数集。
 * 本文件只依赖 Web Crypto API（window.crypto.subtle / getRandomValues），
 * 不依赖任何 UI、DOM、localStorage 或宿主程序逻辑，可独立使用。
 *
 * 使用方式（ES Module）：
 *   import * as sciCore from './sci-secure-core.js'
 *   const { ciphertext, meta } = await sciCore.encryptEnvelope(data, password)
 *   const plain = await sciCore.decryptEnvelope(ciphertext, password)
 *
 * 也可用 <script type="module"> 引入后在页面内调用。
 *
 * 版本：v1.0.0（对应原程序 v3.5.5 的安全算法）
 * 安全约定见 README.md。
 * ===================================================================== */

/* ------------------------- 常量与工具 ------------------------- */

/** PBKDF2 迭代次数（旧默认，仅用于兼容读取历史信封） */
const PBKDF2_ITER = 310000;

/**
 * PBKDF2 迭代次数（当前默认，OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议值）。
 * 向后兼容：信封内自存 iterations 字段，旧信封按自身记录的次数解密，不受影响。
 */
const PBKDF2_ITER_CURRENT = 600000;

/** 验证值加标签：用于把「验证值」与「会话密钥」的派生输入区分开 */
const VERIFY_TAG = '\u0001sci-verify';

/** HKDF 域分离 info 标签 */
const INFO = {
  session: 'sci-session-v1',
  fileV3: 'sci-file-v3',
  fileV4: 'sci-file-v4',
  fileV5: 'sci-file-v5',
  totp: 'sci-totp-v1',
};

/**
 * Argon2id 默认参数（OWASP 推荐基线：19MiB 内存 / 2 轮 / 1 并行）。
 * v5 信封使用 Argon2id（内存密集型 KDF，抗 GPU/ASIC 离线爆破），
 * 需宿主注入实现（见 setArgon2Impl），未注入时 v5 不可用。
 */
const ARGON2_DEFAULTS = { memoryKiB: 19456, passes: 2, parallelism: 1 };

/* ------------------------- 基础编码转换 ------------------------- */

/** Uint8Array → Base64 字符串 */
export function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

/** Base64 字符串 → Uint8Array */
export function b64ToBuf(b64) {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

/** UTF-8 字符串 → Base64（用于含中文等非 ASCII 内容） */
export function utf8ToB64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

/** Base64 → UTF-8 字符串 */
export function b64ToUtf8(b64) {
  return decodeURIComponent(escape(atob(b64)));
}

/* ------------------------- 环境检测 ------------------------- */

/** 检测当前环境是否支持 Web Crypto（需 HTTPS 或 file://，纯 http 不可用） */
export function checkCryptoSupport() {
  return !!(
    typeof window !== 'undefined' &&
    window.crypto &&
    window.crypto.subtle &&
    window.crypto.getRandomValues
  );
}

/* ------------------------- 密钥派生（PBKDF2 / HKDF） ------------------------- */

/**
 * PBKDF2 派生 256-bit 原始字节。
 * @param {string} password 密码
 * @param {Uint8Array|ArrayBuffer} salt 盐
 * @param {number} iterations 迭代次数
 * @returns {Promise<Uint8Array>}
 */
export function pbkdf2Bits(password, salt, iterations) {
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

/**
 * PBKDF2 直接派生 AES-GCM 密钥（适用于简单加密场景）。
 */
export function pbkdf2AesKey(password, salt, iterations) {
  const enc = new TextEncoder();
  const saltBuf = salt instanceof Uint8Array ? salt : new Uint8Array(salt);
  return crypto.subtle
    .importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveKey'])
    .then((km) =>
      crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBuf, iterations: iterations || PBKDF2_ITER_CURRENT, hash: 'SHA-256' },
        km,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      )
    );
}

/**
 * 从密码 + 盐（Base64）+ 迭代次数派生 256-bit IKM（中间密钥材料）。
 * 迭代次数会被限制在 [50000, 1000000] 区间。
 */
export function deriveIkmBits(password, saltB64, iterations) {
  if (!checkCryptoSupport()) return Promise.reject(new Error('当前环境不支持加密'));
  let it = parseInt(iterations, 10);
  if (!isFinite(it) || it < 50000) it = PBKDF2_ITER_CURRENT;
  if (it > 1000000) it = 1000000;
  const salt = b64ToBuf(saltB64);
  return crypto.subtle
    .importKey('raw', new TextEncoder().encode(String(password)), 'PBKDF2', false, ['deriveBits'])
    .then((km) =>
      crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: it, hash: 'SHA-256' }, km, 256)
    )
    .then((bits) => new Uint8Array(bits));
}

/**
 * 由 IKM 派生「验证值」：SHA-256('sci-verify-v1' || ikm)。
 * 关键安全点：验证值与会话密钥的派生输入不同，拿到验证值无法反推会话密钥。
 */
export function verifierForIkm(raw) {
  const tag = new TextEncoder().encode('sci-verify-v1');
  const buf = new Uint8Array(tag.length + raw.length);
  buf.set(tag, 0);
  buf.set(raw, tag.length);
  return crypto.subtle.digest('SHA-256', buf).then((d) => bufToB64(new Uint8Array(d)));
}

/**
 * 由 IKM 派生「会话密钥」（不可导出的 HKDF 密钥）。
 * 派生后立即清零中间字节，避免密钥材料残留。
 */
export function sessionForIkm(raw) {
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
      return crypto.subtle
        .importKey('raw', b, 'HKDF', false, ['deriveKey', 'deriveBits'])
        .then((k) => {
          b.fill(0);
          return k;
        });
    });
}

/**
 * 完整会话密钥派生：password + saltB64 → sessionKey（不可导出 CryptoKey）。
 */
export function deriveSessionKey(password, saltB64, iterations) {
  return deriveIkmBits(password, saltB64, iterations).then((raw) =>
    sessionForIkm(raw).then((k) => {
      raw.fill(0);
      return k;
    })
  );
}

/* ------------------------- HKDF 域分离派生文件/子密钥 ------------------------- */

/** 从会话密钥派生 v4 文件密钥（HKDF，info='sci-file-v4'） */
export function hkdfFileKeyV4(sessionKey, fileSalt) {
  const salt = fileSalt instanceof Uint8Array ? fileSalt : new Uint8Array(fileSalt);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(INFO.fileV4) },
    sessionKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/** 从会话密钥派生 v3 文件密钥（HKDF，info='sci-file-v3'） */
export function hkdfFileKey(kdfKey, fileSalt) {
  const salt = fileSalt instanceof Uint8Array ? fileSalt : new Uint8Array(fileSalt);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(INFO.fileV3) },
    kdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/** 从会话密钥派生 TOTP 密钥（HKDF，info='sci-totp-v1'） */
export function hkdfTotpKey(sessionKey, salt) {
  const s = salt instanceof Uint8Array ? salt : new Uint8Array(salt);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: s, info: new TextEncoder().encode(INFO.totp) },
    sessionKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/* ------------------------- AES-GCM 信封加密 ------------------------- */

/**
 * 通用信封加密：AES-GCM 加密任意字符串/对象，返回信封对象。
 * @param {string|object} data 要加密的数据
 * @param {CryptoKey} key 已派生的 AES-GCM 密钥
 * @param {Uint8Array} [aad] 可选附加认证数据（参与 GCM 认证，不加密）
 * @returns {Promise<{salt:string, iv:string, data:string}>}
 */
export function sealWithKey(data, key, aad) {
  const plain = typeof data === 'string' ? data : JSON.stringify(data);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  return crypto.subtle
    .encrypt(params, key, enc.encode(plain))
    .then((ct) => ({ iv: bufToB64(iv), data: bufToB64(new Uint8Array(ct)) }));
}

/**
 * 通用信封解密：对应 sealWithKey。
 */
export function openWithKey(envelope, key, aad) {
  const params = { name: 'AES-GCM', iv: b64ToBuf(envelope.iv) };
  if (aad) params.additionalData = aad;
  return crypto.subtle
    .decrypt(params, key, b64ToBuf(envelope.data))
    .then((pt) => new TextDecoder().decode(pt));
}

/**
 * 便捷封装：用密码加密任意数据（自动派生密钥）。
 * @returns {Promise<{salt:string, iv:string, data:string, kdf:string, iterations:number}>}
 */
export async function encryptWithPassword(data, password, iterations) {
  if (!checkCryptoSupport()) throw new Error('当前环境不支持加密');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await pbkdf2AesKey(password, salt, iterations || PBKDF2_ITER_CURRENT);
  const env = await sealWithKey(data, key);
  return {
    kdf: 'pbkdf2-sha256',
    iterations: iterations || PBKDF2_ITER_CURRENT,
    salt: bufToB64(salt),
    iv: env.iv,
    data: env.data,
  };
}

/**
 * 便捷封装：用密码解密 encryptWithPassword 的输出。
 */
export async function decryptWithPassword(envelope, password) {
  if (!checkCryptoSupport()) throw new Error('当前环境不支持加密');
  const salt = b64ToBuf(envelope.salt);
  const key = await pbkdf2AesKey(password, salt, envelope.iterations || PBKDF2_ITER);
  return openWithKey(envelope, key);
}

/* ------------------------- 信封加密（会话密钥版，v4 文件格式） ------------------------- */

/**
 * 用会话密钥加密数据对象，返回 v4 格式信封（含 AAD 元数据认证）。
 * 元数据 {v, username, accountSalt, salt, iv, iterations, savedAt} 全部作为 AAD，
 * 任一字段被篡改都会导致解密失败。
 */
export function encryptEnvelopeV4(dataObj, sessionKey, username, accountSalt) {
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

/** 用会话密钥解密 v4 信封（含 AAD 校验） */
export function decryptEnvelopeV4WithKey(blob, sessionKey) {
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

/** 用密码解密 v4 信封（内部派生会话密钥） */
export function decryptEnvelopeV4(blob, password) {
  return deriveIkmBits(password, blob.accountSalt, blob.iterations).then((raw) =>
    sessionForIkm(raw).then((sk) => {
      raw.fill(0);
      return decryptEnvelopeV4WithKey(blob, sk);
    })
  );
}

/* ------------------------- 信封加密（v3 旧格式，兼容） ------------------------- */

export function encryptEnvelopeV3(dataObj, kdfKey, username, accountSalt) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const meta = {
    v: 3,
    username: username || '',
    accountSalt: accountSalt || '',
    salt: bufToB64(salt),
    iv: bufToB64(iv),
    iterations: PBKDF2_ITER,
    savedAt: Date.now(),
  };
  const aad = enc.encode(JSON.stringify(meta));
  return hkdfFileKey(kdfKey, salt).then((key) =>
    crypto.subtle
      .encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, enc.encode(JSON.stringify(dataObj)))
      .then((ct) => {
        meta.data = bufToB64(ct);
        return meta;
      })
  );
}

export function decryptEnvelopeV3WithKey(blob, kdfKey) {
  return hkdfFileKey(kdfKey, b64ToBuf(blob.salt)).then((key) => {
    const aad = new TextEncoder().encode(
      JSON.stringify({
        v: blob.v,
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

export function decryptEnvelopeV3(blob, password) {
  return deriveSessionKey(password, blob.accountSalt, blob.iterations).then((k) =>
    hkdfFileKey(k, b64ToBuf(blob.salt)).then((key) => {
      const aad = new TextEncoder().encode(
        JSON.stringify({
          v: 3,
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
    })
  );
}

/* ------------------------- TOTP 密钥信封加密 ------------------------- */

/**
 * 用会话密钥加密 TOTP 账号数组（信封加密 + HKDF 域分离）。
 * @returns {Promise<string>} 加密后的 JSON 字符串
 */
export function encryptTotpStore(accountsArr, sessionKey) {
  if (!checkCryptoSupport() || !sessionKey) return Promise.reject(new Error('no-key'));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  return hkdfTotpKey(sessionKey, salt).then((key) =>
    crypto.subtle
      .encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(accountsArr)))
      .then((ct) =>
        JSON.stringify({
          v: 1,
          kdf: 'session-hkdf',
          salt: bufToB64(salt),
          iv: bufToB64(iv),
          data: bufToB64(new Uint8Array(ct)),
          locked: false,
        })
      )
  );
}

/**
 * 用会话密钥解密 TOTP 账号数组。
 * @returns {Promise<Array|null>} 解密成功返回数组，失败返回 null
 */
export function decryptTotpStore(raw, sessionKey) {
  let blob;
  try {
    blob = JSON.parse(raw);
  } catch (e) {
    return null;
  }
  if (!blob || blob.v !== 1 || blob.locked) return null;
  if (!checkCryptoSupport() || !sessionKey) return null;
  try {
    return hkdfTotpKey(sessionKey, b64ToBuf(blob.salt)).then((key) =>
      crypto.subtle
        .decrypt({ name: 'AES-GCM', iv: b64ToBuf(blob.iv) }, key, b64ToBuf(blob.data))
        .then((pt) => JSON.parse(new TextDecoder().decode(pt)))
        .catch(() => null)
    );
  } catch (e) {
    return null;
  }
}

/* ------------------------- Argon2id 适配与 v5 信封 ------------------------- */

/**
 * Argon2id 实现注入点。WebCrypto 不支持 Argon2，需宿主提供实现，例如：
 *   import { argon2id } from 'argon2-browser'  // 或自编译 WASM
 *   setArgon2Impl(async (password, salt, opts) => {
 *     const r = await argon2id({ pass: password, salt, mem: opts.memoryKiB,
 *       time: opts.passes, parallelism: opts.parallelism, hashLen: 32, type: 2 });
 *     return r.hash;  // Uint8Array(32)
 *   });
 * @param {(password:string, salt:Uint8Array, opts:{memoryKiB:number,passes:number,parallelism:number})=>Promise<Uint8Array>} fn
 */
let _argon2Impl = null;
export function setArgon2Impl(fn) {
  if (typeof fn !== 'function') throw new Error('Argon2 实现必须是函数');
  _argon2Impl = fn;
}
export function isArgon2Available() { return !!_argon2Impl; }

/**
 * v5 信封加密：Argon2id 直派主密钥 + HKDF 域分离文件密钥（info=sci-file-v5）。
 * 与 v4 差异仅在 KDF：v4 用 PBKDF2（CPU 密集），v5 用 Argon2id（内存密集，抗 GPU 爆破）。
 * 元数据同样全部进 AAD，任一字段被篡改即解密失败。
 * @returns {Promise<object>} v5 信封
 */
export async function encryptEnvelopeV5(dataObj, password, username, argon2Opts) {
  if (!checkCryptoSupport()) throw new Error('当前环境不支持加密');
  if (!_argon2Impl) throw new Error('v5 需要 Argon2id：请先 setArgon2Impl() 注入实现');
  const opts = Object.assign({}, ARGON2_DEFAULTS, argon2Opts || {});
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const master = await _argon2Impl(String(password), salt, opts);  // Uint8Array(32)
  if (!(master instanceof Uint8Array) || master.length !== 32) throw new Error('Argon2 实现必须返回 32 字节');
  try {
    const hk = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
    const fileKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(INFO.fileV5) },
      hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const meta = {
      v: 5,
      kdf: 'argon2id',
      memoryKiB: opts.memoryKiB,
      passes: opts.passes,
      parallelism: opts.parallelism,
      username: username || '',
      salt: bufToB64(salt),
      iv: bufToB64(iv),
      savedAt: Date.now(),
    };
    const aad = enc.encode(JSON.stringify(meta));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad }, fileKey, enc.encode(JSON.stringify(dataObj)));
    meta.data = bufToB64(new Uint8Array(ct));
    return meta;
  } finally {
    master.fill(0);  // 主密钥材料即刻清零
  }
}

/** v5 信封解密：Argon2id + HKDF + AES-GCM（含 AAD 校验） */
export async function decryptEnvelopeV5(blob, password) {
  if (!checkCryptoSupport()) throw new Error('当前环境不支持加密');
  if (!blob || blob.v !== 5 || blob.kdf !== 'argon2id') throw new Error('不是 v5 信封');
  if (!_argon2Impl) throw new Error('v5 需要 Argon2id：请先 setArgon2Impl() 注入实现');
  const enc = new TextEncoder();
  const salt = b64ToBuf(blob.salt);
  const master = await _argon2Impl(String(password), salt, {
    memoryKiB: blob.memoryKiB, passes: blob.passes, parallelism: blob.parallelism,
  });
  try {
    const hk = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
    const fileKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(INFO.fileV5) },
      hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const aad = enc.encode(JSON.stringify({
      v: 5, kdf: 'argon2id',
      memoryKiB: blob.memoryKiB, passes: blob.passes, parallelism: blob.parallelism,
      username: blob.username || '', salt: blob.salt, iv: blob.iv, savedAt: blob.savedAt,
    }));
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(blob.iv), additionalData: aad }, fileKey, b64ToBuf(blob.data));
    return JSON.parse(new TextDecoder().decode(pt));
  } finally {
    master.fill(0);
  }
}

/* ------------------------- 防钓鱼安全短语 ------------------------- */

/** 64 词安全短语词表（双字中文词，便于人眼识别比对） */
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

/**
 * 由验证值派生防钓鱼安全短语（3 个词）。
 * 原理：短语只与「密码派生的验证值」绑定，钓鱼站不知道密码就伪造不出同样的短语。
 * 用户登录后比对自己记住的短语，不一致即说明在假站输入了密码。
 * @param {string} verifierB64 验证值（verifierForIkm 的输出）
 * @returns {Promise<string>} 形如「青柠·远山·星轨」
 */
export async function securityPhrase(verifierB64) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', b64ToBuf(verifierB64)));
  // 取前 18 bit，每 6 bit 映射一个词（64^3 = 262144 种组合，足够人眼区分）
  const bits = (digest[0] << 16) | (digest[1] << 8) | digest[2];
  const w1 = PHRASE_WORDS[(bits >> 12) & 63];
  const w2 = PHRASE_WORDS[(bits >> 6) & 63];
  const w3 = PHRASE_WORDS[bits & 63];
  return w1 + '·' + w2 + '·' + w3;
}

/* ------------------------- 内存清零辅助 ------------------------- */

/**
 * 尽力清零密钥材料缓冲区（Uint8Array/ArrayBuffer）。
 * 注意：JS 无法清零字符串（不可变 + GC 不可控），本函数只对二进制缓冲有效。
 * 这是「缩短明文驻留窗口」的尽力措施，不是绝对保证。
 */
export function zeroize(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
  else if (buf instanceof ArrayBuffer) new Uint8Array(buf).fill(0);
}

/* ------------------------- 统一导出 ------------------------- */

export default {
  // 常量
  PBKDF2_ITER,
  PBKDF2_ITER_CURRENT,
  ARGON2_DEFAULTS,
  VERIFY_TAG,
  INFO,
  PHRASE_WORDS,
  // 编码
  bufToB64,
  b64ToBuf,
  utf8ToB64,
  b64ToUtf8,
  // 检测
  checkCryptoSupport,
  // 派生
  pbkdf2Bits,
  pbkdf2AesKey,
  deriveIkmBits,
  verifierForIkm,
  sessionForIkm,
  deriveSessionKey,
  hkdfFileKeyV4,
  hkdfFileKey,
  hkdfTotpKey,
  // 通用信封
  sealWithKey,
  openWithKey,
  encryptWithPassword,
  decryptWithPassword,
  // v4 信封
  encryptEnvelopeV4,
  decryptEnvelopeV4WithKey,
  decryptEnvelopeV4,
  // v5 信封（Argon2id）
  setArgon2Impl,
  isArgon2Available,
  encryptEnvelopeV5,
  decryptEnvelopeV5,
  // v3 信封
  encryptEnvelopeV3,
  decryptEnvelopeV3WithKey,
  decryptEnvelopeV3,
  // TOTP
  encryptTotpStore,
  decryptTotpStore,
  // 防钓鱼与清零
  securityPhrase,
  zeroize,
};
