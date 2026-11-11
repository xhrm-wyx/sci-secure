//! 玄印（sci-secure）v4 信封跨语言实现（Rust 版）
//!
//! 与 JavaScript 版 sci-secure-core.js 完全互通：
//!
//! ```text
//! IKM        = PBKDF2-HMAC-SHA256(password, accountSalt, iterations, 32)
//! sessionKey = HKDF-SHA256(IKM,        salt=空,     info="sci-session-v1", 32)
//! fileKey    = HKDF-SHA256(sessionKey, salt=文件盐, info="sci-file-v4",    32)
//! AAD        = 固定键序的元数据 JSON
//! 密文        = AES-256-GCM(fileKey, iv, plaintext, AAD)，输出 密文||16字节tag
//! ```
//!
//! 依赖：aes-gcm / sha2 / hkdf / pbkdf2 / base64 / serde / serde_json（均为 RustCrypto 生态）。

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const MIN_ITERATIONS: u32 = 50_000;
pub const MAX_ITERATIONS: u32 = 1_000_000;
pub const DEFAULT_ITERATIONS: u32 = 600_000;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// v4 信封。字段顺序即 JSON 键序，参与 AAD 的字段单独用 `AadPayload` 表达。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    #[serde(default)]
    pub username: String,
    #[serde(rename = "accountSalt")]
    pub account_salt: String,
    pub salt: String,
    pub iv: String,
    pub iterations: u32,
    #[serde(rename = "savedAt")]
    pub saved_at: i64,
    pub data: String,
}

#[derive(Debug, Serialize)]
struct AadPayload<'a> {
    v: u32,
    username: &'a str,
    #[serde(rename = "accountSalt")]
    account_salt: &'a str,
    salt: &'a str,
    iv: &'a str,
    iterations: u32,
    #[serde(rename = "savedAt")]
    saved_at: i64,
}

#[derive(Debug)]
pub enum Error {
    Base64(String),
    Json(String),
    Aead,
    Length(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Base64(s) => write!(f, "base64 解码失败: {s}"),
            Error::Json(s) => write!(f, "JSON 处理失败: {s}"),
            Error::Aead => write!(f, "认证失败：密码错误或数据已被篡改"),
            Error::Length(s) => write!(f, "长度不合法: {s}"),
        }
    }
}

impl std::error::Error for Error {}

pub fn clamp_iterations(n: u32) -> u32 {
    n.clamp(MIN_ITERATIONS, MAX_ITERATIONS)
}

/// 构造 AAD。serde_json 不转义 `<`/`>`/`&`/非 ASCII，与 JavaScript 的 JSON.stringify 一致。
pub fn build_aad(
    username: &str,
    account_salt: &str,
    salt: &str,
    iv: &str,
    iterations: u32,
    saved_at: i64,
) -> Vec<u8> {
    let payload = AadPayload {
        v: 4,
        username,
        account_salt,
        salt,
        iv,
        iterations,
        saved_at,
    };
    serde_json::to_vec(&payload).expect("AAD 序列化不会失败")
}

/// 三级派生，返回 (ikm, sessionKey, fileKey)。
pub fn derive_keys(
    password: &str,
    account_salt_b64: &str,
    iterations: u32,
    file_salt_b64: &str,
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN], [u8; KEY_LEN]), Error> {
    let acct_salt = B64
        .decode(account_salt_b64)
        .map_err(|e| Error::Base64(e.to_string()))?;
    let file_salt = B64
        .decode(file_salt_b64)
        .map_err(|e| Error::Base64(e.to_string()))?;
    let it = clamp_iterations(iterations);

    let mut ikm = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &acct_salt, it, &mut ikm);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut session = [0u8; KEY_LEN];
    hk.expand(b"sci-session-v1", &mut session)
        .map_err(|e| Error::Length(e.to_string()))?;

    let hk2 = Hkdf::<Sha256>::new(Some(&file_salt), &session);
    let mut file_key = [0u8; KEY_LEN];
    hk2.expand(b"sci-file-v4", &mut file_key)
        .map_err(|e| Error::Length(e.to_string()))?;

    Ok((ikm, session, file_key))
}

/// 解析信封 JSON。
pub fn parse_envelope(json: &str) -> Result<Envelope, Error> {
    let env: Envelope = serde_json::from_str(json).map_err(|e| Error::Json(e.to_string()))?;
    if env.v != 4 {
        return Err(Error::Json(format!("不支持的信封版本 v{}（仅支持 v4）", env.v)));
    }
    Ok(env)
}

/// 解密 v4 信封。
pub fn decrypt_v4(env: &Envelope, password: &str) -> Result<Vec<u8>, Error> {
    if env.v != 4 {
        return Err(Error::Json(format!("不支持的信封版本 v{}（仅支持 v4）", env.v)));
    }
    let (_, _, file_key) = derive_keys(password, &env.account_salt, env.iterations, &env.salt)?;

    let iv = B64.decode(&env.iv).map_err(|e| Error::Base64(e.to_string()))?;
    if iv.len() != 12 {
        return Err(Error::Length(format!("iv 应为 12 字节，实际 {}", iv.len())));
    }
    let blob = B64
        .decode(&env.data)
        .map_err(|e| Error::Base64(e.to_string()))?;
    if blob.len() < TAG_LEN {
        return Err(Error::Length("密文长度不足，缺少认证标签".into()));
    }

    let aad = build_aad(
        &env.username,
        &env.account_salt,
        &env.salt,
        &env.iv,
        env.iterations,
        env.saved_at,
    );

    let cipher = Aes256Gcm::new_from_slice(&file_key).map_err(|_| Error::Length("密钥长度错误".into()))?;
    cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &blob,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Aead)
}

/// 便捷函数：信封 JSON 文本 + 密码 → 明文。
pub fn decrypt_v4_json(envelope_json: &str, password: &str) -> Result<Vec<u8>, Error> {
    let env = parse_envelope(envelope_json)?;
    decrypt_v4(&env, password)
}

/// 加密为 v4 信封 JSON（缩进两格）。`iterations == 0` 时用 600000。
pub fn encrypt_v4(
    plain: &[u8],
    password: &str,
    username: &str,
    iterations: u32,
) -> Result<String, Error> {
    encrypt_v4_at(plain, password, username, iterations, now_millis())
}

/// 同 `encrypt_v4`，但可指定 savedAt（毫秒），便于生成可复现向量。
pub fn encrypt_v4_at(
    plain: &[u8],
    password: &str,
    username: &str,
    iterations: u32,
    saved_at: i64,
) -> Result<String, Error> {
    let it = if iterations == 0 {
        DEFAULT_ITERATIONS
    } else {
        clamp_iterations(iterations)
    };

    let mut acct_salt = [0u8; 16];
    let mut file_salt = [0u8; 32];
    let mut iv = [0u8; 12];
    rand_fill(&mut acct_salt)?;
    rand_fill(&mut file_salt)?;
    rand_fill(&mut iv)?;

    let acct_b64 = B64.encode(acct_salt);
    let salt_b64 = B64.encode(file_salt);
    let iv_b64 = B64.encode(iv);

    let (_, _, file_key) = derive_keys(password, &acct_b64, it, &salt_b64)?;
    let aad = build_aad(username, &acct_b64, &salt_b64, &iv_b64, it, saved_at);

    let cipher = Aes256Gcm::new_from_slice(&file_key).map_err(|_| Error::Length("密钥长度错误".into()))?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Aead)?;

    let env = Envelope {
        v: 4,
        username: username.to_string(),
        account_salt: acct_b64,
        salt: salt_b64,
        iv: iv_b64,
        iterations: it,
        saved_at,
        data: B64.encode(sealed),
    };
    serde_json::to_string_pretty(&env).map_err(|e| Error::Json(e.to_string()))
}

fn rand_fill(buf: &mut [u8]) -> Result<(), Error> {
    use aes_gcm::aead::rand_core::RngCore;
    OsRng
        .try_fill_bytes(buf)
        .map_err(|e| Error::Length(format!("随机数生成失败: {e}")))
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 供测试用：生成一个随机 Nonce（12 字节），避免调用方直接依赖 aes-gcm 细节。
pub fn random_nonce() -> [u8; 12] {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut out = [0u8; 12];
    out.copy_from_slice(nonce.as_slice());
    out
}
