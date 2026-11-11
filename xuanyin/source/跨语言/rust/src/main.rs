//! demo — 跨语言互通验证（Rust 版）
//!
//! 用法：
//!   cargo run --release -- ../envelope.json "CrossLang-测试123"
//!   cargo run --release -- ../envelope.json "hex:43726f73..."

use sci_secure as sci;
use sha2::{Digest, Sha256};
use std::fs;

fn decode_password(arg: &str) -> String {
    match arg.strip_prefix("hex:") {
        None => arg.to_string(),
        Some(h) => {
            let bytes: Vec<u8> = (0..h.len() / 2)
                .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).expect("非法 hex"))
                .collect();
            String::from_utf8(bytes).expect("hex 不是合法 UTF-8")
        }
    }
}

fn sha256hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("用法: demo <envelope.json> <密码|hex:...>");
        std::process::exit(1);
    }

    let json = fs::read_to_string(&args[1]).expect("读取信封失败");
    let password = decode_password(&args[2]);

    let env = sci::parse_envelope(&json).expect("解析信封失败");

    let (ikm, session, file_key) =
        sci::derive_keys(&password, &env.account_salt, env.iterations, &env.salt).expect("派生失败");
    println!("ikm       : {}", hex(&ikm));
    println!("sessionKey: {}", hex(&session));
    println!("fileKey   : {}", hex(&file_key));

    let plain = match sci::decrypt_v4(&env, &password) {
        Ok(p) => p,
        Err(e) => {
            println!("解密失败: {e}");
            std::process::exit(4);
        }
    };

    println!("plainLen  : {}", plain.len());
    println!("plainSha  : {}", sha256hex(&plain));
    fs::write("out.txt", &plain).expect("写 out.txt 失败");
    println!("plaintext : {}", String::from_utf8_lossy(&plain));

    let want = r#"{"roundtrip":"rust","n":7}"#;
    let env2 = sci::encrypt_v4(want.as_bytes(), &password, "rust-demo", 600_000).expect("加密失败");
    fs::write("roundtrip_envelope.json", &env2).expect("写 roundtrip_envelope.json 失败");
    let back = sci::decrypt_v4_json(&env2, &password).expect("回解失败");
    println!("roundtrip : {}", String::from_utf8_lossy(&back));
    println!("OK        : {}", back == want.as_bytes());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
