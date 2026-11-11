# 跨语言实现（8 种语言 · 全部实测互通）

同一份加密文件（v4 信封），JavaScript 生成后，**Python / C / C++ / Java / Go / Rust / C#** 都能解开；
反过来，这 7 种语言各自生成的信封，JavaScript 也全部能解开。

本目录的每一份实现都严格对齐 [`FORMAT-SPEC.md`](../源码/FORMAT-SPEC.md)，
并已在本机**逐字节交叉验证**（结果见文末「验证记录」），不是"照着规范抄一遍就算"。

## 语言矩阵

| 语言 | 目录 | 第三方依赖 | 加密 | 解密 | 实测 |
|---|---|---|:--:|:--:|:--:|
| JavaScript | `../源码/sci-secure-core.js` | 无（WebCrypto） | ✅ | ✅ | 基准实现 |
| Python | `python/` | `cryptography`（仅 AES-GCM） | ✅ | ✅ | ✅ |
| C | `c/` | OpenSSL 1.1.1+ | ✅ | ✅ | ✅ |
| C++ | `cpp/` | 复用 C 实现 + OpenSSL | ✅ | ✅ | ✅ |
| Java | `java/` | 无（纯 JDK 8+） | ✅ | ✅ | ✅ |
| Go | `go/` | **无（纯标准库，Go 1.24+）** | ✅ | ✅ | ✅ |
| Rust | `rust/` | RustCrypto 系列 crate | ✅ | ✅ | ✅ |
| C# | `csharp/` | **无（.NET 8 基础类库）** | ✅ | ✅ | ✅ |

---

## 目录

| 文件 | 说明 |
|---|---|
| `test_vectors.json` | 统一测试向量：密码、盐、IV、三级派生中间值、密文、期望明文 |
| `envelope.json` | 由 Python 生成的标准信封，供各语言 demo 直接读取 |
| `envelope_js.json` | 由 **JavaScript 现场生成**的信封（密码 `Matrix-矩阵2026`），用于反向验证 |
| `python/sci_secure.py` | Python 模块（可直接 `import`） |
| `python/demo.py` | Python 验证程序 |
| `c/sci_secure.h` `c/sci_secure.c` | C 实现（OpenSSL），加密 + 解密 |
| `cpp/sci_secure.hpp` | C++17 封装（复用 C 核心，不重写算法） |
| `java/SciSecure.java` | Java 实现（纯 JDK） |
| `go/sci_secure.go` | Go 实现（`package scisecure`，纯标准库） |
| `rust/src/lib.rs` | Rust 实现（库 + demo） |
| `csharp/SciSecure.cs` | C# 实现（.NET 8） |

每个语言目录下都有一个 `demo`（或 `Demo.java` / `Program.cs`），行为一致：
读入信封 → 打印三级派生中间值 → 解密 → 打印明文 SHA-256 → 自己再加密一次并回解。

---

## 依赖

| 语言 | 要求 |
|---|---|
| Python | Python 3.8+，`pip install cryptography` |
| C / C++ | OpenSSL **1.1.1 或以上**；GCC / Clang / MSVC 皆可 |
| Java | **JDK 8+**（用到 `PBKDF2WithHmacSHA256`），无第三方包 |
| Go | **Go 1.24+**（`crypto/pbkdf2` 与 `crypto/hkdf` 自该版本进入标准库），无第三方包 |
| Rust | 稳定版工具链；依赖 `aes-gcm` `sha2` `hkdf` `pbkdf2` `base64` `serde` `serde_json` |
| C# | **.NET 8+**，无第三方包 |

---

## 编译与运行

统一用法：`demo <信封文件> <密码>`。密码若含中文，见下文「坑 1」。

### Python

```bash
cd python
python demo.py ../envelope.json "CrossLang-测试123"
```

### C

```bash
cd c
gcc -O2 -Wall demo.c sci_secure.c -lcrypto -o demo
./demo ../envelope.json "CrossLang-测试123"
```

Windows（MSYS2 / MinGW-w64）把命令换成 `gcc ... -lcrypto -o demo.exe`，
运行前确保 `libcrypto-3-x64.dll` 在 PATH 中。

### C++

```bash
cd cpp
g++ -std=c++17 -O2 -Wall demo.cpp ../c/sci_secure.c -I../c -lcrypto -o demo
./demo ../envelope.json "CrossLang-测试123"
```

> `sci_secure.c` 已写成 C / C++ 双兼容（变量声明全部前置），可直接交给 g++ 编译。

### Java

```bash
cd java
javac -encoding UTF-8 SciSecure.java Demo.java
java -cp . Demo ../envelope.json "CrossLang-测试123"
```

### Go

```bash
cd go
go build -o demo ./cmd/demo
./demo ../envelope.json "CrossLang-测试123"
```

### Rust

```bash
cd rust
cargo build --release
./target/release/demo ../envelope.json "CrossLang-测试123"
```

### C#

```bash
cd csharp
dotnet build -c Release
dotnet run -c Release -- ../envelope.json "CrossLang-测试123"
```

---

## 预期输出

八种语言（含 JS）解同一封信封，输出必须**完全一致**：

```
plainLen  : 47
plainSha  : 0062eed71f20b80c8cb51c90749c19d0388b67442575d380f8f203c638c49fe3
plaintext : {"名称":"跨语言测试","值":42,"ok":true}
roundtrip : {"roundtrip":"<语言>","n":7}
OK        : true
```

`plainSha` 必须等于测试向量里 `plaintext_json` 的 SHA-256；
同时对 `out.txt` 做字节比对，应与 `plaintext_json` 完全一致。

---

## 四个真实踩过的坑

### 坑 1：Windows 命令行里的中文密码（C / C++）

gcc / MSVC 编译出的程序，`main()` 拿到的 `argv` 是**系统代码页**（简体中文环境为 GBK），
不是 UTF-8。直接传中文密码会认证失败——**不是算法错，是参数编码错**。

```bash
./demo ../envelope.json "CrossLang-测试123"     # ❌ 密码字节已变形
./demo ../envelope.json "hex:43726f73734c616e672de6b58be8af95313233"   # ✅ UTF-8 十六进制
```

C / C++ 的 demo 支持 `hex:` 前缀；Go / Rust / C# / Java / Python 从 Unicode 命令行读取参数，不受影响。
生产环境密码一般来自输入框或配置文件，建议统一按 UTF-8 字节处理。

### 坑 2：Rust 在含中文的路径下链接失败

`cargo build` 编译能过，但链接阶段 `ld.exe` 报一堆
`cannot find ...\target\release\deps\*.rcgu.o: No such file or directory`——
因为目标文件路径里含中文，MinGW 的 ld 按 ANSI 代码页解析，找不到文件。

```bash
# 把构建目录放到纯 ASCII 路径即可
export CARGO_TARGET_DIR=F:/build/rust-target
cargo build --release
```

源码放在中文目录没问题，问题只出在链接器读目标文件路径这一步。

### 坑 3：Go 的 GOROOT

MSYS2 分发的 `go.exe` 是裁剪版，未设 `GOROOT` 时会报
`cannot find GOROOT directory`：

```bash
export GOROOT=/e/toolchain/msys2/msys64/ucrt64/lib/go    # 按实际安装路径调整
```

官方安装包（go.dev 下载的 msi/zip）不会有这个问题。

### 坑 4：AAD 里的 JSON 转义规则（最容易翻车的地方）

AAD 是**逐字节参与认证**的，各语言 JSON 库的默认行为并不一致：

| 语言 / 库 | 默认行为 | 处理方式 |
|---|---|---|
| JavaScript `JSON.stringify` | 不转义 `<` `>` `&`，非 ASCII 原样输出 | 基准 |
| Python `json.dumps` | 默认 `ensure_ascii=True` 会把中文转成 `\uXXXX` | 必须 `ensure_ascii=False` + `separators=(",", ":")` |
| Go `json.Marshal` | 会转义 `<` `>` `&` 为 `\u003c` 等 | 用 `Encoder.SetEscapeHTML(false)` |
| C# `JsonSerializer` | 默认把非 ASCII 转成 `\uXXXX` | 用 `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` |
| Rust `serde_json` | 不转义以上字符，非 ASCII 原样输出 | 无需处理 |
| C（本实现） | 手工 `snprintf` 拼接，字符串不做转义 | 用户名含引号/反斜杠时需自行转义 |

只要有一处不一致，解密就会失败（GCM 认证不通过），而且**没有任何提示说明是 AAD 的问题**——
这是排查时最耗时间的一类故障。

---

## 算法要点（改动时务必对照）

```
IKM        = PBKDF2-HMAC-SHA256(password, accountSalt, iterations, 32)
sessionKey = HKDF-SHA256(IKM,        salt = 空,      info = "sci-session-v1", 32)
fileKey    = HKDF-SHA256(sessionKey, salt = 文件盐,  info = "sci-file-v4",   32)
AAD        = 固定键序的元数据 JSON
密文       = AES-256-GCM(fileKey, iv, plaintext, AAD)，输出 密文 || 16 字节 tag
```

**三处最容易被写错的地方：**

1. **HKDF 的 salt 为空时**，按 RFC 5869 要当成 32 个 `0x00` 字节作为 HMAC 的 key，
   不是"空 key"。所有实现都按这个规则处理（Python 版手写了 HKDF，可作对照）。
2. **AAD 的键顺序**必须是
   `v, username, accountSalt, salt, iv, iterations, savedAt`，
   且 `iterations` / `savedAt` 是**数字**（不带引号），JSON 中**不能有空格**。
   任何一处不同，解密必然失败——这不是 bug，是设计（防篡改）。
3. **`data` 字段**是"密文 + 16 字节 tag"拼在一起。
   OpenSSL 需要手动把后 16 字节设为 tag；Java 的 `Cipher` 会自动剥离；
   Go 的 `gcm.Open` / Rust 的 `aes-gcm` / C# 的 `AesGcm` 都要求显式分离 tag。

---

## 验证记录（2026-11-04 实测）

### 一、三级派生 vs 测试向量

八种实现的 `ikm` / `sessionKey` / `fileKey` 均与 `test_vectors.json` **逐位一致**：

```
ikm        76d9e772e61f2cd5a484ed2707982c535c3fa9faa7f8e68e98e777d3e994dcec
sessionKey a53e9e23293c92c93d09a184dd4f858c8a714ac3b57b913e2ef361a6864fd965
fileKey    34bbb51f3931c9ffe208f9479c5f27190886b2992f71032ae317491d380ca89c
```

### 二、解同一封信封（`envelope.json`）

| 语言 | plainSha | 结论 |
|---|---|---|
| C / C++ / Java / Go / Rust / C# / Python | `0062eed7…49fe3` | 全部等于向量值 |

### 三、JS 生成信封 → 七语言解（`envelope_js.json`，密码 `Matrix-矩阵2026`）

| 语言 | 结果 |
|---|---|
| C / C++ / Java / Go / Rust / C# / Python | **7/7 全部解出**，明文 SHA-256 均为 `6c5cbb34…60ab` |

### 四、七语言生成信封 → JS 解（JSCore `decryptEnvelopeV4`）

```
c       OK   {"roundtrip":"c","n":7}
cpp     OK   {"roundtrip":"cpp","n":7}
java    OK   {"roundtrip":"java","n":7}
go      OK   {"roundtrip":"go","n":7}
rust    OK   {"roundtrip":"rust","n":7}
csharp  OK   {"roundtrip":"csharp","n":7}
python  OK   {"roundtrip":"python","n":7}
→ 7/7
```

### 五、编译质量

| 项目 | 结果 |
|---|---|
| `gcc -Wall` / `g++ -Wall` | 零告警 |
| `go build` | 零告警 |
| `cargo build --release` | 零告警 |
| `dotnet build -c Release` | 0 警告 0 错误 |

### 编译 / 运行环境

| 工具 | 版本 |
|---|---|
| GCC | 16.2.0（MSYS2 UCRT64） |
| OpenSSL | 3.6.5 |
| OpenJDK | 21.0.13 LTS |
| Go | 1.27.3 |
| Rust | 1.99.1 |
| .NET SDK | 8.0.404 |
| Python | 3.14.8 + cryptography 50.0.2 |

> 补充：还用 `openssl kdf` 命令行单独核对了 PBKDF2 与两级 HKDF 的参数，与向量一致，
> 相当于对 C 实现的派生链做了第三方工具交叉确认。

---

## 适用范围

- 支持 **v4 信封**（当前默认格式）的加密与解密。
- v3 信封结构与 v4 相同，只差 `v` 字段值与 HKDF 的 info（`sci-file-v3`），
  按同样代码改两处即可。
- v5（Argon2id）需要 Argon2 实现，本目录未包含。
- v2 是主程序早期格式（AAD 只含部分字段），如需要可参照主程序源码另行实现。
