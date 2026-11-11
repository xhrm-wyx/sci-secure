/*
 * sci_secure.h — 玄印（sci-secure）v4 信封跨语言实现（C 版）
 * ---------------------------------------------------------------------
 * 与 JavaScript 版 sci-secure-core.js 完全互通：
 *   IKM        = PBKDF2-HMAC-SHA256(password, accountSalt, iterations, 32)
 *   sessionKey = HKDF-SHA256(IKM,      salt=空,       info="sci-session-v1", 32)
 *   fileKey    = HKDF-SHA256(sessionKey, salt=文件盐, info="sci-file-v4",   32)
 *   AAD        = 固定键序的元数据 JSON（见 .c 内 build_aad）
 *   密文       = AES-256-GCM(fileKey, iv, plaintext, AAD)，输出 密文||16字节tag
 *
 * 依赖：OpenSSL 1.1.1 及以上（1.1.1 / 3.x 均可），只用 EVP + HMAC + RAND
 * 编译：见 README.md
 */
#ifndef SCI_SECURE_H
#define SCI_SECURE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char     *username;     /* 用户名，可为空字符串 */
    char     *accountSalt;  /* Base64 */
    char     *salt;         /* Base64，文件盐 32 字节 */
    char     *iv;           /* Base64，12 字节 */
    long      iterations;   /* PBKDF2 迭代次数（读取时钳制到 [50000, 1000000]） */
    long long savedAt;      /* 时间戳（毫秒），参与 AAD */
    char     *data;         /* Base64，密文||16 字节 tag */
} sci_env_v4;

/* 解析 v4 信封 JSON。成功返回 0；失败返回负值。用 sci_env_free 释放。 */
int  sci_env_parse_v4(const char *json, sci_env_v4 *env);
void sci_env_free(sci_env_v4 *env);

/* 解密 v4 信封。成功返回 0，*out 为 malloc 出来的明文（末尾补 NUL），*out_len 为真实长度。
 * 失败返回负值：-2 表示认证失败（密码错误或数据被篡改）。 */
int  sci_decrypt_v4(const sci_env_v4 *env, const char *password,
                    unsigned char **out, size_t *out_len);

/* 加密为 v4 信封 JSON。返回 malloc 字符串（调用者 free），失败返回 NULL 并把原因写入 *err。 */
char *sci_encrypt_v4(const char *plaintext, size_t plain_len,
                     const char *password, const char *username,
                     long iterations, char **err);

/* 工具函数（可单独使用） */
char *sci_b64_encode(const unsigned char *in, size_t len);
int   sci_b64_decode(const char *in, unsigned char **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SCI_SECURE_H */
