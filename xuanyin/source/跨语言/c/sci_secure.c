/*
 * sci_secure.c — 玄印 v4 信封 C 实现（OpenSSL）
 * 与 JavaScript 版逐字节互通；参数已用 OpenSSL 命令行逐级对齐验证。
 */
#include "sci_secure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define SCI_TAG_LEN 16
#define SCI_IV_LEN  12

/* ---------------- Base64 ---------------- */

static const char B64TAB[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *sci_b64_encode(const unsigned char *in, size_t len)
{
    size_t out_len = ((len + 2) / 3) * 4;
    char *out = (char *)malloc(out_len + 1);
    if (!out) return NULL;
    size_t i, o = 0;
    for (i = 0; i + 2 < len; i += 3) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];
        out[o++] = B64TAB[(v >> 18) & 63];
        out[o++] = B64TAB[(v >> 12) & 63];
        out[o++] = B64TAB[(v >> 6) & 63];
        out[o++] = B64TAB[v & 63];
    }
    if (i < len) {
        unsigned v = (unsigned)in[i] << 16;
        int rem = (int)(len - i);
        if (rem == 2) v |= (unsigned)in[i + 1] << 8;
        out[o++] = B64TAB[(v >> 18) & 63];
        out[o++] = B64TAB[(v >> 12) & 63];
        out[o++] = (rem == 2) ? B64TAB[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

static int b64val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int sci_b64_decode(const char *in, unsigned char **out, size_t *out_len)
{
    size_t n = strlen(in), cap = (n / 4 + 1) * 3, o = 0;
    unsigned char *buf = (unsigned char *)malloc(cap ? cap : 1);
    if (!buf) return -1;
    int quad[4], q = 0;
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char)in[i];
        if (c == '=' ) { quad[q++] = -1; }
        else {
            int v = b64val(c);
            if (v < 0) continue;           /* 跳过换行/空白等 */
            quad[q++] = v;
        }
        if (q == 4) {
            buf[o++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
            if (quad[2] >= 0) buf[o++] = (unsigned char)(((quad[1] & 15) << 4) | (quad[2] >> 2));
            if (quad[3] >= 0) buf[o++] = (unsigned char)(((quad[2] & 3) << 6) | quad[3]);
            q = 0;
        }
    }
    *out = buf;
    *out_len = o;
    return 0;
}

/* ---------------- 极简 JSON 取值（仅用于固定信封结构） ---------------- */

static const char *seek_value(const char *json, const char *key)
{
    char pat[96];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static char *json_get_str(const char *json, const char *key)
{
    const char *p = seek_value(json, key);
    if (!p || *p != '"') return NULL;
    p++;
    size_t cap = strlen(p) + 1, o = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': buf[o++] = '\n'; break;
                case 't': buf[o++] = '\t'; break;
                case 'r': buf[o++] = '\r'; break;
                case 'b': buf[o++] = '\b'; break;
                case 'f': buf[o++] = '\f'; break;
                default:  buf[o++] = *p;   break;
            }
            p++;
        } else {
            buf[o++] = *p++;
        }
    }
    buf[o] = '\0';
    return buf;
}

static long json_get_long(const char *json, const char *key, long defv)
{
    const char *p = seek_value(json, key);
    if (!p) return defv;
    return strtol(p, NULL, 10);
}

static long long json_get_llong(const char *json, const char *key, long long defv)
{
    const char *p = seek_value(json, key);
    if (!p) return defv;
    return strtoll(p, NULL, 10);
}

static char *json_escape(const char *s)
{
    size_t n = strlen(s), cap = n * 2 + 1, o = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { buf[o++] = '\\'; buf[o++] = (char)c; }
        else if (c == '\n') { buf[o++] = '\\'; buf[o++] = 'n'; }
        else if (c == '\r') { buf[o++] = '\\'; buf[o++] = 'r'; }
        else if (c < 0x20) { /* 丢弃控制字符 */ }
        else buf[o++] = (char)c;
    }
    buf[o] = '\0';
    return buf;
}

/* ---------------- HKDF-SHA256（手写，兼容 OpenSSL 1.1.1 / 3.x） ---------------- */

static int hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *salt, size_t salt_len,
                       const char *info, unsigned char out[32])
{
    unsigned char prk[32];
    unsigned char zero[32];
    unsigned int len = 32;

    memset(zero, 0, sizeof(zero));
    const unsigned char *salt_use = (salt && salt_len) ? salt : zero;
    size_t salt_use_len = (salt && salt_len) ? salt_len : sizeof(zero);

    if (!HMAC(EVP_sha256(), salt_use, (int)salt_use_len, ikm, ikm_len, prk, &len))
        return -1;

    size_t info_len = strlen(info);
    unsigned char *t = (unsigned char *)malloc(info_len + 1);
    if (!t) return -1;
    memcpy(t, info, info_len);
    t[info_len] = 0x01;                       /* T(1) = HMAC(PRK, info || 0x01) */
    if (!HMAC(EVP_sha256(), prk, 32, t, info_len + 1, out, &len)) {
        free(t);
        return -1;
    }
    free(t);
    return 0;
}

/* ---------------- AAD 构造（键序固定，不得改动） ---------------- */

static char *build_aad(const sci_env_v4 *env)
{
    char *u = json_escape(env->username ? env->username : "");
    if (!u) return NULL;
    size_t need = strlen(u) + strlen(env->accountSalt) + strlen(env->salt)
                + strlen(env->iv) + 192;
    char *aad = (char *)malloc(need);
    if (!aad) { free(u); return NULL; }
    snprintf(aad, need,
        "{\"v\":4,\"username\":\"%s\",\"accountSalt\":\"%s\",\"salt\":\"%s\","
        "\"iv\":\"%s\",\"iterations\":%ld,\"savedAt\":%lld}",
        u, env->accountSalt, env->salt, env->iv, env->iterations, env->savedAt);
    free(u);
    return aad;
}

/* ---------------- 密钥派生（两级） ---------------- */

static int derive_file_key(const char *password, const char *accountSalt_b64,
                           long iterations, const char *fileSalt_b64,
                           unsigned char file_key[32])
{
    unsigned char *acct = NULL, *fsalt = NULL;
    size_t acct_len = 0, fsalt_len = 0;
    unsigned char ikm[32], session[32];
    int rc = -1;

    if (iterations < 50000)   iterations = 50000;
    if (iterations > 1000000) iterations = 1000000;

    if (sci_b64_decode(accountSalt_b64, &acct, &acct_len) != 0) return -1;
    if (sci_b64_decode(fileSalt_b64, &fsalt, &fsalt_len) != 0) { free(acct); return -1; }

    if (!PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           acct, (int)acct_len, (int)iterations,
                           EVP_sha256(), 32, ikm))
        goto done;

    if (hkdf_sha256(ikm, 32, NULL, 0, "sci-session-v1", session) != 0)
        goto done;

    if (hkdf_sha256(session, 32, fsalt, fsalt_len, "sci-file-v4", file_key) != 0)
        goto done;

    rc = 0;
done:
    memset(ikm, 0, sizeof(ikm));
    memset(session, 0, sizeof(session));
    free(acct);
    free(fsalt);
    return rc;
}

/* ---------------- 信封解析 / 释放 ---------------- */

int sci_env_parse_v4(const char *json, sci_env_v4 *env)
{
    if (!json || !env) return -1;
    memset(env, 0, sizeof(*env));

    env->username    = json_get_str(json, "username");
    env->accountSalt = json_get_str(json, "accountSalt");
    env->salt        = json_get_str(json, "salt");
    env->iv          = json_get_str(json, "iv");
    env->data        = json_get_str(json, "data");
    env->iterations  = json_get_long(json, "iterations", 0);
    env->savedAt     = json_get_llong(json, "savedAt", 0);

    if (!env->accountSalt || !env->salt || !env->iv || !env->data) {
        sci_env_free(env);
        return -2;
    }
    if (!env->username) {
        env->username = (char *)malloc(1);
        if (env->username) env->username[0] = '\0';
    }
    return 0;
}

void sci_env_free(sci_env_v4 *env)
{
    if (!env) return;
    free(env->username);
    free(env->accountSalt);
    free(env->salt);
    free(env->iv);
    free(env->data);
    memset(env, 0, sizeof(*env));
}

/* ---------------- 解密 ---------------- */

int sci_decrypt_v4(const sci_env_v4 *env, const char *password,
                   unsigned char **out, size_t *out_len)
{
    unsigned char file_key[32];
    unsigned char *iv = NULL, *ct = NULL;
    size_t iv_len = 0, ct_len = 0, body_len = 0;
    char *aad = NULL;
    int rc = -1, len = 0, flen = 0;
    unsigned char *plain = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    if (!env || !password || !out || !out_len) return -1;
    *out = NULL; *out_len = 0;

    if (derive_file_key(password, env->accountSalt, env->iterations,
                        env->salt, file_key) != 0)
        return -1;

    if (sci_b64_decode(env->iv, &iv, &iv_len) != 0) goto cleanup;
    if (sci_b64_decode(env->data, &ct, &ct_len) != 0) goto cleanup;
    if (iv_len != SCI_IV_LEN || ct_len <= SCI_TAG_LEN) { rc = -3; goto cleanup; }

    aad = build_aad(env);
    if (!aad) goto cleanup;

    body_len = ct_len - SCI_TAG_LEN;
    plain = (unsigned char *)malloc(body_len + 1);
    if (!plain) goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, file_key, iv) != 1) goto cleanup;

    if (EVP_DecryptUpdate(ctx, NULL, &len, (const unsigned char *)aad, (int)strlen(aad)) != 1) goto cleanup;
    if (body_len > 0) {
        if (EVP_DecryptUpdate(ctx, plain, &len, ct, (int)body_len) != 1) goto cleanup;
    } else {
        len = 0;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SCI_TAG_LEN, ct + body_len) != 1) goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, plain + len, &flen) != 1) { rc = -2; goto cleanup; }

    *out_len = (size_t)(len + flen);
    plain[*out_len] = '\0';
    *out = plain;
    plain = NULL;
    rc = 0;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (plain) free(plain);
    free(iv); free(ct); free(aad);
    memset(file_key, 0, sizeof(file_key));
    return rc;
}

/* ---------------- 加密 ---------------- */

char *sci_encrypt_v4(const char *plaintext, size_t plain_len,
                     const char *password, const char *username,
                     long iterations, char **err)
{
    unsigned char acct[16], fsalt[32], iv[SCI_IV_LEN], file_key[32];
    unsigned char *ct = NULL;
    char *acct_b64 = NULL, *fsalt_b64 = NULL, *iv_b64 = NULL, *ct_b64 = NULL;
    char *u = NULL, *aad = NULL, *out = NULL;
    int len = 0, flen = 0;
    long long now_ms = 0;
    size_t aad_need = 0, need = 0, aad_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;

    if (err) *err = NULL;
    if (iterations <= 0) iterations = 600000;
    if (iterations < 50000) iterations = 50000;
    if (iterations > 1000000) iterations = 1000000;

    if (RAND_bytes(acct, sizeof(acct)) != 1) goto fail;
    if (RAND_bytes(fsalt, sizeof(fsalt)) != 1) goto fail;
    if (RAND_bytes(iv, sizeof(iv)) != 1) goto fail;

    acct_b64  = sci_b64_encode(acct, sizeof(acct));
    fsalt_b64 = sci_b64_encode(fsalt, sizeof(fsalt));
    iv_b64    = sci_b64_encode(iv, sizeof(iv));
    if (!acct_b64 || !fsalt_b64 || !iv_b64) goto fail;

    if (derive_file_key(password, acct_b64, iterations, fsalt_b64, file_key) != 0) goto fail;

    u = json_escape((username && *username) ? username : "");
    if (!u) goto fail;

    now_ms = (long long)time(NULL) * 1000LL;
    aad_need = strlen(u) + strlen(acct_b64) + strlen(fsalt_b64) + strlen(iv_b64) + 192;
    aad = (char *)malloc(aad_need);
    if (!aad) goto fail;
    snprintf(aad, aad_need,
        "{\"v\":4,\"username\":\"%s\",\"accountSalt\":\"%s\",\"salt\":\"%s\","
        "\"iv\":\"%s\",\"iterations\":%ld,\"savedAt\":%lld}",
        u, acct_b64, fsalt_b64, iv_b64, iterations, now_ms);

    ct = (unsigned char *)malloc(plain_len + SCI_TAG_LEN + 1);
    if (!ct) goto fail;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto fail;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SCI_IV_LEN, NULL) != 1) goto fail;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, file_key, iv) != 1) goto fail;
    if (EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char *)aad, (int)strlen(aad)) != 1) goto fail;
    if (plain_len > 0) {
        if (EVP_EncryptUpdate(ctx, ct, &len, (const unsigned char *)plaintext, (int)plain_len) != 1) goto fail;
    } else {
        len = 0;
    }
    if (EVP_EncryptFinal_ex(ctx, ct + len, &flen) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SCI_TAG_LEN, ct + len + flen) != 1) goto fail;

    ct_b64 = sci_b64_encode(ct, (size_t)(len + flen + SCI_TAG_LEN));
    if (!ct_b64) goto fail;

    {
        need = strlen(aad) + strlen(ct_b64) + 64;
        out = (char *)malloc(need);
        if (!out) goto fail;
        /* aad 形如 {...}，把末尾的 } 换成 ,"data":"..."} */
        aad_len = strlen(aad);
        memcpy(out, aad, aad_len - 1);
        snprintf(out + aad_len - 1, need - (aad_len - 1), ",\"data\":\"%s\"}", ct_b64);
    }

    EVP_CIPHER_CTX_free(ctx);
    free(acct_b64); free(fsalt_b64); free(iv_b64); free(ct); free(ct_b64); free(u); free(aad);
    memset(file_key, 0, sizeof(file_key));
    return out;

fail:
    if (err && !*err) *err = (char *)"encrypt failed (openssl)";
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    free(acct_b64); free(fsalt_b64); free(iv_b64); free(ct); free(ct_b64); free(u); free(aad);
    memset(file_key, 0, sizeof(file_key));
    return NULL;
}
