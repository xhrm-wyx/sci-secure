/*
 * demo.c — 跨语言互通验证（C 版）
 *
 * 用法：
 *   gcc -O2 demo.c sci_secure.c -lcrypto -o demo
 *   ./demo ../envelope.json "CrossLang-测试123"
 *
 * 预期：解密成功，out.txt 与 test_vectors.json 的 plaintext_json 逐字节一致。
 */
#include "sci_secure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    if (len) *len = got;
    return buf;
}

static void print_sha256(const unsigned char *data, size_t len)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL);
    printf("plainSha  : ");
    for (unsigned int i = 0; i < mdlen; i++) printf("%02x", md[i]);
    printf("\n");
}

static char *decode_password(const char *arg)
{
    if (strncmp(arg, "hex:", 4) != 0) {
        char *cp = (char *)malloc(strlen(arg) + 1);
        strcpy(cp, arg);
        return cp;
    }
    const char *h = arg + 4;
    size_t n = strlen(h) / 2;
    char *out = (char *)malloc(n + 1);
    for (size_t i = 0; i < n; i++) {
        unsigned int v = 0;
        sscanf(h + i * 2, "%2x", &v);
        out[i] = (char)v;
    }
    out[n] = '\0';
    return out;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("用法: demo <envelope.json> <密码>\n");
        return 1;
    }

    char *password = decode_password(argv[2]);
    size_t json_len = 0;
    char *json = read_file(argv[1], &json_len);
    if (!json) { printf("读取文件失败: %s\n", argv[1]); return 1; }

    sci_env_v4 env;
    if (sci_env_parse_v4(json, &env) != 0) {
        printf("信封格式不正确：缺少 accountSalt / salt / iv / data\n");
        free(json);
        return 2;
    }

    unsigned char *plain = NULL;
    size_t plain_len = 0;
    int rc = sci_decrypt_v4(&env, password, &plain, &plain_len);
    if (rc != 0) {
        printf("解密失败 rc=%d（-2 = 密码错误或数据被篡改）\n", rc);
        sci_env_free(&env);
        free(json);
        return 3;
    }

    printf("plainLen  : %zu\n", plain_len);
    print_sha256(plain, plain_len);

    FILE *out = fopen("out.txt", "wb");
    if (out) { fwrite(plain, 1, plain_len, out); fclose(out); }

    printf("plaintext : ");
    fwrite(plain, 1, plain_len, stdout);
    printf("\n");

    /* 回收加密：自己生成的信封，自己能解开 */
    char *err = NULL;
    char *env2 = sci_encrypt_v4("{\"roundtrip\":\"c\",\"n\":7}", 23,
                                password, "c-demo", 600000, &err);
    if (env2) {
        FILE *ef = fopen("roundtrip_envelope.json", "wb");
        if (ef) { fwrite(env2, 1, strlen(env2), ef); fclose(ef); }
        sci_env_v4 e2;
        if (sci_env_parse_v4(env2, &e2) == 0) {
            unsigned char *back = NULL;
            size_t back_len = 0;
            if (sci_decrypt_v4(&e2, password, &back, &back_len) == 0) {
                printf("roundtrip : %.*s\n", (int)back_len, back);
                printf("OK        : %s\n",
                       (back_len == 23 && memcmp(back, "{\"roundtrip\":\"c\",\"n\":7}", 23) == 0)
                       ? "true" : "false");
                free(back);
            }
            sci_env_free(&e2);
        }
        free(env2);
    } else {
        printf("roundtrip : 加密失败 (%s)\n", err ? err : "unknown");
    }

    free(plain);
    sci_env_free(&env);
    free(json);
    return 0;
}
