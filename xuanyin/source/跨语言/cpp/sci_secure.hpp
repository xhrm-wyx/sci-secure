/*
 * sci_secure.hpp — 玄印 v4 信封 C++ 封装
 * ---------------------------------------------------------------------
 * 底层直接复用 sci_secure.c（OpenSSL），本头文件只做 std::string 包装，
 * 避免"两套实现、两种行为"的风险。
 *
 * 用法：
 *   #include "sci_secure.hpp"
 *   std::string plain = sci::decryptV4(envelopeJson, "密码");
 *   std::string env   = sci::encryptV4("明文", "密码", "用户名");
 *
 * 编译（与 sci_secure.c 一起）：
 *   g++ -std=c++17 demo.cpp sci_secure.c -lcrypto -o demo
 */
#ifndef SCI_SECURE_HPP
#define SCI_SECURE_HPP

#include <stdexcept>
#include <string>
#include <cstdlib>

#include "sci_secure.h"

namespace sci {

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& msg) : std::runtime_error(msg) {}
};

/** 解密 v4 信封 JSON，返回明文（UTF-8 字节）。失败抛 sci::Error。 */
inline std::string decryptV4(const std::string& envelopeJson, const std::string& password)
{
    sci_env_v4 env;
    if (sci_env_parse_v4(envelopeJson.c_str(), &env) != 0)
        throw Error("信封格式不正确：缺少 accountSalt / salt / iv / data");

    unsigned char* out = nullptr;
    size_t outLen = 0;
    int rc = sci_decrypt_v4(&env, password.c_str(), &out, &outLen);
    sci_env_free(&env);

    if (rc != 0) {
        if (rc == -2) throw Error("认证失败：密码错误，或数据被篡改");
        throw Error("解密失败（错误码 " + std::to_string(rc) + "）");
    }
    std::string s(reinterpret_cast<const char*>(out), outLen);
    std::free(out);
    return s;
}

/** 加密为 v4 信封 JSON。iterations 传 0 或省略则用 600000。 */
inline std::string encryptV4(const std::string& plaintext,
                             const std::string& password,
                             const std::string& username = "",
                             long iterations = 600000)
{
    char* err = nullptr;
    char* env = sci_encrypt_v4(plaintext.data(), plaintext.size(),
                               password.c_str(), username.c_str(),
                               iterations, &err);
    if (!env) throw Error(err ? err : "加密失败");
    std::string s(env);
    std::free(env);
    return s;
}

} // namespace sci

#endif // SCI_SECURE_HPP
