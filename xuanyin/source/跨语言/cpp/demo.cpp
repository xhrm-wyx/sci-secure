/*
 * demo.cpp — 跨语言互通验证（C++ 版）
 *
 * 用法：
 *   g++ -std=c++17 -O2 demo.cpp ../c/sci_secure.c -I../c -lcrypto -o demo
 *   ./demo ../envelope.json "CrossLang-测试123"
 */
#include "sci_secure.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <openssl/evp.h>

static std::string readFile(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("读取文件失败: " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static std::string sha256hex(const std::string& data)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    EVP_Digest(data.data(), data.size(), md, &mdlen, EVP_sha256(), nullptr);
    static const char* HEX = "0123456789abcdef";
    std::string out;
    out.reserve(mdlen * 2);
    for (unsigned int i = 0; i < mdlen; ++i) {
        out.push_back(HEX[md[i] >> 4]);
        out.push_back(HEX[md[i] & 0x0F]);
    }
    return out;
}

static std::string decodePassword(const std::string& arg)
{
    if (arg.rfind("hex:", 0) != 0) return arg;
    const std::string h = arg.substr(4);
    std::string out;
    out.reserve(h.size() / 2);
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        unsigned int v = 0;
        std::sscanf(h.c_str() + i, "%2x", &v);
        out.push_back(static_cast<char>(v));
    }
    return out;
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cout << "用法: demo <envelope.json> <密码>\n";
        return 1;
    }

    try {
        const std::string json = readFile(argv[1]);
        const std::string password = decodePassword(argv[2]);

        const std::string plain = sci::decryptV4(json, password);

        std::cout << "plainLen  : " << plain.size() << "\n";
        std::cout << "plainSha  : " << sha256hex(plain) << "\n";

        std::ofstream out("out.txt", std::ios::binary);
        out.write(plain.data(), static_cast<std::streamsize>(plain.size()));

        std::cout << "plaintext : " << plain << "\n";

        const std::string env2 = sci::encryptV4("{\"roundtrip\":\"cpp\",\"n\":7}", password, "cpp-demo");
        {
            std::ofstream ef("roundtrip_envelope.json", std::ios::binary);
            ef.write(env2.data(), static_cast<std::streamsize>(env2.size()));
        }
        const std::string back = sci::decryptV4(env2, password);
        std::cout << "roundtrip : " << back << "\n";
        std::cout << "OK        : "
                  << (back == "{\"roundtrip\":\"cpp\",\"n\":7}" ? "true" : "false") << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cout << "失败: " << e.what() << "\n";
        return 3;
    }
}
