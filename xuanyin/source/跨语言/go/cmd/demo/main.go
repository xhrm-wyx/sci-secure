// demo — 跨语言互通验证（Go 版）
//
// 用法：
//
//	go run ./cmd/demo ../envelope.json "CrossLang-测试123"
//	go run ./cmd/demo ../envelope.json "hex:43726f73734c616e672de6b58be8af95313233"
//
// Windows 下若控制台代码页导致中文密码变形，可用 hex: 前缀直接给 UTF-8 十六进制。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	scisecure "scisecure"
)

func decodePassword(arg string) string {
	if !strings.HasPrefix(arg, "hex:") {
		return arg
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(arg, "hex:"))
	if err != nil {
		fmt.Println("密码十六进制解析失败:", err)
		os.Exit(2)
	}
	return string(raw)
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("用法: demo <envelope.json> <密码|hex:...>")
		os.Exit(1)
	}

	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("读取信封失败:", err)
		os.Exit(2)
	}
	password := decodePassword(os.Args[2])

	env, err := scisecure.ParseEnvelope(raw)
	if err != nil {
		fmt.Println("解析失败:", err)
		os.Exit(3)
	}

	// 打印三级派生中间值，便于与 test_vectors.json 逐位核对
	ikm, session, fileKey, err := scisecure.DeriveKeys(password, env.AccountSalt, env.Iterations, env.Salt)
	if err != nil {
		fmt.Println("派生失败:", err)
		os.Exit(3)
	}
	fmt.Println("ikm       :", hex.EncodeToString(ikm))
	fmt.Println("sessionKey:", hex.EncodeToString(session))
	fmt.Println("fileKey   :", hex.EncodeToString(fileKey))

	plain, err := scisecure.DecryptV4(env, password)
	if err != nil {
		fmt.Println("解密失败:", err)
		os.Exit(4)
	}

	fmt.Println("plainLen  :", len(plain))
	fmt.Println("plainSha  :", sha256hex(plain))

	if err := os.WriteFile("out.txt", plain, 0o644); err != nil {
		fmt.Println("写 out.txt 失败:", err)
	}

	fmt.Println("plaintext :", string(plain))

	const roundtripWant = `{"roundtrip":"go","n":7}`
	env2, err := scisecure.EncryptV4([]byte(roundtripWant), password, "go-demo", 600000)
	if err != nil {
		fmt.Println("加密失败:", err)
		os.Exit(5)
	}
	if err := os.WriteFile("roundtrip_envelope.json", env2, 0o644); err != nil {
		fmt.Println("写 roundtrip_envelope.json 失败:", err)
	}
	back, err := scisecure.DecryptV4JSON(env2, password)
	if err != nil {
		fmt.Println("回解失败:", err)
		os.Exit(5)
	}
	fmt.Println("roundtrip :", string(back))
	fmt.Println("OK        :", string(back) == roundtripWant)
}
