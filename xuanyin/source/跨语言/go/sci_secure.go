// Package scisecure — 玄印（sci-secure）v4 信封跨语言实现（Go 版）
//
// 与 JavaScript 版 sci-secure-core.js 完全互通：
//
//	IKM        = PBKDF2-HMAC-SHA256(password, accountSalt, iterations, 32)
//	sessionKey = HKDF-SHA256(IKM,        salt=空,     info="sci-session-v1", 32)
//	fileKey    = HKDF-SHA256(sessionKey, salt=文件盐, info="sci-file-v4",    32)
//	AAD        = 固定键序的元数据 JSON（见 buildAAD）
//	密文        = AES-256-GCM(fileKey, iv, plaintext, AAD)，输出 密文||16字节tag
//
// 依赖：仅 Go 标准库（要求 Go 1.24+，因为用到了 crypto/pbkdf2 与 crypto/hkdf）。
package scisecure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// 迭代次数钳制区间，与服务端/JS 端保持一致，防止恶意信封让客户端卡死。
const (
	MinIterations     = 50000
	MaxIterations     = 1000000
	DefaultIterations = 600000
	TagLen            = 16
	KeyLen            = 32
)

var (
	// ErrAuth 认证失败：密码错误，或数据/AAD 被篡改。
	ErrAuth = errors.New("认证失败：密码错误或数据已被篡改")
	// ErrVersion 不是受支持的 v4 信封。
	ErrVersion = errors.New("不支持的信封版本（本实现仅支持 v4）")
)

// Envelope 是 v4 信封的字段定义。JSON 键序即结构体字段序，与 AAD 构造严格一致。
type Envelope struct {
	V           int    `json:"v"`
	Username    string `json:"username"`
	AccountSalt string `json:"accountSalt"`
	Salt        string `json:"salt"`
	IV          string `json:"iv"`
	Iterations  int    `json:"iterations"`
	SavedAt     int64  `json:"savedAt"`
	Data        string `json:"data"`
}

// aadPayload 只包含参与 AAD 的字段（不含 data）。
type aadPayload struct {
	V           int    `json:"v"`
	Username    string `json:"username"`
	AccountSalt string `json:"accountSalt"`
	Salt        string `json:"salt"`
	IV          string `json:"iv"`
	Iterations  int    `json:"iterations"`
	SavedAt     int64  `json:"savedAt"`
}

// jsonQuote 生成与 JavaScript JSON.stringify 行为一致的字符串字面量：
// 不转义 < > &，不转义非 ASCII，仅转义引号、反斜杠与控制字符。
func jsonQuote(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return `""`
	}
	return strings.TrimRight(buf.String(), "\n")
}

func buildAAD(username, accountSalt, salt, iv string, iterations int, savedAt int64) []byte {
	return []byte(fmt.Sprintf(
		`{"v":4,"username":%s,"accountSalt":%s,"salt":%s,"iv":%s,"iterations":%d,"savedAt":%d}`,
		jsonQuote(username), jsonQuote(accountSalt), jsonQuote(salt), jsonQuote(iv),
		iterations, savedAt))
}

// BuildAAD 导出版 AAD 构造，便于测试与自查。
func BuildAAD(username, accountSalt, salt, iv string, iterations int, savedAt int64) []byte {
	return buildAAD(username, accountSalt, salt, iv, iterations, savedAt)
}

func clampIterations(n int) int {
	if n < MinIterations {
		return MinIterations
	}
	if n > MaxIterations {
		return MaxIterations
	}
	return n
}

// DeriveKeys 执行三级派生，按顺序返回 ikm / sessionKey / fileKey。
// 传入的 iterations 会被钳制到 [50000, 1000000]。
func DeriveKeys(password, accountSaltB64 string, iterations int, fileSaltB64 string) (ikm, sessionKey, fileKey []byte, err error) {
	acctSalt, err := base64.StdEncoding.DecodeString(accountSaltB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("accountSalt 不是合法 base64: %w", err)
	}
	fileSalt, err := base64.StdEncoding.DecodeString(fileSaltB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("salt 不是合法 base64: %w", err)
	}

	it := clampIterations(iterations)

	ikm, err = pbkdf2.Key(sha256.New, password, acctSalt, it, KeyLen)
	if err != nil {
		return nil, nil, nil, err
	}
	sessionKey, err = hkdf.Key(sha256.New, ikm, nil, "sci-session-v1", KeyLen)
	if err != nil {
		return nil, nil, nil, err
	}
	fileKey, err = hkdf.Key(sha256.New, sessionKey, fileSalt, "sci-file-v4", KeyLen)
	if err != nil {
		return nil, nil, nil, err
	}
	return ikm, sessionKey, fileKey, nil
}

// ParseEnvelope 解析信封 JSON。
func ParseEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("信封 JSON 解析失败: %w", err)
	}
	if env.V != 4 {
		return nil, ErrVersion
	}
	return &env, nil
}

// DecryptV4 解密 v4 信封，返回明文字节。
func DecryptV4(env *Envelope, password string) ([]byte, error) {
	if env.V != 4 {
		return nil, ErrVersion
	}
	_, _, fileKey, err := DeriveKeys(password, env.AccountSalt, env.Iterations, env.Salt)
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(env.IV)
	if err != nil {
		return nil, fmt.Errorf("iv 不是合法 base64: %w", err)
	}
	if len(iv) != 12 {
		return nil, fmt.Errorf("iv 长度应为 12 字节，实际 %d", len(iv))
	}
	blob, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, fmt.Errorf("data 不是合法 base64: %w", err)
	}
	if len(blob) < TagLen {
		return nil, errors.New("密文长度不足，缺少认证标签")
	}

	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := buildAAD(env.Username, env.AccountSalt, env.Salt, env.IV, env.Iterations, env.SavedAt)

	plain, err := gcm.Open(nil, iv, blob, aad)
	if err != nil {
		// GCM 校验失败一律归一为 ErrAuth，不区分具体原因
		return nil, ErrAuth
	}
	return plain, nil
}

// DecryptV4JSON 便捷函数：传入信封 JSON 文本与密码，返回明文。
func DecryptV4JSON(envelopeJSON []byte, password string) ([]byte, error) {
	env, err := ParseEnvelope(envelopeJSON)
	if err != nil {
		return nil, err
	}
	return DecryptV4(env, password)
}

// EncryptV4 用给定密码加密，返回信封 JSON 文本（缩进两格，便于人工查看）。
// username 可为空字符串；iterations <= 0 时使用 600000。
func EncryptV4(plain []byte, password, username string, iterations int) ([]byte, error) {
	return EncryptV4At(plain, password, username, iterations, nowMillis())
}

// EncryptV4At 与 EncryptV4 相同，但可显式指定 savedAt（毫秒时间戳），便于生成可复现向量。
func EncryptV4At(plain []byte, password, username string, iterations int, savedAt int64) ([]byte, error) {
	if iterations <= 0 {
		iterations = DefaultIterations
	}
	iterations = clampIterations(iterations)

	accountSalt := randomBytes(16)
	fileSalt := randomBytes(32)
	iv := randomBytes(12)
	if accountSalt == nil || fileSalt == nil || iv == nil {
		return nil, errors.New("随机数生成失败")
	}

	_, _, fileKey, err := DeriveKeys(password, base64.StdEncoding.EncodeToString(accountSalt), iterations,
		base64.StdEncoding.EncodeToString(fileSalt))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	acctB64 := base64.StdEncoding.EncodeToString(accountSalt)
	saltB64 := base64.StdEncoding.EncodeToString(fileSalt)
	ivB64 := base64.StdEncoding.EncodeToString(iv)
	aad := buildAAD(username, acctB64, saltB64, ivB64, iterations, savedAt)

	sealed := gcm.Seal(nil, iv, plain, aad)

	env := Envelope{
		V:           4,
		Username:    username,
		AccountSalt: acctB64,
		Salt:        saltB64,
		IV:          ivB64,
		Iterations:  iterations,
		SavedAt:     savedAt,
		Data:        base64.StdEncoding.EncodeToString(sealed),
	}
	return json.MarshalIndent(env, "", "  ")
}
