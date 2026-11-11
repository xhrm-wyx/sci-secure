package scisecure

import (
	"crypto/rand"
	"time"
)

// randomBytes 读取 n 个密码学安全随机字节；失败返回 nil。
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	return b
}

// nowMillis 返回当前 Unix 毫秒时间戳。
func nowMillis() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
