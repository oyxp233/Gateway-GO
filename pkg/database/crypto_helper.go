package database

import "crypto/rand"

// cryptoRandRead 从加密随机源读取字节。
func cryptoRandRead(buf []byte) (int, error) {
	return rand.Read(buf)
}
