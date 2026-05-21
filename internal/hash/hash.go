package hash

import (
	"crypto/sha512"
	"encoding/hex"
)

const Size = 48

func Sha384(b []byte) [Size]byte {
	return sha512.Sum384(b)
}

func Hex(d [Size]byte) string {
	return hex.EncodeToString(d[:])
}
