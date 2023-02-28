package cryptoAes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
)

const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz"

type result struct {
	CT   string `json:"ct"`
	IV   string `json:"iv"`
	Salt string `json:"s"`
}

func Encrypt(data, key string) (string, error) {
	salt, err := generateRandomString(8)
	dx := ""
	salted := strings.Builder{}

	if err != nil {
		return "", err
	}

	if len(data)%16 != 0 {
		padding := 16 - len(data)%16
		data = string(append([]byte(data), bytes.Repeat([]byte{byte(padding)}, padding)...))
	}

	for i := 0; i < 3; i++ {
		x := md5.Sum([]byte(dx + key + salt))
		dx = string(x[:])
		salted.WriteString(dx)
	}

	saltedBytes := []byte(salted.String())

	k := saltedBytes[:32]
	iv := saltedBytes[32:48]

	block, _ := aes.NewCipher(k)
	cipherText := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, []byte(data))
	hash := hex.EncodeToString(cipherText)

	raw, err := json.Marshal(result{
		CT:   base64.URLEncoding.EncodeToString([]byte(hash)),
		IV:   hex.EncodeToString(iv),
		Salt: hex.EncodeToString([]byte(salt)),
	})

	return string(raw), err
}

func EncryptBytes(data []byte, key string) (string, error) {
	return Encrypt(string(data), key)
}

func Decrypt(data, key string) (string, error) {
	var (
		res       result
		md5result strings.Builder
	)
	err := json.Unmarshal([]byte(data), &res)

	if err != nil {
		return "", err
	}

	ct, err := base64.URLEncoding.DecodeString(res.CT)

	if err != nil {
		return "", err
	}

	iv, err := hex.DecodeString(res.IV)

	if err != nil {
		return "", err
	}

	salt, err := hex.DecodeString(res.Salt)

	if err != nil {
		return "", err
	}

	var c []byte
	c = append(c, []byte(key)...)
	c = append(c, salt...)

	md5Slice := make([]string, 3)
	hash := md5.Sum(c)
	md5Slice[0] = string(hash[:])
	md5result.WriteString(md5Slice[0])

	for i := 1; i < 3; i++ {
		hash = md5.Sum(append([]byte(md5Slice[i-1]), c...))
		md5Slice[i] = string(hash[:])
		md5result.WriteString(md5Slice[i])
	}

	md5String := md5result.String()

	k := md5String[:32]

	out, err := hex.DecodeString(string(ct))

	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(k))

	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(out, out)

	return string(pKCS7Padding(out)), nil

}

func DecryptBytes(data []byte) string {
	return ""
}

func generateRandomString(length int) (string, error) {
	ret := make([]byte, length)

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(LETTERS))))

		if err != nil {
			return "", err
		}
		ret[i] = LETTERS[num.Int64()]
	}
	return base64.URLEncoding.EncodeToString(ret)[:length], nil
}

func pKCS7Padding(src []byte) []byte {
	length := len(src)
	padding := int(src[length-1])
	return src[:(length - padding)]
}
