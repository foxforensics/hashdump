package hashdump

import (
	"crypto/aes"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"

	_cipher "crypto/cipher"
)

func decryptDES(b, key1, key2 []byte) ([]byte, error) {
	var buf []byte

	cipher1, err := des.NewCipher(key1)

	if err != nil {
		return nil, err
	}

	cipher2, err := des.NewCipher(key2)

	if err != nil {
		return nil, err
	}

	buf1 := make([]byte, 8)
	buf2 := make([]byte, 8)

	cipher1.Decrypt(buf1, b[:8])
	cipher2.Decrypt(buf2, b[8:])

	buf = append(buf, buf1...)
	buf = append(buf, buf2...)

	return buf, nil
}

func decryptAES(b, key, iv []byte) ([]byte, error) {
	buf := make([]byte, len(b))

	cipher, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	_cipher.NewCBCDecrypter(cipher, iv).CryptBlocks(buf, b)

	return buf, nil
}

func decryptRC4(b, key []byte) ([]byte, error) {
	buf := make([]byte, len(b))

	cipher, err := rc4.NewCipher(key)

	if err != nil {
		return nil, err
	}

	cipher.XORKeyStream(buf, b)

	return buf, nil
}

func deriveMD5(b, key []byte, n int) []byte {
	buf := make([]byte, 16)

	hasher := md5.New()
	hasher.Write(key)

	for i := 0; i < n; i++ {
		hasher.Write(b)
	}

	sum := hasher.Sum(nil)

	copy(buf, sum)

	return buf
}
