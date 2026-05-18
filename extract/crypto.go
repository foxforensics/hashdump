package extract

import (
	"crypto/aes"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	_cipher "crypto/cipher"
)

func decryptCleartext(b []byte, pek []PEK) (string, error) {
	var err error

	if len(b) == 0 {
		return "", nil
	}

	// get used key or first one
	i := min(b[4], byte(len(pek)-1))

	switch b[0] {
	case 0x13: // new decryption method
		b = b[8:] // skip header
		b, err = decryptAES(b[20:], pek[i], b[:16])

	default: // old decryption method
		b = b[8:] // skip header
		b, err = decryptRC4(b[16:], deriveMD5(b[:16], pek[i], 1))
	}

	if err != nil {
		return "", err
	}

	if len(b) <= 0x6F {
		return "", nil // empty properties
	}

	if binary.LittleEndian.Uint32(b[:4]) != 0 {
		return "", errors.New("invalid properties")
	}

	if binary.LittleEndian.Uint16(b[108:]) != 0x50 {
		return "", errors.New("invalid properties")
	}

	for i := 112; i < len(b)-1; {
		p := b[i:]

		nl := binary.LittleEndian.Uint16(p[0:])
		vl := binary.LittleEndian.Uint16(p[2:])

		if int(6+nl+vl) > len(p) {
			break // something went wrong
		}

		if utf16(p[6:6+nl]) == cleartext {
			v, err := hex.DecodeString(string(p[6+nl : 6+nl+vl]))

			if err != nil {
				return "", err
			}

			if s := utf16(v); len(s) > 0 {
				return s, nil
			}

			// might be an encoding error
			return fmt.Sprintf("0x%x", v), nil
		}

		i += 6 + int(nl) + int(vl)
	}

	return "", nil
}

func decryptHistory(b, key1, key2 []byte, pek []PEK) ([]string, error) {
	var res []string
	var err error

	if len(b) == 0 {
		return res, nil
	}

	// get used key or first one
	i := min(b[4], byte(len(pek)-1))

	switch b[0] {
	case 0x13: // new decryption method
		b = b[8:] // skip header
		b, err = decryptAES(b[20:], pek[i], b[:16])

	default: // old decryption method
		b = b[8:] // skip header
		b, err = decryptRC4(b[16:], deriveMD5(b[:16], pek[i], 1))
	}

	if err != nil {
		return nil, err
	}

	// skip actual hash
	for i := 16; i < len(b); i += 16 {
		v, err := decryptDES(b[i:i+16], key1, key2)

		if err != nil {
			return nil, err
		}

		res = append(res, hex.EncodeToString(v))
	}

	return res, nil
}

func decryptHash(b, key1, key2, def []byte, pek []PEK) (string, error) {
	var err error

	if len(b) == 0 {
		return hex.EncodeToString(def), nil // default hash
	}

	// get used key or first one
	i := min(b[4], byte(len(pek)-1))

	switch b[0] {
	case 0x13: // new decryption method
		b = b[8:] // skip header
		b, err = decryptAES(b[20:36], pek[i], b[:16])

	default: // old decryption method
		b = b[8:] // skip header
		b, err = decryptRC4(b[16:], deriveMD5(b[:16], pek[i], 1))
	}

	if err != nil {
		return "", err
	}

	b, err = decryptDES(b, key1, key2)

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func decryptPEK(b, key []byte) ([]byte, error) {
	var pek PEK
	var err error

	switch b[0] {
	case 0x03: // 2016
		b = b[8:] // skip header
		b, err = decryptAES(b[16:], key, b[:16])

		if err != nil {
			return nil, err
		}

		pek = b[36:52]

	case 0x02: // 2000
		b = b[8:] // skip header
		b, err = decryptRC4(b[16:], deriveMD5(b[:16], key, 1000))

		if err != nil {
			return nil, err
		}

		pek = b[36:]

	default:
		// plain text?
	}

	if len(pek) != 16 {
		return nil, errors.New("invalid PEK length")
	}

	return pek, nil
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
