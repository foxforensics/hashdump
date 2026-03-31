// Dump user password hashes from Active Directory databases.
//
// Usage:
//
//	hashdump system ntds
//
// The arguments are:
//
//	system
//		System registry hive (required).
//	ntds
//		Active Directory database (required).
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"

	_cipher "crypto/cipher"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.dev/go-ese/parser"
	"golang.org/x/text/encoding/unicode"
	"www.velocidex.com/golang/regparser"
)

// row attributes
const (
	pekData  = "ATTk590689"
	userType = "ATTj590126"
	userRow  = "ATTm590045"
	userSid  = "ATTr589970"
	ntHash   = "ATTk589914"
	lmHash   = "ATTk589879"
)

var (
	lmDefault = []byte{
		0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
	}
	ntDefault = []byte{
		0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31, 0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0,
	}
	transpose = [16]int{
		8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7,
	}
	userTypes = []int64{
		0x30000000, // SAM_NORMAL_USER_ACCOUNT
		0x30000001, // SAM_MACHINE_ACCOUNT
		0x30000002, // SAM_TRUST_ACCOUNT
	}
	keyClasses = []string{
		"JD", "Skew1", "GBG", "Data",
	}
)

type Pek []byte

type Hash []byte

type Record struct {
	Username string
	Rid      uint32
	LmHash   string
	NtHash   string
}

func (r *Record) String() string {
	return fmt.Sprintf("%s:%d:%s:%s:::",
		r.Username,
		r.Rid,
		r.LmHash,
		r.NtHash,
	)
}

func newPek(b, key []byte) Pek {
	var pek []byte

	buf := b[8:] // skip header

	switch b[0] {
	case 0x03: // 2016
		pek = decryptAes(buf[16:], key, buf[:16])
		pek = pek[36:52]

	case 0x02: // 2000
		pek = deriveMd5(buf[:16], key, 1000)
		pek = decryptRc4(buf[16:], pek)
		pek = pek[36:]

	default:
		// plain text?
	}

	if len(pek) != 16 {
		_, _ = fmt.Fprintln(os.Stderr, "invalid pek length")
		return []byte{}
	}

	return pek
}

func newHash(b, def, key1, key2 []byte, pek []Pek) Hash {
	if len(b) == 0 {
		return def // empty hash
	}

	buf := b[8:] // skip header

	switch b[0] {
	case 0x13: // new decryption method
		buf = decryptAes(buf[20:36], pek[b[4]], buf[:16])

	default: // old decryption method
		key := deriveMd5(buf[:16], pek[0], 1)
		buf = decryptRc4(buf[16:], key)
	}

	return decryptDes(buf, key1, key2)
}

func newRecord(row *ordereddict.Dict, usr string, pek []Pek) *Record {
	rid := extractRid(getBytes(row, userSid))
	k1, k2 := deriveKey(rid)

	return &Record{
		Username: usr,
		Rid:      rid,
		LmHash:   hex.EncodeToString(newHash(getBytes(row, lmHash), lmDefault, k1, k2, pek)),
		NtHash:   hex.EncodeToString(newHash(getBytes(row, ntHash), ntDefault, k1, k2, pek)),
	}
}

func getRow(row *ordereddict.Dict, key string) any {
	if v, ok := row.Get(key); ok && v != nil {
		return v
	}

	return nil
}

func getBytes(row *ordereddict.Dict, key string) []byte {
	if v := getRow(row, key); v != nil {
		b, _ := hex.DecodeString(v.(string))
		return b
	}

	return nil
}

func getPeks(ctg *parser.Catalog, att string, key []byte) (peks []Pek) {
	_ = ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(att); ok && v != nil {
			b, _ := hex.DecodeString(v.(string))
			peks = append(peks, newPek(b, key))
		}
		return nil
	})

	return
}

func getBootkey(r io.ReaderAt) ([]byte, error) {
	reg, err := regparser.NewRegistry(r)

	if err != nil {
		return nil, err
	}

	var key, buf []byte

	for _, class := range keyClasses {
		key := reg.OpenKey(fmt.Sprintf("\\%s\\Control\\Lsa\\%s", controlSet(reg), class))
		bin := make([]byte, key.ClassLength())

		_, err = reg.BaseBlock.HiveBin().Reader.ReadAt(bin, int64(key.Class()+4096+4))

		if err != nil {
			return nil, err
		}

		buf = append(buf, bin...)
	}

	str := string(buf)

	// convert if unicode string
	if len(buf) > 32 {
		decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		str, _ = decoder.String(string(buf))
	}

	// decode string
	buf, err = hex.DecodeString(str)

	if err != nil {
		return nil, err
	}

	for i := 0; i < len(buf); i++ {
		key = append(key, buf[transpose[i]])
	}

	return key, nil
}

func getRecords(b, key []byte) ([]Record, error) {
	ctx, err := parser.NewESEContext(bytes.NewReader(b), int64(len(b)))

	if err != nil {
		return nil, err
	}

	ctg, err := parser.ReadCatalog(ctx)

	if err != nil {
		return nil, err
	}

	var records []Record

	peks := getPeks(ctg, pekData, key)

	_ = ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(userRow); ok && v != nil {
			userType, _ := row.GetInt64(userType)

			if slices.Contains(userTypes, userType) {
				records = append(records, *newRecord(row, v.(string), peks))
			}
			return nil
		}
		return nil
	})

	return records, nil
}

func extractRid(sid []byte) uint32 {
	n, b := sid[1], sid[8:]

	return binary.BigEndian.Uint32(b[(n-1)*4 : (n-1)*4+4])
}

func decryptDes(b, key1, key2 []byte) []byte {
	var buf []byte

	cipher1, err := des.NewCipher(key1)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return buf
	}

	cipher2, err := des.NewCipher(key2)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return buf
	}

	buf1 := make([]byte, 8)
	buf2 := make([]byte, 8)

	cipher1.Decrypt(buf1, b[:8])
	cipher2.Decrypt(buf2, b[8:])

	buf = append(buf, buf1...)
	buf = append(buf, buf2...)

	return buf
}

func decryptAes(b, key, iv []byte) []byte {
	buf := make([]byte, len(b))

	cipher, err := aes.NewCipher(key)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return buf
	}

	_cipher.NewCBCDecrypter(cipher, iv).CryptBlocks(buf, b)

	return buf
}

func decryptRc4(b, key []byte) []byte {
	buf := make([]byte, len(b))

	cipher, err := rc4.NewCipher(key)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return buf
	}

	cipher.XORKeyStream(buf, b)

	return buf
}

func deriveMd5(b, key []byte, n int) []byte {
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

func deriveKey(rid uint32) ([]byte, []byte) {
	b := make([]byte, 4)

	binary.LittleEndian.PutUint32(b, rid)

	key1 := transformKey([]byte{
		b[0], b[1], b[2], b[3],
		b[0], b[1], b[2],
	})

	key2 := transformKey([]byte{
		b[3], b[0], b[1], b[2],
		b[3], b[0], b[1],
	})

	return key1, key2
}

func transformKey(b []byte) []byte {
	var key []byte

	key = append(key, b[0]>>0x01)
	key = append(key, ((b[0]&0x01)<<6)|b[1]>>2)
	key = append(key, ((b[1]&0x03)<<5)|b[2]>>3)
	key = append(key, ((b[2]&0x07)<<4)|b[3]>>4)
	key = append(key, ((b[3]&0x0f)<<3)|b[4]>>5)
	key = append(key, ((b[4]&0x1f)<<2)|b[5]>>6)
	key = append(key, ((b[5]&0x3f)<<1)|b[6]>>7)
	key = append(key, b[6]&0x7f)

	for i := 0; i < 8; i++ {
		key[i] = (key[i] << 1) & 0xfe
	}

	return key
}

func controlSet(reg *regparser.Registry) string {
	set := "ControlSet001"

	if key := reg.OpenKey("\\Select"); key != nil {
		for _, value := range key.Values() {
			if value.ValueName() == "Current" {
				set = fmt.Sprintf("ControlSet%03d", value.ValueData().Uint64)
			}
		}
	}

	return set
}

func main() {
	if len(os.Args) < 3 || os.Args[1] == "--help" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: hashdump system ntds")
		os.Exit(2)
	}

	hive, err := os.Open(os.Args[1])

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ntds, err := os.Open(os.Args[2])

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	bootkey, err := getBootkey(hive)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	buf, err := io.ReadAll(ntds)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	records, err := getRecords(buf, bootkey)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, record := range records {
		_, _ = fmt.Println(record.String())
	}

	_ = ntds.Close()
	_ = hive.Close()
}
