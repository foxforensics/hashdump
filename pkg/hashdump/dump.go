// Package hashdump provides methods to dump user password hashes.
package hashdump

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.dev/go-ese/parser"
)

// Row attributes
const (
	account = "ATTj590126"
	pekData = "ATTk590689"
	userRow = "ATTm590045"
	userSid = "ATTr589970"
	userUac = "ATTj589832"
	lmHash  = "ATTk589879"
	ntHash  = "ATTk589914"
)

// Dump all user records from the given database.
func Dump(ad, bootkey []byte) ([]Record, error) {
	var records []Record

	ctx, err := parser.NewESEContext(bytes.NewReader(ad), int64(len(ad)))

	if err != nil {
		return nil, err
	}

	clg, err := parser.ReadCatalog(ctx)

	if err != nil {
		return nil, err
	}

	keys, err := getPEKs(clg, pekData, bootkey)

	if err != nil {
		return nil, err
	}

	err = clg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(userRow); ok && v != nil {
			userType, ok := row.GetInt64(account)

			if !ok {
				return errors.New("could not get account type")
			}

			if !slices.Contains([]int64{
				0x30000000, // SAM_NORMAL_USER_ACCOUNT
				0x30000001, // SAM_MACHINE_ACCOUNT
				0x30000002, // SAM_TRUST_ACCOUNT
			}, userType) {
				return nil
			}

			record, err := newRecord(row, v.(string), keys)

			if err != nil {
				return err
			}

			records = append(records, *record)

			return nil
		}
		return nil
	})

	return records, err
}

func getPEKs(clg *parser.Catalog, id string, k []byte) ([][]byte, error) {
	var keys [][]byte

	err := clg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(id); ok && v != nil {
			b, _ := hex.DecodeString(v.(string))

			key, err := decryptPEK(b, k)

			if err != nil {
				return err
			}

			keys = append(keys, key)
		}
		return nil
	})

	return keys, err
}

func decryptPEK(b, k []byte) ([]byte, error) {
	var key []byte
	var err error

	switch b[0] {
	case 0x03: // 2016
		b = b[8:] // skip header
		b, err = decryptAES(b[16:], k, b[:16])

		if err != nil {
			return nil, err
		}

		key = b[36:52]

	case 0x02: // 2000
		b = b[8:] // skip header
		b, err = decryptRC4(b[16:], deriveMD5(b[:16], k, 1000))

		if err != nil {
			return nil, err
		}

		key = b[36:]

	default:
		// plain text?
	}

	if len(key) != 16 {
		return nil, errors.New("invalid PEK length")
	}

	return key, nil
}
