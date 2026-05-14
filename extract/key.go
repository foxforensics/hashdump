package extract

import (
	"encoding/hex"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.dev/go-ese/parser"
)

// PEK the Password Encryption Key.
type PEK []byte

func newKeys(clg *parser.Catalog, bk []byte) ([]PEK, error) {
	var keys []PEK

	err := clg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(pekList); ok && v != nil {
			b, _ := hex.DecodeString(v.(string))

			key, err := decryptPEK(b, bk)

			if err != nil {
				return err
			}

			keys = append(keys, key)
		}
		return nil
	})

	return keys, err
}
