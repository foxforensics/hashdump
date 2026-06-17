package extract

import (
	"context"
	"encoding/hex"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.eu/go-ese/parser"
)

// PEK the Password Encryption Key.
type PEK []byte

func newKeys(ctx context.Context, clg *parser.Catalog, bk []byte) ([]PEK, error) {
	var keys []PEK

	err := clg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(pekList); ok && v != nil {
			b, err := hex.DecodeString(v.(string))

			if err != nil {
				return err
			}

			key, err := decryptPEK(b, bk)

			if err != nil {
				return err
			}

			keys = append(keys, key)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	return keys, err
}
