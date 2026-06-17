package extract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.eu/go-ese/parser"
)

func getCatalog(data []byte) (*parser.Catalog, error) {
	ctx, err := parser.NewESEContext(bytes.NewReader(data), int64(len(data)))

	if err != nil {
		return nil, err
	}

	return parser.ReadCatalog(ctx)
}

func getString(row *ordereddict.Dict, id string) string {
	if v := getRow(row, id); v != nil {
		return v.(string)
	}

	return ""
}

func getBytes(row *ordereddict.Dict, id string) []byte {
	if v := getRow(row, id); v != nil {
		b, err := hex.DecodeString(v.(string))

		if err != nil {
			return []byte{} // could not parse
		}

		return b
	}

	return nil
}

func getTime(row *ordereddict.Dict, id string) string {
	if v := getRow(row, id); v != nil {
		switch val := v.(type) {
		case uint64:
			if val == 0 {
				return "Never" // value is not set
			}
		case int64:
			if val == 0 {
				return "Never" // value is not set
			}
		default:
			return "Error"
		}

		if strings.HasPrefix(id, "ATTl") {
			v = v.(uint64) * 10000000 // scale up to 64 bit
		}

		t := time.Unix(0, int64((v.(uint64)-116444736000000000)*100)).UTC()

		if t.Format(time.RFC3339) == Never {
			return "Never" // value is never value
		}

		return t.Format(time.RFC3339Nano)
	}

	return ""
}

func getInt(row *ordereddict.Dict, id string) int {
	if i := getRow(row, id); i != nil {
		switch v := i.(type) {
		case int64:
			return int(v)
		case uint64:
			return int(v)
		case int32:
			return int(v)
		case uint32:
			return int(v)
		case int16:
			return int(v)
		case uint16:
			return int(v)
		case int8:
			return int(v)
		case uint8:
			return int(v)
		case int:
			return v
		}
	}

	return 0
}

func getRow(row *ordereddict.Dict, id string) any {
	if v, ok := row.Get(id); ok && v != nil {
		return v
	}

	return nil
}

// https://github.com/t9t/gomft/blob/v0.0.1/utf16/decode.go
func decodeUtf16(b []byte) string {
	n := len(b) / 2
	v := make([]uint16, n)

	for i := 0; i < n; i++ {
		v[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}

	return string(utf16.Decode(v))
}
