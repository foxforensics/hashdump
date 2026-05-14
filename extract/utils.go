package extract

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
)

func getString(row *ordereddict.Dict, id string) string {
	if v := getRow(row, id); v != nil {
		return v.(string)
	}

	return ""
}

func getBytes(row *ordereddict.Dict, id string) []byte {
	if v := getRow(row, id); v != nil {
		b, _ := hex.DecodeString(v.(string))
		return b
	}

	return nil
}

func getTime(row *ordereddict.Dict, id string) string {
	if v := getRow(row, id); v != nil {
		if v.(uint64) == 0 {
			return "Never" // value is not set
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
