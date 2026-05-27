package extract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.dev/go-ese/parser"
)

// internal caches
var (
	objects  = make(map[int64]string)
	members  = make(map[int64][]int64)
	memberOf = make(map[int64][]int64)
)

// internal name hierarchy
var objectNames = []string{
	dNSHostName,
	sAMAccountName,
	lDAPDisplayName,
	displayName,
	name,
	cn,
}

func fillObjects(ctg *parser.Catalog) error {
	return ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		var v string

		for _, id := range objectNames {
			if v = getString(row, id); len(v) > 0 {
				break
			}
		}

		if len(v) > 0 {
			if k, ok := row.GetInt64(dnt); ok && k > 0 {
				objects[k] = v
			}
		}

		return nil
	})
}

func fillMembers(ctg *parser.Catalog) error {
	return ctg.DumpTable("link_table", func(row *ordereddict.Dict) error {
		var grp, obj int64

		if grp, _ = row.GetInt64(linkDnt); grp > 0 {
			if _, ok := members[grp]; !ok {
				members[grp] = make([]int64, 0)
			}
		}

		if obj, _ = row.GetInt64(backlinkDnt); obj > 0 {
			if _, ok := memberOf[obj]; !ok {
				memberOf[obj] = make([]int64, 0)
			}
		}

		if grp > 0 && obj > 0 {
			members[grp] = append(members[grp], obj)
			memberOf[obj] = append(memberOf[obj], grp)
		}

		return nil
	})
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

func getCatalog(data []byte) (*parser.Catalog, error) {
	ctx, err := parser.NewESEContext(bytes.NewReader(data), int64(len(data)))

	if err != nil {
		return nil, err
	}

	return parser.ReadCatalog(ctx)
}

func getMemberOf(row *ordereddict.Dict, id string) (v []string) {
	if obj, ok := row.GetInt64(id); ok {
		if lst, ok := memberOf[obj]; ok {
			for _, i := range lst {
				if s, ok := objects[i]; ok {
					v = append(v, s)
				}
			}
			return
		}
	}
	return
}

func getMembers(row *ordereddict.Dict, id string) (v []string) {
	if obj, ok := row.GetInt64(id); ok {
		if lst, ok := members[obj]; ok {
			for _, i := range lst {
				if s, ok := objects[i]; ok {
					v = append(v, s)
				}
			}
			return
		}
	}
	return
}

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
