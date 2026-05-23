package extract

import (
	"bytes"
	"encoding/hex"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.dev/go-ese/parser"
	"golang.org/x/text/encoding/unicode"
)

// internal caches
var (
	objects  = make(map[int64]string)
	members  = make(map[string][]string)
	memberOf = make(map[string][]string)
)

func fillObjects(ctg *parser.Catalog) error {
	return ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v := getString(row, cn); len(v) > 0 {
			if k, ok := row.GetInt64(dnt); ok && k > 0 {
				objects[k] = v
			}
		}
		return nil
	})
}

func fillMembers(ctg *parser.Catalog) error {
	return ctg.DumpTable("link_table", func(row *ordereddict.Dict) error {
		var g, o string

		if i, ok := row.GetInt64(linkDnt); ok && i > 0 {
			if g, ok = objects[i]; ok {
				if _, ok = members[g]; !ok {
					members[g] = make([]string, 0)
				}
			}
		}

		if i, ok := row.GetInt64(backlinkDnt); ok && i > 0 {
			if o, ok = objects[i]; ok && len(o) > 0 {
				if _, ok = memberOf[o]; !ok {
					memberOf[o] = make([]string, 0)
				}
			}
		}

		if len(g) > 0 && len(o) > 0 {
			members[g] = append(members[g], o)
			memberOf[o] = append(memberOf[o], g)
		}

		return nil
	})
}

func getCatalog(data []byte) (*parser.Catalog, error) {
	ctx, err := parser.NewESEContext(bytes.NewReader(data), int64(len(data)))

	if err != nil {
		return nil, err
	}

	return parser.ReadCatalog(ctx)
}

func getMemberOf(row *ordereddict.Dict, id string) []string {
	if i, ok := row.GetInt64(id); ok {
		if k, ok := objects[i]; ok {
			if v, ok := memberOf[k]; ok {
				return v
			}
		}
	}
	return nil
}

func getMembers(row *ordereddict.Dict, id string) []string {
	if i, ok := row.GetInt64(id); ok {
		if k, ok := objects[i]; ok {
			if v, ok := members[k]; ok {
				return v
			}
		}
	}
	return nil
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

func toUtf16(b []byte) string {
	v, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(b)

	if err != nil {
		return ""
	}

	return string(v)
}
