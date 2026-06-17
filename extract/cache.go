package extract

import (
	"context"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.eu/go-ese/parser"
)

var objectNames = []string{
	dNSHostName,
	sAMAccountName,
	lDAPDisplayName,
	displayName,
	name,
	cn,
}

type Cache struct {
	objects  map[int64]string
	members  map[int64][]int64
	memberOf map[int64][]int64
}

func NewCache() *Cache {
	return &Cache{
		objects:  make(map[int64]string),
		members:  make(map[int64][]int64),
		memberOf: make(map[int64][]int64),
	}
}

func (c *Cache) FillObjects(ctx context.Context, ctg *parser.Catalog) error {
	return ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		var v string

		for _, id := range objectNames {
			if v = getString(row, id); len(v) > 0 {
				break
			}
		}

		if len(v) > 0 {
			if k, ok := row.GetInt64(dnt); ok && k > 0 {
				c.objects[k] = v
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})
}

func (c *Cache) FillMembers(ctx context.Context, ctg *parser.Catalog) error {
	return ctg.DumpTable("link_table", func(row *ordereddict.Dict) error {
		var grp, obj int64

		if grp, _ = row.GetInt64(linkDnt); grp > 0 {
			if _, ok := c.members[grp]; !ok {
				c.members[grp] = make([]int64, 0)
			}
		}

		if obj, _ = row.GetInt64(backlinkDnt); obj > 0 {
			if _, ok := c.memberOf[obj]; !ok {
				c.memberOf[obj] = make([]int64, 0)
			}
		}

		if grp > 0 && obj > 0 {
			c.members[grp] = append(c.members[grp], obj)
			c.memberOf[obj] = append(c.memberOf[obj], grp)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})
}

func (c *Cache) MemberOf(row *ordereddict.Dict, id string) (v []string) {
	if obj, ok := row.GetInt64(id); ok {
		if lst, ok := c.memberOf[obj]; ok {
			for _, i := range lst {
				if s, ok := c.objects[i]; ok {
					v = append(v, s)
				}
			}
			return
		}
	}
	return
}

func (c *Cache) Members(row *ordereddict.Dict, id string) (v []string) {
	if obj, ok := row.GetInt64(id); ok {
		if lst, ok := c.members[obj]; ok {
			for _, i := range lst {
				if s, ok := c.objects[i]; ok {
					v = append(v, s)
				}
			}
			return
		}
	}
	return
}
