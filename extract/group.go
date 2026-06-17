package extract

import (
	"encoding/json"
	"fmt"

	"github.com/Velocidex/ordereddict"
)

type Group struct {
	CN            string   `json:"cn,omitempty"`
	Name          string   `json:"name,omitempty"`
	GroupType     string   `json:"group_type,omitempty"`
	WhenCreated   string   `json:"when_created,omitempty"`
	WhenChanged   string   `json:"when_changed,omitempty"`
	DNSTombstoned int32    `json:"dns_tombstoned,omitempty"`
	IsRecycled    int32    `json:"is_recycled,omitempty"`
	IsDeleted     int32    `json:"is_deleted,omitempty"`
	Members       []string `json:"members,omitempty"`
	MemberOf      []string `json:"member_of,omitempty"`
}

// String returns the group formated as string.
func (grp *Group) String() string {
	return grp.CN
}

// JSON returns the group details as JSON.
func (grp *Group) JSON() string {
	b, err := json.MarshalIndent(grp, "", "  ")

	if err != nil {
		return fmt.Sprintf(`{"error": "%s"}`, err.Error())
	}

	return string(b)
}

func groupFromRow(cache *Cache, row *ordereddict.Dict) (*Group, error) {
	return &Group{
		CN:            getString(row, cn),
		Name:          getString(row, name),
		GroupType:     getGroupType(getInt(row, groupType)),
		WhenCreated:   getTime(row, whenCreated),
		WhenChanged:   getTime(row, whenChanged),
		DNSTombstoned: int32(getInt(row, dNSTombstoned)),
		IsRecycled:    int32(getInt(row, isRecycled)),
		IsDeleted:     int32(getInt(row, isDeleted)),
		Members:       cache.Members(row, dnt),
		MemberOf:      cache.MemberOf(row, dnt),
	}, nil
}

func getGroupType(v int) string {
	switch v {
	case builtInGroup:
		return "Build-in Group"
	case globalGroup:
		return "Global Group"
	case domainLocalGroup:
		return "Domain Local Group"
	case universalGroup:
		return "Universal Group"
	case appBasicGroup:
		return "App Basic Group"
	case appQueryGroup:
		return "App Query Group"
	case securityGroup:
		return "Security Group"
	default:
		return ""
	}
}
