package extract

import (
	"encoding/json"

	"github.com/Velocidex/ordereddict"
)

type Group struct {
	CN            string `json:"cn,omitempty"`
	Name          string `json:"name,omitempty"`
	GroupType     string `json:"group_type,omitempty"`
	WhenCreated   string `json:"when_created,omitempty"`
	WhenChanged   string `json:"when_changed,omitempty"`
	DNSTombstoned int32  `json:"dns_tombstoned,omitempty"`
	IsDeleted     int32  `json:"is_deleted,omitempty"`
}

// String returns the computer formated as string.
func (grp *Group) String() string {
	return grp.CN
}

// JSON returns the computer details as JSON.
func (grp *Group) JSON() string {
	b, _ := json.MarshalIndent(grp, "", "  ")
	return string(b)
}

func newGroup(row *ordereddict.Dict) (*Group, error) {
	return &Group{
		CN:            getString(row, cn),
		Name:          getString(row, name),
		GroupType:     getGroupType(getInt(row, groupType)),
		WhenCreated:   getTime(row, whenCreated),
		WhenChanged:   getTime(row, whenChanged),
		DNSTombstoned: int32(getInt(row, dNSTombstoned)),
		IsDeleted:     int32(getInt(row, isDeleted)),
	}, nil
}

func getGroupType(v int) string {
	switch {
	case v&builtInGroup != 0:
		return "Build-in Group"
	case v&globalGroup != 0:
		return "Global Group"
	case v&domainLocalGroup != 0:
		return "Domain Local Group"
	case v&universalGroup != 0:
		return "Universal Group"
	case v&appBasicGroup != 0:
		return "App Basic Group"
	case v&appQueryGroup != 0:
		return "App Query Group"
	case v&securityGroup != 0:
		return "Security Group"
	}
	return ""
}
