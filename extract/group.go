package extract

import (
	"encoding/json"

	"github.com/Velocidex/ordereddict"
)

type Group struct {
	CN                string `json:"cn,omitempty"`
	Name              string `json:"name,omitempty"`
	DistinguishedName int32  `json:"distinguished_name,omitempty"`
	GroupType         int32  `json:"group_type,omitempty"`
	GroupPriority     string `json:"group_priority,omitempty"`
	GroupAttributes   int32  `json:"group_attributes,omitempty"`
	ObjectCategory    int32  `json:"object_category,omitempty"`
	ObjectClass       int32  `json:"object_class,omitempty"`
	WhenCreated       string `json:"when_created,omitempty"`
	WhenChanged       string `json:"when_changed,omitempty"`
	DNSTombstoned     int32  `json:"dns_tombstoned,omitempty"`
	IsDeleted         int32  `json:"is_deleted,omitempty"`
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
		CN:                getString(row, cn),
		Name:              getString(row, name),
		DistinguishedName: int32(getInt(row, distinguishedName)),
		GroupType:         int32(getInt(row, groupType)),
		GroupPriority:     getString(row, groupPriority),
		GroupAttributes:   int32(getInt(row, groupAttributes)),
		ObjectCategory:    int32(getInt(row, objectCategory)),
		ObjectClass:       int32(getInt(row, objectClass)),
		WhenCreated:       getTime(row, whenCreated),
		WhenChanged:       getTime(row, whenChanged),
		DNSTombstoned:     int32(getInt(row, dNSTombstoned)),
		IsDeleted:         int32(getInt(row, isDeleted)),
	}, nil
}
