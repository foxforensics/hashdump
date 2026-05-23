package extract

import (
	"encoding/json"

	"github.com/Velocidex/ordereddict"
)

type Computer struct {
	CN                         string   `json:"cn,omitempty"`
	Name                       string   `json:"name,omitempty"`
	DNSHostName                string   `json:"dns_host_name,omitempty"`
	PrimaryGroup               string   `json:"primary_group,omitempty"`
	OperatingSystem            string   `json:"operating_system,omitempty"`
	OperatingSystemServicePack string   `json:"operating_system_service_pack,omitempty"`
	OperatingSystemVersion     string   `json:"operating_system_version,omitempty"`
	OperatingSystemHotfix      string   `json:"operating_system_hotfix,omitempty"`
	LastLogon                  string   `json:"last_logon,omitempty"`
	WhenCreated                string   `json:"when_created,omitempty"`
	WhenChanged                string   `json:"when_changed,omitempty"`
	DNSTombstoned              int32    `json:"dns_tombstoned,omitempty"`
	IsRecycled                 int32    `json:"is_recycled,omitempty"`
	IsDeleted                  int32    `json:"is_deleted,omitempty"`
	MemberOf                   []string `json:"member_of,omitempty"`
}

// String returns the computer formated as string.
func (com *Computer) String() string {
	return com.DNSHostName
}

// JSON returns the computer details as JSON.
func (com *Computer) JSON() string {
	b, _ := json.MarshalIndent(com, "", "  ")
	return string(b)
}

func computerFromRow(row *ordereddict.Dict) (*Computer, error) {
	return &Computer{
		CN:                         getString(row, cn),
		Name:                       getString(row, name),
		DNSHostName:                getString(row, dNSHostName),
		PrimaryGroup:               PrimaryGroups[int32(getInt(row, primaryGroupID))],
		OperatingSystem:            getString(row, operatingSystem),
		OperatingSystemServicePack: getString(row, operatingSystemServicePack),
		OperatingSystemVersion:     getString(row, operatingSystemVersion),
		OperatingSystemHotfix:      getString(row, operatingSystemHotfix),
		LastLogon:                  getTime(row, lastLogon),
		WhenCreated:                getTime(row, whenCreated),
		WhenChanged:                getTime(row, whenChanged),
		DNSTombstoned:              int32(getInt(row, dNSTombstoned)),
		IsRecycled:                 int32(getInt(row, isRecycled)),
		IsDeleted:                  int32(getInt(row, isDeleted)),
		MemberOf:                   getMemberOf(row, dnt),
	}, nil
}
