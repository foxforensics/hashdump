package hashdump

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Velocidex/ordereddict"
)

// EmptyLM default hash.
var EmptyLM = []byte{
	0xAA, 0xD3, 0xB4, 0x35,
	0xB5, 0x14, 0x04, 0xEE,
	0xAA, 0xD3, 0xB4, 0x35,
	0xB5, 0x14, 0x04, 0xEE,
}

// EmptyNT default hash.
var EmptyNT = []byte{
	0x31, 0xD6, 0xCF, 0xE0,
	0xD1, 0x6A, 0xE9, 0x31,
	0xB7, 0x3C, 0x59, 0xD7,
	0xE0, 0xC0, 0x89, 0xC0,
}

// Record with decrypted user data.
type Record struct {
	// Username systemwide.
	Username string `json:"username,omitempty"`
	// RID of the user.
	RID uint32 `json:"rid,omitempty"`
	// LM hash value of the users password (might have an empty value).
	LM string `json:"lm,omitempty"`
	// NT hash value of the users password (might have an empty value).
	NT string `json:"nt,omitempty"`
	// Flags of the user.
	Flags *Flags `json:"flags,omitempty"`
}

// Flags set for the user account.
type Flags struct {
	Script                       bool `json:"script,omitempty"`
	AccountDisable               bool `json:"account_disable,omitempty"`
	HomeDirRequired              bool `json:"home_dir_required,omitempty"`
	Lockout                      bool `json:"lockout,omitempty"`
	PasswordNotRequired          bool `json:"password_not_required,omitempty"`
	EncryptedTextPasswordAllowed bool `json:"encrypted_text_password_allowed,omitempty"`
	TemporaryDupAccount          bool `json:"temporary_dup_account,omitempty"`
	NormalAccount                bool `json:"normal_account,omitempty"`
	InterDomainTrustAccount      bool `json:"inter_domain_trust_account,omitempty"`
	WorkstationTrustAccount      bool `json:"workstation_trust_account,omitempty"`
	ServerTrustAccount           bool `json:"server_trust_account,omitempty"`
	DontExpirePassword           bool `json:"dont_expire_password,omitempty"`
	MNSLogonAccount              bool `json:"mns_logon_account,omitempty"`
	SmartCardRequired            bool `json:"smart_card_required,omitempty"`
	TrustedForDelegation         bool `json:"trusted_for_delegation,omitempty"`
	NotDelegated                 bool `json:"not_delegated,omitempty"`
	UseDESOnly                   bool `json:"use_des_only,omitempty"`
	DontPreAuth                  bool `json:"dont_pre_auth,omitempty"`
	PasswordExpired              bool `json:"password_expired,omitempty"`
	TrustedToAuthForDelegation   bool `json:"trusted_to_auth_for_delegation,omitempty"`
	PartialSecrets               bool `json:"partial_secrets,omitempty"`
}

// String representation of user account in canonical form.
func (r *Record) String() string {
	return fmt.Sprintf("%s:%d:%s:%s:::",
		r.Username,
		r.RID,
		r.LM,
		r.NT,
	)
}

func newRecord(row *ordereddict.Dict, usr string, keys [][]byte) (*Record, error) {
	sid := getRowData(row, userSid)
	rid := extractRid(sid)
	k1, k2 := deriveKey(rid)
	uac, ok := row.GetInt64(userUac)

	if !ok {
		return nil, errors.New("could not get account flags")
	}

	lm, err := decryptHash(getRowData(row, lmHash), EmptyLM, k1, k2, keys)

	if err != nil {
		return nil, err
	}

	nt, err := decryptHash(getRowData(row, ntHash), EmptyNT, k1, k2, keys)

	if err != nil {
		return nil, err
	}

	return &Record{
		Username: usr,
		RID:      rid,
		LM:       hex.EncodeToString(lm),
		NT:       hex.EncodeToString(nt),
		Flags:    extractFlags(uac),
	}, nil
}

func getRowData(row *ordereddict.Dict, id string) []byte {
	if v := getRow(row, id); v != nil {
		b, _ := hex.DecodeString(v.(string))
		return b
	}

	return nil
}

func getRow(row *ordereddict.Dict, id string) any {
	if v, ok := row.Get(id); ok && v != nil {
		return v
	}

	return nil
}

func decryptHash(b, d, k1, k2 []byte, pek [][]byte) ([]byte, error) {
	var err error

	if len(b) == 0 {
		return d, nil // empty default hash
	}

	switch b[0] {
	case 0x13: // new decryption method
		b = b[8:] // skip header
		b, err = decryptAES(b[20:36], pek[b[4]], b[:16])

	default: // old decryption method
		b = b[8:] // skip header
		b, err = decryptRC4(b[16:], deriveMD5(b[:16], pek[0], 1))
	}

	if err != nil {
		return nil, err
	}

	return decryptDES(b, k1, k2)
}

func extractFlags(v int64) *Flags {
	return &Flags{
		Script:                       v|1 == v,
		AccountDisable:               v|2 == v,
		HomeDirRequired:              v|8 == v,
		Lockout:                      v|6 == v,
		PasswordNotRequired:          v|32 == v,
		EncryptedTextPasswordAllowed: v|128 == v,
		TemporaryDupAccount:          v|256 == v,
		NormalAccount:                v|512 == v,
		InterDomainTrustAccount:      v|2048 == v,
		WorkstationTrustAccount:      v|4096 == v,
		ServerTrustAccount:           v|8192 == v,
		DontExpirePassword:           v|65536 == v,
		MNSLogonAccount:              v|131072 == v,
		SmartCardRequired:            v|262144 == v,
		TrustedForDelegation:         v|524288 == v,
		NotDelegated:                 v|1048576 == v,
		UseDESOnly:                   v|2097152 == v,
		DontPreAuth:                  v|4194304 == v,
		PasswordExpired:              v|8388608 == v,
		TrustedToAuthForDelegation:   v|16777216 == v,
		PartialSecrets:               v|67108864 == v,
	}
}

func extractRid(sid []byte) uint32 {
	n, b := sid[1], sid[8:]

	return binary.BigEndian.Uint32(b[(n-1)*4 : (n-1)*4+4])
}

func deriveKey(rid uint32) ([]byte, []byte) {
	b := make([]byte, 4)

	binary.LittleEndian.PutUint32(b, rid)

	k1 := transformKey([]byte{
		b[0], b[1], b[2], b[3],
		b[0], b[1], b[2],
	})

	k2 := transformKey([]byte{
		b[3], b[0], b[1], b[2],
		b[3], b[0], b[1],
	})

	return k1, k2
}

func transformKey(b []byte) []byte {
	var key []byte

	key = append(key, b[0]>>0x01)
	key = append(key, ((b[0]&0x01)<<6)|b[1]>>2)
	key = append(key, ((b[1]&0x03)<<5)|b[2]>>3)
	key = append(key, ((b[2]&0x07)<<4)|b[3]>>4)
	key = append(key, ((b[3]&0x0f)<<3)|b[4]>>5)
	key = append(key, ((b[4]&0x1f)<<2)|b[5]>>6)
	key = append(key, ((b[5]&0x3f)<<1)|b[6]>>7)
	key = append(key, b[6]&0x7f)

	for i := 0; i < 8; i++ {
		key[i] = (key[i] << 1) & 0xfe
	}

	return key
}
