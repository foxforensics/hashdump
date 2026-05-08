package hashdump

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Velocidex/ordereddict"
)

// DefaultLM for an empty hash.
var DefaultLM = []byte{
	0xAA, 0xD3, 0xB4, 0x35,
	0xB5, 0x14, 0x04, 0xEE,
	0xAA, 0xD3, 0xB4, 0x35,
	0xB5, 0x14, 0x04, 0xEE,
}

// DefaultNT for an empty hash.
var DefaultNT = []byte{
	0x31, 0xD6, 0xCF, 0xE0,
	0xD1, 0x6A, 0xE9, 0x31,
	0xB7, 0x3C, 0x59, 0xD7,
	0xE0, 0xC0, 0x89, 0xC0,
}

// ExpiresNever timestamp.
var ExpiresNever = time.Unix(6802270473, 709551516).UTC()

// Account of a user with decrypted password hashes.
type Account struct {
	// Username of the account.
	Username string `json:"username,omitempty"`
	// Description of the account.
	Description string `json:"description,omitempty"`
	// RID of the account.
	RID uint32 `json:"rid,omitempty"`
	// LmHash value of the accounts actual password (can be a default value).
	LmHash string `json:"lm_hash,omitempty"`
	// NtHash value of the accounts actual password (can be a default value).
	NtHash string `json:"nt_hash,omitempty"`
	// Logons of the account.
	Logons int64 `json:"logons,omitempty"`
	// LastLogon time of the account.
	LastLogon time.Time `json:"last_logon,omitempty"`
	// LastChange of accounts password.
	LastChange time.Time `json:"last_change,omitempty"`
	// Expires at date and time.
	Expires time.Time `json:"expires,omitempty"`
	// UAC flags of the account.
	UAC *UAC `json:"uac,omitempty"`
}

// UAC flags of a user account.
type UAC struct {
	// The logon script will be run.
	Script bool `json:"script,omitempty"`
	// The user account is disabled.
	AccountDisable bool `json:"account_disable,omitempty"`
	// The home folder is required.
	HomeDirRequired bool `json:"home_dir_required,omitempty"`
	// The account is currently locked out.
	Lockout bool `json:"lockout,omitempty"`
	// No password is required.
	PasswordNotRequired bool `json:"password_not_required,omitempty"`
	// The user can't change the password. It's a permission on the user's object. For information about how to programmatically set this permission, see Modifying User Cannot Change Password (LDAP Provider).
	PasswordCantChange bool `json:"password_cant_change,omitempty"`
	// The user can send an encrypted password.
	EncryptedTextPasswordAllowed bool `json:"encrypted_text_password_allowed,omitempty"`
	// It's an account for users whose primary account is in another domain. This account provides user access to this domain, but not to any domain that trusts this domain. It's sometimes referred to as a local user account.
	TemporaryDuplicateAccount bool `json:"temporary_duplicate_account,omitempty"`
	// It's a default account type that represents a typical user.
	NormalAccount bool `json:"normal_account,omitempty"`
	// It's a permit to trust an account for a system domain that trusts other domains.
	InterDomainTrustAccount bool `json:"inter_domain_trust_account,omitempty"`
	// It's a computer account for a computer that is running Microsoft Windows NT 4.0 Workstation, Microsoft Windows NT 4.0 Server, Microsoft Windows 2000 Professional, or Windows 2000 Server and is a member of this domain.
	WorkstationTrustAccount bool `json:"workstation_trust_account,omitempty"`
	// It's a computer account for a domain controller that is a member of this domain.
	ServerTrustAccount bool `json:"server_trust_account,omitempty"`
	// Represents the password, which should never expire on the account.
	DontExpirePassword bool `json:"dont_expire_password,omitempty"`
	//  It's an MNS logon account.
	MNSLogonAccount bool `json:"mns_logon_account,omitempty"`
	// When this flag is set, it forces the user to log on by using a smart card.
	SmartCardRequired bool `json:"smart_card_required,omitempty"`
	// When this flag is set, the service account (the user or computer account) under which a service runs is trusted for Kerberos delegation.
	TrustedForDelegation bool `json:"trusted_for_delegation,omitempty"`
	// When this flag is set, the security context of the user isn't delegated to a service even if the service account is set as trusted for Kerberos delegation. Any such service can impersonate a client requesting the service. To enable a service for Kerberos delegation, you must set this flag on the userAccountControl property of the service account.
	NotDelegated bool `json:"not_delegated,omitempty"`
	// Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
	UseDESKeyOnly bool `json:"use_des_key_only,omitempty"`
	// This account doesn't require Kerberos pre-authentication for logging on.
	DontRequirePreAuth bool `json:"dont_require_pre_auth,omitempty"`
	// The user's password has expired.
	PasswordExpired bool `json:"password_expired,omitempty"`
	// The account is enabled for delegation. It's a security-sensitive setting. Accounts that have this option enabled should be tightly controlled. This setting lets a service that runs under the account assume a client's identity and authenticate as that user to other remote servers on the network.
	TrustedToAuthForDelegation bool `json:"trusted_to_auth_for_delegation,omitempty"`
	// The account is a read-only domain controller (RODC). It's a security-sensitive setting. Removing this setting from an RODC compromises security on that server.
	PartialSecretsAccount bool `json:"partial_secrets_account,omitempty"`
	// The account can only use AES keys.
	UseAESKeys bool `json:"use_aes_keys,omitempty"`
}

// String representation of user account in canonical form (secretsdump).
func (acc *Account) String() string {
	return fmt.Sprintf("%s:%d:%s:%s:::",
		acc.Username,
		acc.RID,
		acc.LmHash,
		acc.NtHash,
	)
}

func getAccount(row *ordereddict.Dict, peks []PEK) (*Account, error) {
	name := getRowString(row, userName)
	desc := getRowString(row, userDesc)
	sid := getRowBytes(row, userSid)
	rid := extractRID(sid)
	k1, k2 := deriveKey(rid)
	logins, _ := row.GetInt64(logons)
	llogin := getRowTime(row, lastLogon)
	lchange := getRowTime(row, lastChange)
	expires := getRowTime(row, accExpires)
	uac, ok := row.GetInt64(userUac)

	println(expires.Unix(), expires.UnixNano())
	println(ExpiresNever.Unix(), ExpiresNever.UnixNano())

	if !ok {
		return nil, errors.New("could not get account flags")
	}

	lmData, err := decryptHash(getRowBytes(row, lmHash), k1, k2, DefaultLM, peks)

	if err != nil {
		return nil, err
	}

	ntData, err := decryptHash(getRowBytes(row, ntHash), k1, k2, DefaultNT, peks)

	if err != nil {
		return nil, err
	}

	return &Account{
		Username:    name,
		Description: desc,
		RID:         rid,
		LmHash:      hex.EncodeToString(lmData),
		NtHash:      hex.EncodeToString(ntData),
		Logons:      logins,
		LastLogon:   llogin,
		LastChange:  lchange,
		Expires:     expires,
		UAC:         extractUAC(uac),
	}, nil
}

func getRowString(row *ordereddict.Dict, id string) string {
	if v := getRow(row, id); v != nil {
		return v.(string)
	}

	return ""
}

func getRowBytes(row *ordereddict.Dict, id string) []byte {
	if v := getRow(row, id); v != nil {
		b, _ := hex.DecodeString(v.(string))
		return b
	}

	return nil
}

func getRowTime(row *ordereddict.Dict, id string) time.Time {
	if v := getRow(row, id); v != nil {
		return time.Unix(0, int64((v.(uint64)-116444736000000000)*100)).UTC()
	}

	return time.Unix(0, 0)
}

func getRow(row *ordereddict.Dict, id string) any {
	if v, ok := row.Get(id); ok && v != nil {
		return v
	}

	return nil
}

func extractRID(sid []byte) uint32 {
	n, b := sid[1], sid[8:]

	return binary.BigEndian.Uint32(b[(n-1)*4 : (n-1)*4+4])
}

func extractUAC(uac int64) *UAC {
	return &UAC{
		Script:                       uac|0x0000001 == uac,
		AccountDisable:               uac|0x0000002 == uac,
		HomeDirRequired:              uac|0x0000008 == uac,
		Lockout:                      uac|0x0000010 == uac,
		PasswordNotRequired:          uac|0x0000020 == uac,
		PasswordCantChange:           uac|0x0000040 == uac,
		EncryptedTextPasswordAllowed: uac|0x0000080 == uac,
		TemporaryDuplicateAccount:    uac|0x0000100 == uac,
		NormalAccount:                uac|0x0000200 == uac,
		InterDomainTrustAccount:      uac|0x0000800 == uac,
		WorkstationTrustAccount:      uac|0x0001000 == uac,
		ServerTrustAccount:           uac|0x0002000 == uac,
		DontExpirePassword:           uac|0x0010000 == uac,
		MNSLogonAccount:              uac|0x0020000 == uac,
		SmartCardRequired:            uac|0x0040000 == uac,
		TrustedForDelegation:         uac|0x0080000 == uac,
		NotDelegated:                 uac|0x0100000 == uac,
		UseDESKeyOnly:                uac|0x0200000 == uac,
		DontRequirePreAuth:           uac|0x0400000 == uac,
		PasswordExpired:              uac|0x0800000 == uac,
		TrustedToAuthForDelegation:   uac|0x1000000 == uac,
		PartialSecretsAccount:        uac|0x4000000 == uac,
		UseAESKeys:                   uac|0x8000000 == uac,
	}
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
