package extract

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Velocidex/ordereddict"
)

// Account of a user with decrypted password hashes.
type Account struct {
	CN                 string   `json:"cn,omitempty"`
	Name               string   `json:"name,omitempty"`
	GivenName          string   `json:"given_name,omitempty"`
	DisplayName        string   `json:"display_name,omitempty"`
	LDAPDisplayName    string   `json:"ldap_display_name,omitempty"`
	UserPrincipalName  string   `json:"user_principal_name,omitempty"`
	SAMAccountName     string   `json:"sam_account_name,omitempty"`
	SAMAccountType     string   `json:"sam_account_type,omitempty"`
	PrimaryGroup       string   `json:"primary_group,omitempty"`
	Description        string   `json:"description,omitempty"`
	GUID               string   `json:"guid,omitempty"`
	SID                string   `json:"sid,omitempty"`
	RID                int32    `json:"rid,omitempty"`
	LMHash             string   `json:"lm_hash,omitempty"`
	LMHashHistory      []string `json:"lm_hash_history,omitempty"`
	NTHash             string   `json:"nt_hash,omitempty"`
	NTHashHistory      []string `json:"nt_hash_history,omitempty"`
	Cleartext          string   `json:"cleartext,omitempty"`
	BadPasswordCount   int32    `json:"bad_password_count,omitempty"`
	BadPasswordTime    string   `json:"bad_password_time,omitempty"`
	LogonCount         int32    `json:"logon_count,omitempty"`
	LastLogon          string   `json:"last_logon,omitempty"`
	LastLogonTimestamp string   `json:"last_logon_timestamp,omitempty"`
	PasswordLastSet    string   `json:"password_last_set,omitempty"`
	AccountExpires     string   `json:"account_expires,omitempty"`
	WhenCreated        string   `json:"when_created,omitempty"`
	WhenChanged        string   `json:"when_changed,omitempty"`
	DNSTombstoned      int32    `json:"dns_tombstoned,omitempty"`
	IsDeleted          int32    `json:"is_deleted,omitempty"`
	UserAccountControl *UAC     `json:"user_account_control,omitempty"`
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
	// It's an MNS logon account.
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

// String returns the account formated as string.
func (acc *Account) String() string {
	return fmt.Sprintf("%s:%d:%s:%s:::",
		acc.SAMAccountName,
		acc.RID,
		acc.LMHash,
		acc.NTHash,
	)
}

// JSON returns the account details as JSON.
func (acc *Account) JSON() string {
	b, _ := json.MarshalIndent(acc, "", "  ")
	return string(b)
}

func newAccount(row *ordereddict.Dict, keys []PEK) (*Account, error) {
	guid := getBytes(row, objectGUID)
	sid := getBytes(row, objectSid)
	rid := extractRID(sid)
	k1, k2 := deriveKey(rid)

	lmPwd, err := decryptHash(getBytes(row, dBCSPwd), k1, k2, DefaultLM, keys)

	if err != nil {
		return nil, err
	}

	lmPwdH, err := decryptHistory(getBytes(row, lmPwdHistory), k1, k2, keys)

	if err != nil {
		return nil, err
	}

	ntPwd, err := decryptHash(getBytes(row, unicodePwd), k1, k2, DefaultNT, keys)

	if err != nil {
		return nil, err
	}

	ntPwdH, err := decryptHistory(getBytes(row, ntPwdHistory), k1, k2, keys)

	if err != nil {
		return nil, err
	}

	ctPwd, err := decryptCleartext(getBytes(row, supplementalCredentials), keys)

	if err != nil {
		return nil, err
	}

	uac, _ := row.GetInt64(userAccountControl)

	return &Account{
		CN:                 getString(row, cn),
		Name:               getString(row, name),
		GivenName:          getString(row, givenName),
		DisplayName:        getString(row, displayName),
		LDAPDisplayName:    getString(row, lDAPDisplayName),
		UserPrincipalName:  getString(row, userPrincipalName),
		SAMAccountName:     getString(row, sAMAccountName),
		SAMAccountType:     SAMAccountTypes[int64(getInt(row, sAMAccountType))],
		PrimaryGroup:       PrimaryGroups[int32(getInt(row, primaryGroupID))],
		Description:        getString(row, description),
		GUID:               extractGUID(guid),
		SID:                extractSID(sid),
		RID:                int32(rid),
		LMHash:             lmPwd,
		LMHashHistory:      lmPwdH,
		NTHash:             ntPwd,
		NTHashHistory:      ntPwdH,
		Cleartext:          ctPwd,
		BadPasswordCount:   int32(getInt(row, badPwdCount)),
		BadPasswordTime:    getTime(row, badPasswordTime),
		LogonCount:         int32(getInt(row, logonCount)),
		LastLogon:          getTime(row, lastLogon),
		LastLogonTimestamp: getTime(row, lastLogonTimestamp),
		PasswordLastSet:    getTime(row, pwdLastSet),
		AccountExpires:     getTime(row, accountExpires),
		WhenCreated:        getTime(row, whenCreated),
		WhenChanged:        getTime(row, whenChanged),
		DNSTombstoned:      int32(getInt(row, dNSTombstoned)),
		IsDeleted:          int32(getInt(row, isDeleted)),
		UserAccountControl: extractUAC(uac),
	}, nil
}

func extractGUID(guid []byte) string {
	a := binary.LittleEndian.Uint32(guid[0:4])
	b := binary.LittleEndian.Uint16(guid[4:6])
	c := binary.LittleEndian.Uint16(guid[6:8])
	d, e := guid[8:10], guid[10:16]

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", a, b, c, d, e)
}

func extractSID(sid []byte) string {
	var sb strings.Builder

	rev, n, auth, b := sid[0], sid[1], sid[7], sid[8:]

	sb.WriteString(fmt.Sprintf("S-%d-%d", rev, auth))

	for i := 0; i < int(n-1); i++ {
		sb.WriteString(fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[i*4:i*4+4])))
	}

	sb.WriteString(fmt.Sprintf("-%d", binary.BigEndian.Uint32(b[(n-1)*4:(n-1)*4+4])))

	return sb.String()
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
