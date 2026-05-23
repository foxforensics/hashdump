package extract

// col names
const (
	dnt         = "DNT_col"
	linkDnt     = "link_DNT"
	backlinkDnt = "backlink_DNT"
)

// row attributes
const (
	cn                         = "ATTm3"
	name                       = "ATTm589825"
	givenName                  = "ATTm42"
	description                = "ATTm13"
	sAMAccountType             = "ATTj590126"
	sAMAccountName             = "ATTm590045"
	displayName                = "ATTm131085"
	lDAPDisplayName            = "ATTm131532"
	userPrincipalName          = "ATTm590480"
	primaryGroupID             = "ATTj589922"
	groupType                  = "ATTj590574"
	objectGUID                 = "ATTk589826"
	objectSid                  = "ATTr589970"
	adminCount                 = "ATTj589974"
	dBCSPwd                    = "ATTk589879"
	lmPwdHistory               = "ATTk589984"
	unicodePwd                 = "ATTk589914"
	ntPwdHistory               = "ATTk589918"
	badPwdCount                = "ATTj589836"
	badPasswordTime            = "ATTq589873"
	logonCount                 = "ATTj589993"
	lastLogon                  = "ATTq589876"
	lastLogonTimestamp         = "ATTq591520"
	pwdLastSet                 = "ATTq589920"
	accountExpires             = "ATTq589983"
	whenCreated                = "ATTl131074"
	whenChanged                = "ATTl131075"
	userAccountControl         = "ATTj589832"
	supplementalCredentials    = "ATTk589949"
	dNSTombstoned              = "ATTi591238"
	isRecycled                 = "ATTi591882"
	isDeleted                  = "ATTi131120"
	dNSHostName                = "ATTm590443"
	operatingSystem            = "ATTm590187"
	operatingSystemServicePack = "ATTm590189"
	operatingSystemVersion     = "ATTm590188"
	operatingSystemHotfix      = "ATTm590239"
	pekList                    = "ATTk590689"
)

// group types
const (
	builtInGroup     = 0x00000001
	globalGroup      = 0x00000002
	domainLocalGroup = 0x00000004
	universalGroup   = 0x00000008
	appBasicGroup    = 0x00000010
	appQueryGroup    = 0x00000020
	securityGroup    = 0x80000000
)

// property names
const (
	cleartext = "Primary:CLEARTEXT"
)

// Never special timestamp (UTC).
const Never = "2185-07-21T23:34:33Z"

// SAMAccountTypes to be extracted.
var SAMAccountTypes = map[int64]string{
	0x30000000: "SAM_NORMAL_USER_ACCOUNT",
	0x30000001: "SAM_MACHINE_ACCOUNT",
	0x30000002: "SAM_TRUST_ACCOUNT",
}

// SAMGroupTypes to be extracted.
var SAMGroupTypes = map[int64]string{
	0x10000000: "SAM_GROUP_OBJECT",
	0x10000001: "SAM_NON_SECURITY_GROUP_OBJECT",
	0x40000000: "SAM_APP_BASIC_GROUP",
	0x40000001: "SAM_APP_QUERY_GROUP",
}

// PrimaryGroups of an object.
var PrimaryGroups = map[int32]string{
	512: "Domain Admins",
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
	521: "Read-only Domain Controllers",
}

// DefaultLM for an empty password.
var DefaultLM = []byte{
	0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
	0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
}

// DefaultNT for an empty password.
var DefaultNT = []byte{
	0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31,
	0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0,
}
