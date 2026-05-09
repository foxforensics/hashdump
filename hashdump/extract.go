// Package hashdump provides methods to dump user password hashes.
//
// Sources:
// https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
// https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py
// https://github.com/C-Sto/gosecretsdump/blob/master/pkg/ditreader/crypto.go
// https://github.com/Dionach/NtdsAudit/blob/master/src/NtdsAudit/NTCrypto.cs
// https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
package hashdump

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.dev/go-ese/parser"
)

// User row attributes
const (
	name               = "ATTm3"
	description        = "ATTm13"
	sAMAccountType     = "ATTj590126"
	sAMAccountName     = "ATTm590045"
	userPrincipalName  = "ATTm590480"
	objectSid          = "ATTr589970"
	dBCSPwd            = "ATTk589879"
	lmPwdHistory       = "ATTk589984"
	unicodePwd         = "ATTk589914"
	ntPwdHistory       = "ATTk589918"
	logonCount         = "ATTj589993"
	lastLogon          = "ATTq589876"
	pwdLastSet         = "ATTq589920"
	accountExpires     = "ATTq589983"
	userAccountControl = "ATTj589832"
	pekList            = "ATTk590689"
)

// User account types
var samAccountTypes = []int64{
	0x30000000, // SAM_NORMAL_USER_ACCOUNT
	0x30000001, // SAM_MACHINE_ACCOUNT
	0x30000002, // SAM_TRUST_ACCOUNT
}

// PEK is the password encryption key.
type PEK []byte

// Extract all accounts from the given database.
func Extract(ad, bootkey []byte) ([]Account, []PEK, error) {
	var accounts []Account

	ctx, err := parser.NewESEContext(bytes.NewReader(ad), int64(len(ad)))

	if err != nil {
		return nil, nil, err
	}

	ctg, err := parser.ReadCatalog(ctx)

	if err != nil {
		return nil, nil, err
	}

	peks, err := extractKeys(ctg, pekList, bootkey)

	if err != nil {
		return nil, nil, err
	}

	err = ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(sAMAccountName); ok && v != nil {
			sat, ok := row.GetInt64(sAMAccountType)

			if !ok {
				return errors.New("could not get account type")
			}

			if !slices.Contains(samAccountTypes, sat) {
				return nil
			}

			account, err := getAccount(row, peks)

			if err != nil {
				return err
			}

			accounts = append(accounts, *account)

			return nil
		}
		return nil
	})

	return accounts, peks, err
}

func extractKeys(clg *parser.Catalog, id string, k []byte) ([]PEK, error) {
	var peks []PEK

	err := clg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(id); ok && v != nil {
			b, _ := hex.DecodeString(v.(string))

			pek, err := decryptPEK(b, k)

			if err != nil {
				return err
			}

			peks = append(peks, pek)
		}
		return nil
	})

	return peks, err
}
