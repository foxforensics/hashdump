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

// Row attributes
const (
	pekData      = "ATTk590689"
	accType      = "ATTj590126"
	userRow      = "ATTm590045"
	userName     = "ATTm3"
	userDesc     = "ATTm13"
	userSid      = "ATTr589970"
	userUac      = "ATTj589832"
	lmHash       = "ATTk589879"
	ntHash       = "ATTk589914"
	badCount     = "ATTj589993"
	lastLogon    = "ATTq589876"
	lastChange   = "ATTq589920"
	willExpire   = "ATTq589983"
	ntPwdHistory = "ATTk589918"
	lmPwdHistory = "ATTk589984"
)

// PEK is the password encryption key.
type PEK []byte

// Extract all user accounts from the given database.
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

	peks, err := getPEKs(ctg, pekData, bootkey)

	if err != nil {
		return nil, nil, err
	}

	err = ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(userRow); ok && v != nil {
			typ, ok := row.GetInt64(accType)

			if !ok {
				return errors.New("could not get account type")
			}

			if !slices.Contains([]int64{
				0x30000000, // SAM_NORMAL_USER_ACCOUNT
				0x30000001, // SAM_MACHINE_ACCOUNT
				0x30000002, // SAM_TRUST_ACCOUNT
			}, typ) {
				return nil
			}

			account, err := getAccount(row, v.(string), peks)

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

func getPEKs(clg *parser.Catalog, id string, k []byte) ([]PEK, error) {
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
