// Package extract provides a method to extract user accounts.
//
// Sources:
//   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
//   - https://troopers.de/downloads/troopers24/TR24_Decrypting_the_Directory_1.0_8EKVXR.pdf
//   - https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py
//   - https://github.com/C-Sto/gosecretsdump/blob/master/pkg/ditreader/crypto.go
//   - https://github.com/Dionach/NtdsAudit/blob/master/src/NtdsAudit/NTCrypto.cs
//   - https://github.com/xmco/ntds_extract/blob/main/Part-2-La-Datatable/Win2012R2_level.txt
//   - https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
package extract

import (
	"bytes"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.dev/go-ese/parser"
)

// Keys extracts all PEKs.
func Keys(data, bootkey []byte) ([]PEK, error) {
	ctg, err := getCatalog(data)

	if err != nil {
		return nil, err
	}

	return newKeys(ctg, bootkey)
}

// Accounts extracts all accounts.
func Accounts(data, bootkey []byte) ([]Account, error) {
	var accounts []Account

	ctg, err := getCatalog(data)

	if err != nil {
		return nil, err
	}

	keys, err := newKeys(ctg, bootkey)

	if err != nil {
		return nil, err
	}

	err = ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(sAMAccountName); ok && v != nil {
			sat, ok := row.GetInt64(sAMAccountType)

			if !ok {
				return nil // account type missing
			}

			if _, ok = SAMAccountTypes[sat]; !ok {
				return nil // account type wrong
			}

			account, err := newAccount(row, keys)

			if err == nil {
				accounts = append(accounts, *account)
			}

			return err
		}
		return nil
	})

	return accounts, err
}

// Computers extracts all computers.
func Computers(data []byte) ([]Computer, error) {
	var computers []Computer

	ctg, err := getCatalog(data)

	if err != nil {
		return nil, err
	}

	err = ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(dNSHostName); ok && v != nil {
			if _, ok := row.Get(operatingSystem); !ok {
				return nil // operating system missing
			}

			computer, err := newComputer(row)

			if err == nil {
				computers = append(computers, *computer)
			}

			return err
		}
		return nil
	})

	return computers, err
}

func getCatalog(data []byte) (*parser.Catalog, error) {
	ctx, err := parser.NewESEContext(bytes.NewReader(data), int64(len(data)))

	if err != nil {
		return nil, err
	}

	return parser.ReadCatalog(ctx)
}
