// Package extract provides methods to extract Active Directory records.
//
// Sources:
//   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
//   - https://trustedsec.com/blog/exploring-ntds-dit-part-1-cracking-the-surface-with-dit-explorer
//   - https://troopers.de/downloads/troopers24/TR24_Decrypting_the_Directory_1.0_8EKVXR.pdf
//   - https://rootdse.org/posts/active-directory-basics-2/
//   - https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py
//   - https://github.com/C-Sto/gosecretsdump/blob/master/pkg/ditreader/crypto.go
//   - https://github.com/Dionach/NtdsAudit/blob/master/src/NtdsAudit/NTCrypto.cs
//   - https://github.com/xmco/ntds_extract/blob/main/Part-2-La-Datatable/Win2012R2_level.txt
//   - https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
//   - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/8263e7ab-aba9-43d2-8a36-3a9cb2dd3dad?redirectedfrom=MSDN
//   - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/7c0f2eca-1783-450b-b5a0-754cf11f22c9
//   - https://learn.microsoft.com/en-us/windows/win32/adschema/a-grouptype
package extract

import (
	"bytes"
	"fmt"

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

			account, err := accountFromRow(row, keys)

			if err == nil {
				accounts = append(accounts, *account)
			}

			return err
		}
		return nil
	})

	return accounts, err
}

// Groups extracts all groups.
func Groups(data []byte) ([]Group, error) {
	var groups []Group

	ctg, err := getCatalog(data)

	if err != nil {
		return nil, err
	}

	err = parseObjects(ctg)

	if err != nil {
		return nil, err
	}

	err = parseMembers(ctg)

	if err != nil {
		return nil, err
	}

	err = ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.GetInt64(sAMAccountType); ok && v > 0 {
			if _, ok = SAMGroupTypes[v]; !ok {
				return nil // group type wrong
			}

			group, err := groupFromRow(row)

			if err == nil {
				groups = append(groups, *group)
			}

			return err
		}
		return nil
	})

	fmt.Printf("Objects: %d %v\n", len(objects), objects)
	fmt.Printf("Members: %d %v\n", len(members), members)

	return groups, err
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

			computer, err := computerFromRow(row)

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
