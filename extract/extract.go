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
	"context"

	"github.com/Velocidex/ordereddict"
	"go.foxforensics.eu/go-ese/parser"
)

// Keys extracts all keys.
func Keys(ctx context.Context, data, bootkey []byte) ([]PEK, error) {
	ctg, err := getCatalog(data)

	if err != nil {
		return nil, err
	}

	return newKeys(ctx, ctg, bootkey)
}

// Accounts extracts all accounts with hashes (optional).
func Accounts(ctx context.Context, data, bootkey []byte) ([]Account, error) {
	var accounts []Account
	var keys []PEK

	cache := NewCache()

	ctg, err := bootstrap(ctx, cache, data)

	if err != nil {
		return nil, err
	}

	// extract keys from bootkey
	if len(bootkey) > 0 {
		keys, err = newKeys(ctx, ctg, bootkey)

		if err != nil {
			return nil, err
		}
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

			account, err := accountFromRow(cache, row, keys)

			if err == nil {
				accounts = append(accounts, *account)
			}

			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	return accounts, err
}

// Groups extracts all groups.
func Groups(ctx context.Context, data []byte) ([]Group, error) {
	var groups []Group

	cache := NewCache()

	ctg, err := bootstrap(ctx, cache, data)

	if err != nil {
		return nil, err
	}

	err = ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.GetInt64(sAMAccountType); ok && v > 0 {
			if _, ok = SAMGroupTypes[v]; !ok {
				return nil // group type wrong
			}

			group, err := groupFromRow(cache, row)

			if err == nil {
				groups = append(groups, *group)
			}

			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	return groups, err
}

// Computers extracts all computers.
func Computers(ctx context.Context, data []byte) ([]Computer, error) {
	var computers []Computer

	cache := NewCache()

	ctg, err := bootstrap(ctx, cache, data)

	if err != nil {
		return nil, err
	}

	err = ctg.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if v, ok := row.Get(dNSHostName); ok && v != nil {
			if _, ok := row.Get(operatingSystem); !ok {
				return nil // operating system missing
			}

			computer, err := computerFromRow(cache, row)

			if err == nil {
				computers = append(computers, *computer)
			}

			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	return computers, err
}

func bootstrap(ctx context.Context, cache *Cache, data []byte) (*parser.Catalog, error) {
	ctg, err := getCatalog(data)

	if err != nil {
		return nil, err
	}

	err = cache.FillObjects(ctx, ctg)

	if err != nil {
		return nil, err
	}

	err = cache.FillMembers(ctx, ctg)

	if err != nil {
		return nil, err
	}

	return ctg, err
}
