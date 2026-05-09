// Dump user account data and password hashes from an Active Directory database.
//
// Usage:
//
//	hashdump ntds system
//
// The arguments are:
//
//	ntds
//		Active Directory database (NTDS.dit, required).
//	system
//		System registry hive (SYSTEM, required).
package main

import (
	"fmt"
	"os"

	"go.foxforensics.dev/bootkey/bootkey"
	"go.foxforensics.dev/go-mmap"
	"go.foxforensics.dev/hashdump/hashdump"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] == "--help" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: hashdump NTDS SYSTEM")
		os.Exit(2)
	}

	k, err := bootkey.ReadFile(os.Args[2])

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	defer func() { _ = f.Close() }()

	m, err := mmap.Map(f, mmap.RDONLY, 0)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	defer func() { _ = m.Unmap() }()

	accounts, _, err := hashdump.Extract(m, k)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, account := range accounts {
		_, _ = fmt.Println(account.String())
	}
}
