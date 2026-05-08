// Dump user account data and password hashes from an Active Directory database.
//
// Usage:
//
//	hashdump system ntds
//
// The arguments are:
//
//	system
//		System registry hive (SYSTEM, required).
//	ntds
//		Active Directory database (NTDS.DIT, required).
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
		_, _ = fmt.Fprintln(os.Stderr, "usage: hashdump system ntds")
		os.Exit(2)
	}

	k, err := bootkey.ReadFile(os.Args[1])

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	_, _ = fmt.Printf("BootKey: %x\n", k)

	f, err := os.Open(os.Args[2])

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

	accounts, peks, err := hashdump.Extract(m, k)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for i, pek := range peks {
		_, _ = fmt.Printf("PEK #%d: %x\n", i, pek)
	}

	for _, account := range accounts {
		_, _ = fmt.Println(account.String())
	}
}
