// Dump user password hashes from Active Directory databases.
//
// Usage:
//
//	hashdump system ntds
//
// The arguments are:
//
//	system
//		System registry hive (required).
//	ntds
//		Active Directory database (required).
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

	records, keys, err := hashdump.Dump(m, k)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for i, key := range keys {
		_, _ = fmt.Printf("PEK #%d: %x\n", i, key)
	}

	for _, record := range records {
		_, _ = fmt.Println(record.String())
	}
}
