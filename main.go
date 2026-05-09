// Dump account data and password hashes from an offline Active Directory database.
//
// Usage:
//
//	hashdump [-j] ntds system
//
// The options are:
//
//	j
//	    Show detailed infos as JSON.
//
// The arguments are:
//
//	ntds
//		Active Directory database (NTDS.dit, required).
//	system
//		System registry hive (SYSTEM, required).
package main

import (
	"flag"
	"fmt"
	"os"

	"go.foxforensics.dev/bootkey/bootkey"
	"go.foxforensics.dev/go-mmap"
	"go.foxforensics.dev/hashdump/extract"
)

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintln(os.Stderr, "usage: hashdump [-j] NTDS SYSTEM")
		os.Exit(2)
	}

	json := flag.Bool("j", false, "show detailed infos as JSON")

	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
	}

	k, err := bootkey.ReadFile(flag.Arg(1))

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	f, err := os.Open(flag.Arg(0))

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

	_, accounts, err := extract.Extract(m, k)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, account := range accounts {
		if *json {
			_, _ = fmt.Println(account.JSON())
		} else {
			_, _ = fmt.Println(account.NTLM())
		}
	}
}
