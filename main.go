// Dump password hashes and data from an offline Active Directory database.
//
// Usage:
//
//	hashdump [-c|u] ntds system
//
// The options are:
//
//	c
//	    Dump all computers.
//	u
//	    Dump all users.
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
		_, _ = fmt.Fprintln(os.Stderr, "usage: hashdump [-c|u] NTDS SYSTEM")
		os.Exit(2)
	}

	c := flag.Bool("c", false, "dump all computers")
	u := flag.Bool("u", false, "dump all users")

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

	b, err := mmap.Map(f, mmap.RDONLY, 0)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	defer func() { _ = b.Unmap() }()

	switch {
	case *c:
		dumpComputers(b)
	case *u:
		dumpAccounts(b, k)
	default:
		dumpSecrets(b, k)
	}
}

func dumpComputers(b []byte) {
	computers, err := extract.Computers(b)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, computer := range computers {
		_, _ = fmt.Println(computer.JSON())
	}
}

func dumpAccounts(b, k []byte) {
	accounts, err := extract.Accounts(b, k)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, account := range accounts {
		_, _ = fmt.Println(account.JSON())
	}
}

func dumpSecrets(b, k []byte) {
	accounts, err := extract.Accounts(b, k)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, account := range accounts {
		_, _ = fmt.Println(account.String())
	}
}
