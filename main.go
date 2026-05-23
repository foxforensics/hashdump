// Dump password hashes and records from an offline Active Directory database.
//
// Usage:
//
//	hashdump [-u|g|c] ntds system
//
// The options are:
//
//	u
//	    Dump all users.
//	g
//	    Dump all groups.
//	c
//	    Dump all computers.
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
		_, _ = fmt.Fprintln(os.Stderr, "usage: hashdump [-u|g|c] NTDS SYSTEM")
		os.Exit(2)
	}

	u := flag.Bool("u", false, "dump all users")
	g := flag.Bool("g", false, "dump all groups")
	c := flag.Bool("c", false, "dump all computers")

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
	case *u:
		dumpUsers(b, k)
	case *g:
		dumpGroups(b)
	case *c:
		dumpComputers(b)
	default:
		dumpSecrets(b, k)
	}
}

func dumpUsers(b, k []byte) {
	accounts, err := extract.Accounts(b, k)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, account := range accounts {
		_, _ = fmt.Println(account.JSON())
	}
}

func dumpGroups(b []byte) {
	groups, err := extract.Groups(b)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, group := range groups {
		_, _ = fmt.Println(group.JSON())
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
