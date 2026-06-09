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
	"go.foxforensics.dev/hashdump/extract"
)

var Usage = `© 2026 Fox Forensics. Licensed under MIT License.
Usage: hashdump [-ugc] NTDS SYSTEM

  -u  dump all users
  -g  dump all groups
  -c  dump all computers

Report bugs at: foxforensics.dev/issues`

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintln(os.Stderr, Usage)
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

	b, err := mmap.Map(f, mmap.RDONLY, 0)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		_ = f.Close()
		os.Exit(1)
	}

	switch {
	case *u:
		err = dumpUsers(b, k)
	case *g:
		err = dumpGroups(b)
	case *c:
		err = dumpComputers(b)
	default:
		err = dumpSecrets(b, k)
	}

	_ = b.Unmap()
	_ = f.Close()

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func dumpUsers(b, k []byte) error {
	accounts, err := extract.Accounts(b, k)

	if err != nil {
		return err
	}

	for _, account := range accounts {
		_, _ = fmt.Println(account.JSON())
	}

	return nil
}

func dumpGroups(b []byte) error {
	groups, err := extract.Groups(b)

	if err != nil {
		return err
	}

	for _, group := range groups {
		_, _ = fmt.Println(group.JSON())
	}

	return nil
}

func dumpComputers(b []byte) error {
	computers, err := extract.Computers(b)

	if err != nil {
		return err
	}

	for _, computer := range computers {
		_, _ = fmt.Println(computer.JSON())
	}

	return nil
}

func dumpSecrets(b, k []byte) error {
	accounts, err := extract.Accounts(b, k)

	if err != nil {
		return err
	}

	for _, account := range accounts {
		_, _ = fmt.Println(account.String())
	}

	return nil
}
