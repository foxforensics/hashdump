// Dump password hashes and records from an offline Active Directory database.
//
// Usage:
//
//	hashdump [-u|g|c] ntds [system]
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
//		System registry hive (SYSTEM, optional).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.foxforensics.eu/bootkey/bootkey"
	"go.foxforensics.eu/go-mmap"
	"go.foxforensics.eu/hashdump/extract"
)

var Usage = `© 2026 Fox Forensics. Licensed under MIT License.
Usage: hashdump [-ugc] NTDS [SYSTEM]

  -u  dump all users
  -g  dump all groups
  -c  dump all computers

Report bugs at: foxforensics.eu/issues`

func main() {
	var err error

	flag.Usage = func() {
		_, _ = fmt.Fprintln(os.Stderr, Usage)
		os.Exit(2)
	}

	u := flag.Bool("u", false, "dump all users")
	g := flag.Bool("g", false, "dump all groups")
	c := flag.Bool("c", false, "dump all computers")

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
	}

	if flag.NArg() < 2 && !(*u || *g || *c) {
		_, _ = fmt.Fprintln(os.Stderr, "SYSTEM file required")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	defer stop()

	var bk []byte

	if flag.NArg() > 1 {
		bk, err = bootkey.ExtractFromFile(flag.Arg(1))

		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}

	f, err := os.Open(flag.Arg(0))

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	defer func() {
		_ = f.Close()
	}()

	b, err := mmap.Map(f, mmap.RDONLY, 0)

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		_ = f.Close()
		os.Exit(1)
	}

	defer func() {
		_ = b.Unmap()
	}()

	switch {
	case *u:
		err = dumpUsers(ctx, b, bk)
	case *g:
		err = dumpGroups(ctx, b)
	case *c:
		err = dumpComputers(ctx, b)
	default:
		err = dumpSecrets(ctx, b, bk)
	}

	if err != nil {
		if !errors.Is(err, context.Canceled) {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		} else {
			os.Exit(3)
		}
	}
}

func dumpUsers(ctx context.Context, b, bk []byte) error {
	accounts, err := extract.Accounts(ctx, b, bk)

	if err != nil {
		return err
	}

	for _, account := range accounts {
		_, _ = fmt.Println(account.JSON())
	}

	return nil
}

func dumpGroups(ctx context.Context, b []byte) error {
	groups, err := extract.Groups(ctx, b)

	if err != nil {
		return err
	}

	for _, group := range groups {
		_, _ = fmt.Println(group.JSON())
	}

	return nil
}

func dumpComputers(ctx context.Context, b []byte) error {
	computers, err := extract.Computers(ctx, b)

	if err != nil {
		return err
	}

	for _, computer := range computers {
		_, _ = fmt.Println(computer.JSON())
	}

	return nil
}

func dumpSecrets(ctx context.Context, b, bk []byte) error {
	accounts, err := extract.Accounts(ctx, b, bk)

	if err != nil {
		return err
	}

	for _, account := range accounts {
		_, _ = fmt.Println(account.String())
	}

	return nil
}
