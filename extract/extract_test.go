package extract

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bootkey = "\x13\xD2\x09\x76\xD6\x3E\xA5\xE8\x36\x03\x6E\xC8\xBC\x68\xD6\xEB"

var (
	ntds = filepath.Join("..", "testdata", "NTDS.dit")
	dump = filepath.Join("..", "testdata", "users.golden")
)

func TestExtractSecrets(t *testing.T) {
	t.Run("Test Extract Secrets", func(t *testing.T) {
		ctx := context.Background()

		gs, err := fixture(dump)

		if err != nil {
			t.Fatalf("Extract: %v", err)
		}

		ad, err := fixture(ntds)

		if err != nil {
			t.Fatalf("Extract: %v", err)
		}

		acc, err := Accounts(ctx, ad, []byte(bootkey))

		if err != nil {
			t.Fatalf("Extract: %v", err)
		}

		var sb strings.Builder

		for _, a := range acc {
			sb.WriteString(a.String() + "\n")
		}

		if sb.String() != string(gs) {
			t.Fatal("golden sample mismatch")
		}
	})
}

func BenchmarkExtractSecrets(b *testing.B) {
	b.Run("Benchmark Extract Secrets", func(b *testing.B) {
		ctx := context.Background()

		ad, err := fixture(ntds)

		if err != nil {
			b.Fatalf("Extract: %v", err)
		}

		b.ResetTimer()

		for n := 0; n < b.N; n++ {
			_, _ = Accounts(ctx, ad, []byte(bootkey))
		}
	})
}

func BenchmarkExtract(b *testing.B) {
	b.Run("Benchmark Extract", func(b *testing.B) {
		ctx := context.Background()

		ad, err := fixture(ntds)

		if err != nil {
			b.Fatalf("Extract: %v", err)
		}

		b.ResetTimer()

		for n := 0; n < b.N; n++ {
			_, _ = Accounts(ctx, ad, []byte{})
		}
	})
}

func fixture(path string) ([]byte, error) {
	f, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	b, err := io.ReadAll(f)

	if err != nil {
		return nil, err
	}

	return b, nil
}
