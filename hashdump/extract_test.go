package hashdump

import (
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

func TestExtract(t *testing.T) {
	t.Run("Test Extract", func(t *testing.T) {
		gs, err := fixture(dump)

		if err != nil {
			t.Fatalf("Extract: %v", err)
		}

		ad, err := fixture(ntds)

		if err != nil {
			t.Fatalf("Extract: %v", err)
		}

		acc, _, err := Extract(ad, []byte(bootkey))

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

func BenchmarkExtract(b *testing.B) {
	b.Run("Benchmark Extract", func(b *testing.B) {
		ad, err := fixture(ntds)

		if err != nil {
			b.Fatalf("Extract: %v", err)
		}

		b.ResetTimer()

		for n := 0; n < b.N; n++ {
			_, _, _ = Extract(ad, []byte(bootkey))
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
