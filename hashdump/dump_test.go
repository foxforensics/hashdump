package hashdump

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bootkey = "\x13\xD2\x09\x76\xD6\x3E\xA5\xE8\x36\x03\x6E\xC8\xBC\x68\xD6\xEB"

var dump = filepath.Join("..", "testdata", "dump.golden")
var path = filepath.Join("..", "testdata", "NTDS.dit")

func TestDump(t *testing.T) {
	t.Run("Test Dump", func(t *testing.T) {
		gs, err := fixture(dump)

		if err != nil {
			t.Fatalf("Dump: %v", err)
		}

		ad, err := fixture(path)

		if err != nil {
			t.Fatalf("Dump: %v", err)
		}

		rec, _, err := Dump(ad, []byte(bootkey))

		if err != nil {
			t.Fatalf("Dump: %v", err)
		}

		var sb strings.Builder

		for _, r := range rec {
			sb.WriteString(r.String() + "\n")
		}

		if sb.String() != string(gs) {
			t.Fatal("dump differs")
		}
	})
}

func BenchmarkDump(b *testing.B) {
	b.Run("Benchmark Dump", func(b *testing.B) {
		ad, err := fixture(path)

		if err != nil {
			b.Fatalf("Dump: %v", err)
		}

		b.ResetTimer()

		for n := 0; n < b.N; n++ {
			_, _, _ = Dump(ad, []byte(bootkey))
		}
	})
}

func fixture(path string) ([]byte, error) {
	f, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer func() {
		_ = f.Close()
	}()

	b, err := io.ReadAll(f)

	if err != nil {
		return nil, err
	}

	return b, nil
}
