package repo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/angga-22/pqinv/internal/model"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanFindsCryptoPatterns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main

import (
	"crypto/md5"
	"crypto/rsa"
)

const tokenAlg = "RS256"
`)
	writeFile(t, dir, "README.md", "we finally migrated off MD5 and RS256")
	writeFile(t, dir, "node_modules/dep.js", `const alg = "md5"`)
	writeFile(t, dir, "vendor/lib.go", `import "crypto/rsa"`)
	writeFile(t, dir, "blob.bin", "crypto/rsa\x00\x01\x02")

	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	assets, err := p.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want := map[string]struct {
		location string
		usage    model.Usage
	}{
		"MD5":   {"main.go:4", model.UsageHash},
		"RSA":   {"main.go:5", model.UsageSignature},
		"RS256": {"main.go:8", model.UsageSignature},
	}
	for alg, w := range want {
		found := false
		for _, a := range assets {
			if a.Algorithm == alg && a.Location == w.location {
				found = true
				if a.Usage != w.usage {
					t.Errorf("%s usage = %s, want %s", alg, a.Usage, w.usage)
				}
			}
		}
		if !found {
			t.Errorf("%s at %s not found in %d assets", alg, w.location, len(assets))
		}
	}

	for _, a := range assets {
		if strings.HasPrefix(a.Location, "node_modules") || strings.HasPrefix(a.Location, "vendor") {
			t.Errorf("junk directory was scanned: %s", a.Location)
		}
		if strings.HasPrefix(a.Location, "blob.bin") {
			t.Errorf("binary file was scanned: %s", a.Location)
		}
		if strings.HasPrefix(a.Location, "README.md") {
			t.Errorf("documentation file was scanned: %s", a.Location)
		}
	}
}

func TestScanDedupesOverlappingPatterns(t *testing.T) {
	dir := t.TempDir()
	// "crypto/md5" matches both the import pattern and the md5 literal —
	// must yield exactly one MD5 asset for the line.
	writeFile(t, dir, "hash.go", `import "crypto/md5"`)

	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	assets, err := p.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, a := range assets {
		if a.Algorithm == "MD5" && a.Location == "hash.go:1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("MD5 at hash.go:1 reported %d times, want exactly 1", count)
	}
}

func TestScanRejectsNonDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "file.go", "package x")

	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Scan(context.Background(), filepath.Join(dir, "file.go")); err == nil {
		t.Error("expected error scanning a file instead of a directory")
	}
}
