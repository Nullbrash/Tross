package main

import (
	"os"
	"path/filepath"
	"testing"

	"tross/core/keycheck"
)

func TestExecuteDryRunRejectsUnsafeLimits(t *testing.T) {
	input := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(input, []byte("vless://id@example.test:443?security=tls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := execute(input, t.TempDir(), "", "", false, 11, 10e9); err == nil {
		t.Fatal("workers above limit accepted")
	}
	if err := execute(input, t.TempDir(), "", "", false, 1, 9e9); err == nil {
		t.Fatal("changed timeout accepted")
	}
}

func TestLoadRecordsExcludesUnsupported(t *testing.T) {
	input := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(input, []byte("vless://id@example.test:443?security=tls\nss://secret@example.test:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	records, skipped, err := loadRecords(input, nilCheckpoint())
	if err != nil || len(records) != 1 || skipped != 1 {
		t.Fatalf("records=%d skipped=%d err=%v", len(records), skipped, err)
	}
}

func nilCheckpoint() *keycheck.Checkpoint {
	return &keycheck.Checkpoint{Records: map[string]keycheck.Record{}}
}
