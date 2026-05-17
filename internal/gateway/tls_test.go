package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureTLSMaterialGeneratesPair(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.TLSCertPath = filepath.Join(dir, "certs", "server.crt")
	cfg.TLSKeyPath = filepath.Join(dir, "certs", "server.key")
	if err := EnsureTLSMaterial(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.TLSCertPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(cfg.TLSKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected restrictive key permissions, got %o", info.Mode().Perm())
	}
}

func TestEnsureTLSMaterialRejectsPartialPair(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.TLSCertPath = filepath.Join(dir, "server.crt")
	cfg.TLSKeyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(cfg.TLSCertPath, []byte("bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsureTLSMaterial(cfg); err == nil {
		t.Fatal("expected partial pair error")
	}
}
