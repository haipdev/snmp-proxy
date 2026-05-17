package gateway

import (
	"testing"
	"time"
)

func TestLoadConfigEnvAndFlagPrecedence(t *testing.T) {
	env := map[string]string{
		"SNMP_PROXY_BASIC_AUTH_USERNAME":  "env-user",
		"SNMP_PROXY_BASIC_AUTH_PASSWORD":  "env-pass",
		"SNMP_PROXY_TLS_ENABLED":          "false",
		"SNMP_PROXY_MAX_PARALLEL_TARGETS": "4",
	}
	cfg, err := LoadConfig([]string{"-basic-auth-username=flag-user", "-max-parallel-targets=7"}, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BasicAuthUsername != "flag-user" || cfg.BasicAuthPassword != "env-pass" {
		t.Fatalf("unexpected auth config: %+v", cfg)
	}
	if cfg.MaxParallelTargets != 7 {
		t.Fatalf("expected flag override, got %d", cfg.MaxParallelTargets)
	}
	if cfg.ListenAddress != ":8080" {
		t.Fatalf("expected TLS-disabled default listen address, got %s", cfg.ListenAddress)
	}
}

func TestConfigValidationRequiresAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BasicAuthUsername = "user"
	cfg.BasicAuthPassword = "pass"
	cfg.RequestStatsInterval = time.Second
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.BasicAuthPassword = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing password error")
	}
}
