package main

import (
	"testing"
	"time"

	"github.com/example/snmp-proxy/internal/gateway"
)

func TestExpectedSNMPExecutionBudgetIncludesSequentialOperations(t *testing.T) {
	cfg := gateway.DefaultConfig()
	cfg.DefaultSNMPTimeout = 2 * time.Second
	cfg.DefaultSNMPRetries = 2
	cfg.MaxOperationsPerTarget = 4
	if got, want := expectedSNMPExecutionBudget(cfg), 24*time.Second; got != want {
		t.Fatalf("budget = %s, want %s", got, want)
	}
}
