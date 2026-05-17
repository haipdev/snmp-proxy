package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeExecutor struct {
	fn func(context.Context, TargetRequest) []OperationResult
}

func (f fakeExecutor) Execute(ctx context.Context, req TargetRequest) []OperationResult {
	return f.fn(ctx, req)
}

func newTestServer(exec SNMPExecutor) *Server {
	return NewServer(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), exec, "v1", "abc", "now")
}

func TestHealthzUnauthenticatedAndVersionProtected(t *testing.T) {
	s := newTestServer(fakeExecutor{fn: func(context.Context, TargetRequest) []OperationResult { return nil }})
	health := httptest.NewRecorder()
	s.Handler().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", health.Code)
	}
	version := httptest.NewRecorder()
	s.Handler().ServeHTTP(version, httptest.NewRequest(http.MethodGet, "/version", nil))
	if version.Code != http.StatusUnauthorized {
		t.Fatalf("version status = %d", version.Code)
	}
}

func TestQueryReturnsOrderedPartialFailures(t *testing.T) {
	s := newTestServer(fakeExecutor{fn: func(_ context.Context, req TargetRequest) []OperationResult {
		out := make([]OperationResult, len(req.Operations))
		for i, op := range req.Operations {
			if i == 0 {
				out[i] = OperationResult{Type: op.Type, Status: "ok", Values: []VarBind{{OID: ".1", Type: "Integer", Value: 1}}}
			} else {
				out[i] = OperationResult{Type: op.Type, Status: "error", Error: &APIError{Code: "timeout", Message: "request timeout"}}
			}
		}
		return out
	}})
	body := `{"requests":[{"target":"a","community":"public","operations":[{"type":"get","oids":[".1"]},{"type":"walk","root_oid":".1"}]},{"target":"b","community":"public","operations":[{"type":"get","oids":[".1"]}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("user", "pass")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query status = %d", rec.Code)
	}
	var resp QueryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Results[0].Target != "a" || resp.Results[1].Target != "b" {
		t.Fatalf("target order not preserved: %+v", resp.Results)
	}
	if resp.Results[0].Operations[0].Status != "ok" || resp.Results[0].Operations[1].Status != "error" {
		t.Fatalf("operation results unexpected: %+v", resp.Results[0].Operations)
	}
}

func TestQueryEnforcesConcurrencyLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MaxParallelTargets = 2
	var current int32
	var maxSeen int32
	var once sync.Once
	release := make(chan struct{})
	s := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), fakeExecutor{fn: func(_ context.Context, req TargetRequest) []OperationResult {
		n := atomic.AddInt32(&current, 1)
		for {
			old := atomic.LoadInt32(&maxSeen)
			if n <= old || atomic.CompareAndSwapInt32(&maxSeen, old, n) {
				break
			}
		}
		once.Do(func() { time.AfterFunc(50*time.Millisecond, func() { close(release) }) })
		<-release
		atomic.AddInt32(&current, -1)
		return []OperationResult{{Type: req.Operations[0].Type, Status: "ok"}}
	}}, "v1", "abc", "now")
	body := `{"requests":[{"target":"a","community":"public","operations":[{"type":"get","oids":[".1"]}]},{"target":"b","community":"public","operations":[{"type":"get","oids":[".1"]}]},{"target":"c","community":"public","operations":[{"type":"get","oids":[".1"]}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("user", "pass")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if maxSeen > 2 {
		t.Fatalf("expected concurrency <= 2, saw %d", maxSeen)
	}
}

func TestQueryRejectsLargeBody(t *testing.T) {
	cfg := testConfig()
	cfg.RequestBodyLimitBytes = 10
	s := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), fakeExecutor{fn: func(context.Context, TargetRequest) []OperationResult { return nil }}, "v1", "abc", "now")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", bytes.NewBufferString(`{"requests":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("user", "pass")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
}

func TestDebugLogsDoNotLeakCommunity(t *testing.T) {
	var logs bytes.Buffer
	cfg := testConfig()
	cfg.LogDebugRequests = true
	cfg.LogDebugTargets = []string{"a"}
	s := NewServer(cfg, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), fakeExecutor{fn: func(_ context.Context, req TargetRequest) []OperationResult {
		return []OperationResult{{Type: req.Operations[0].Type, Status: "ok"}}
	}}, "v1", "abc", "now")
	body := `{"requests":[{"target":"a","community":"super-secret","operations":[{"type":"get","oids":[".1"]}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("user", "pass")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if bytes.Contains(logs.Bytes(), []byte("super-secret")) {
		t.Fatalf("community leaked in logs: %s", logs.String())
	}
}
