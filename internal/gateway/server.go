package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfg      Config
	logger   *slog.Logger
	executor SNMPExecutor
	stats    *Stats
	version  string
	commit   string
	build    string
}

func NewServer(cfg Config, logger *slog.Logger, executor SNMPExecutor, version, commit, build string) *Server {
	return &Server{cfg: cfg, logger: logger, executor: executor, stats: &Stats{}, version: version, commit: commit, build: build}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.Handle("/version", s.auth(http.HandlerFunc(s.versionHandler)))
	mux.Handle("/api/v1/query", s.auth(http.HandlerFunc(s.query)))
	return requestIDMiddleware(mux)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) versionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"version": s.version, "commit": s.commit, "build_time": s.build})
}

func (s *Server) query(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "content type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.RequestBodyLimitBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req QueryRequest
	if err := dec.Decode(&req); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "request body too large") {
			status = http.StatusRequestEntityTooLarge
		}
		writeError(w, status, "invalid_request", "invalid JSON request body")
		return
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must contain one JSON value")
		return
	}
	if err := ValidateQuery(&req, s.cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	start := time.Now()
	if s.cfg.LogDebugRequests {
		s.logDebugTargets(req.Requests, "query request accepted")
	}
	results := s.execute(r.Context(), req.Requests)
	s.stats.Record(results, time.Since(start))
	writeJSON(w, http.StatusOK, QueryResponse{Results: results})
	if s.cfg.LogDebugRequests {
		s.logDebugResults(results)
	}
	if hasFailures(results) {
		s.logger.Info("query completed with failures",
			"request_id", RequestIDFromContext(r.Context()),
			"target_count", len(results),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}
}

func (s *Server) execute(ctx context.Context, requests []TargetRequest) []TargetResult {
	results := make([]TargetResult, len(requests))
	sem := make(chan struct{}, s.cfg.MaxParallelTargets)
	var wg sync.WaitGroup
	for i := range requests {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = TargetResult{Target: requests[i].Target, Port: requests[i].Port, Operations: errorResults(requests[i].Operations, &APIError{Code: "internal_error", Message: "request canceled"})}
				return
			}
			results[i] = TargetResult{
				Target:     requests[i].Target,
				Port:       requests[i].Port,
				Operations: s.executor.Execute(ctx, requests[i]),
			}
		}()
	}
	wg.Wait()
	return results
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		validUser := subtle.ConstantTimeCompare([]byte(username), []byte(s.cfg.BasicAuthUsername)) == 1
		validPass := subtle.ConstantTimeCompare([]byte(password), []byte(s.cfg.BasicAuthPassword)) == 1
		if !ok || !validUser || !validPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="snmp-proxy"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.cfg.ListenAddress,
		Handler:           s.Handler(),
		ReadHeaderTimeout: s.cfg.ReadHeaderTimeout,
		ReadTimeout:       s.cfg.ReadTimeout,
		WriteTimeout:      s.cfg.WriteTimeout,
		IdleTimeout:       s.cfg.IdleTimeout,
	}
}

func (s *Server) StartStatsLoop(ctx context.Context) {
	if s.cfg.RequestStatsInterval == 0 {
		return
	}
	ticker := time.NewTicker(s.cfg.RequestStatsInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.stats.Log(s.logger)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorEnvelope{Error: APIError{Code: code, Message: message}})
}

func hasFailures(results []TargetResult) bool {
	for _, target := range results {
		for _, op := range target.Operations {
			if op.Status == "error" {
				return true
			}
		}
	}
	return false
}

func (s *Server) logDebugTargets(requests []TargetRequest, message string) {
	for _, req := range requests {
		if s.debugTargetSelected(req.Target) {
			s.logger.Debug(message,
				"target", req.Target,
				"operation_count", len(req.Operations),
			)
		}
	}
}

func (s *Server) logDebugResults(results []TargetResult) {
	for _, result := range results {
		if !s.debugTargetSelected(result.Target) {
			continue
		}
		successes, failures := 0, 0
		for _, op := range result.Operations {
			if op.Status == "ok" {
				successes++
			} else {
				failures++
			}
		}
		s.logger.Debug("query target completed",
			"target", result.Target,
			"operation_success_count", successes,
			"operation_failure_count", failures,
		)
	}
}

func (s *Server) debugTargetSelected(target string) bool {
	for _, allowed := range s.cfg.LogDebugTargets {
		if allowed == target {
			return true
		}
	}
	return false
}

type requestIDKey struct{}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID(id) {
			id = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

func validRequestID(v string) bool {
	return len(v) > 0 && len(v) <= 128 && !strings.ContainsAny(v, "\r\n")
}

func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func ShutdownHTTP(ctx context.Context, srv *http.Server) error {
	err := srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return err
}
