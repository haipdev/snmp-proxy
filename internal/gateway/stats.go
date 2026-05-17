package gateway

import (
	"log/slog"
	"sync"
	"time"
)

type Stats struct {
	mu                 sync.Mutex
	totalQueries       int64
	successfulQueries  int64
	partiallyFailed    int64
	fullyFailed        int64
	targetCount        int64
	operationCount     int64
	operationSuccesses int64
	operationFailures  int64
	totalLatency       time.Duration
}

func (s *Stats) Record(results []TargetResult, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalQueries++
	s.totalLatency += duration
	var successes, failures int64
	s.targetCount += int64(len(results))
	for _, target := range results {
		s.operationCount += int64(len(target.Operations))
		for _, op := range target.Operations {
			if op.Status == "ok" {
				successes++
			} else {
				failures++
			}
		}
	}
	s.operationSuccesses += successes
	s.operationFailures += failures
	switch {
	case failures == 0:
		s.successfulQueries++
	case successes == 0:
		s.fullyFailed++
	default:
		s.partiallyFailed++
	}
}

func (s *Stats) Log(logger *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	avg := time.Duration(0)
	if s.totalQueries > 0 {
		avg = s.totalLatency / time.Duration(s.totalQueries)
	}
	logger.Info("aggregate request statistics",
		"total_query_requests", s.totalQueries,
		"successful_query_requests", s.successfulQueries,
		"partially_failed_query_requests", s.partiallyFailed,
		"fully_failed_query_requests", s.fullyFailed,
		"target_count", s.targetCount,
		"operation_count", s.operationCount,
		"operation_success_count", s.operationSuccesses,
		"operation_failure_count", s.operationFailures,
		"average_latency_ms", avg.Milliseconds(),
	)
}
