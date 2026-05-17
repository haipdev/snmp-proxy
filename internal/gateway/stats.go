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
	receivedTraps      int64
	decodedTraps       int64
	rejectedTraps      int64
	matchedTraps       int64
	unmatchedTraps     int64
	queuedTraps        int64
	forwardedTraps     int64
	failedForwards     int64
	trapRetries        int64
	trapForwardLatency time.Duration
	routeSuccesses     map[string]int64
	routeFailures      map[string]int64
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

func (s *Stats) ensureRouteMaps() {
	if s.routeSuccesses == nil {
		s.routeSuccesses = make(map[string]int64)
	}
	if s.routeFailures == nil {
		s.routeFailures = make(map[string]int64)
	}
}

func (s *Stats) RecordTrapReceived() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receivedTraps++
}

func (s *Stats) RecordTrapDecoded() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decodedTraps++
	s.matchedTraps++
}

func (s *Stats) RecordTrapRejected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectedTraps++
}

func (s *Stats) RecordTrapUnmatched() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unmatchedTraps++
}

func (s *Stats) RecordTrapQueued() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queuedTraps++
}

func (s *Stats) RecordTrapRetry() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trapRetries++
}

func (s *Stats) RecordTrapForwardSuccess(route string, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureRouteMaps()
	s.forwardedTraps++
	s.routeSuccesses[route]++
	s.trapForwardLatency += duration
}

func (s *Stats) RecordTrapForwardFailure(route string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureRouteMaps()
	s.failedForwards++
	s.routeFailures[route]++
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
		"received_trap_count", s.receivedTraps,
		"decoded_trap_count", s.decodedTraps,
		"rejected_trap_count", s.rejectedTraps,
		"matched_trap_count", s.matchedTraps,
		"unmatched_trap_count", s.unmatchedTraps,
		"queued_trap_count", s.queuedTraps,
		"forwarded_trap_success_count", s.forwardedTraps,
		"forwarded_trap_failure_count", s.failedForwards,
		"trap_retry_count", s.trapRetries,
	)
}
