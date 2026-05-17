package gateway

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
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

type StatsSnapshot struct {
	TotalQueries       int64
	SuccessfulQueries  int64
	PartiallyFailed    int64
	FullyFailed        int64
	TargetCount        int64
	OperationCount     int64
	OperationSuccesses int64
	OperationFailures  int64
	TotalLatency       time.Duration
	ReceivedTraps      int64
	DecodedTraps       int64
	RejectedTraps      int64
	MatchedTraps       int64
	UnmatchedTraps     int64
	QueuedTraps        int64
	ForwardedTraps     int64
	FailedForwards     int64
	TrapRetries        int64
	TrapForwardLatency time.Duration
	RouteSuccesses     map[string]int64
	RouteFailures      map[string]int64
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

func (s *Stats) Snapshot() StatsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return StatsSnapshot{
		TotalQueries:       s.totalQueries,
		SuccessfulQueries:  s.successfulQueries,
		PartiallyFailed:    s.partiallyFailed,
		FullyFailed:        s.fullyFailed,
		TargetCount:        s.targetCount,
		OperationCount:     s.operationCount,
		OperationSuccesses: s.operationSuccesses,
		OperationFailures:  s.operationFailures,
		TotalLatency:       s.totalLatency,
		ReceivedTraps:      s.receivedTraps,
		DecodedTraps:       s.decodedTraps,
		RejectedTraps:      s.rejectedTraps,
		MatchedTraps:       s.matchedTraps,
		UnmatchedTraps:     s.unmatchedTraps,
		QueuedTraps:        s.queuedTraps,
		ForwardedTraps:     s.forwardedTraps,
		FailedForwards:     s.failedForwards,
		TrapRetries:        s.trapRetries,
		TrapForwardLatency: s.trapForwardLatency,
		RouteSuccesses:     copyCounts(s.routeSuccesses),
		RouteFailures:      copyCounts(s.routeFailures),
	}
}

func copyCounts(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func (s StatsSnapshot) PrometheusText() string {
	var b strings.Builder
	writeMetricHeader(&b, "snmp_proxy_query_requests_total", "Total SNMP query requests by outcome.", "counter")
	writeLabeledMetric(&b, "snmp_proxy_query_requests_total", "outcome", "success", s.SuccessfulQueries)
	writeLabeledMetric(&b, "snmp_proxy_query_requests_total", "outcome", "partial_failure", s.PartiallyFailed)
	writeLabeledMetric(&b, "snmp_proxy_query_requests_total", "outcome", "failure", s.FullyFailed)
	writeMetricHeader(&b, "snmp_proxy_query_targets_total", "Total SNMP query targets processed.", "counter")
	writeMetric(&b, "snmp_proxy_query_targets_total", s.TargetCount)
	writeMetricHeader(&b, "snmp_proxy_query_operations_total", "Total SNMP query operations by outcome.", "counter")
	writeLabeledMetric(&b, "snmp_proxy_query_operations_total", "outcome", "success", s.OperationSuccesses)
	writeLabeledMetric(&b, "snmp_proxy_query_operations_total", "outcome", "failure", s.OperationFailures)
	writeMetricHeader(&b, "snmp_proxy_query_duration_seconds", "SNMP query request duration.", "summary")
	writeFloatMetric(&b, "snmp_proxy_query_duration_seconds_sum", s.TotalLatency.Seconds())
	writeMetric(&b, "snmp_proxy_query_duration_seconds_count", s.TotalQueries)

	writeMetricHeader(&b, "snmp_proxy_traps_total", "Trap and inform packets by processing outcome.", "counter")
	writeLabeledMetric(&b, "snmp_proxy_traps_total", "outcome", "received", s.ReceivedTraps)
	writeLabeledMetric(&b, "snmp_proxy_traps_total", "outcome", "decoded", s.DecodedTraps)
	writeLabeledMetric(&b, "snmp_proxy_traps_total", "outcome", "rejected", s.RejectedTraps)
	writeLabeledMetric(&b, "snmp_proxy_traps_total", "outcome", "matched", s.MatchedTraps)
	writeLabeledMetric(&b, "snmp_proxy_traps_total", "outcome", "unmatched", s.UnmatchedTraps)
	writeLabeledMetric(&b, "snmp_proxy_traps_total", "outcome", "queued", s.QueuedTraps)
	writeLabeledMetric(&b, "snmp_proxy_traps_total", "outcome", "forwarded_success", s.ForwardedTraps)
	writeLabeledMetric(&b, "snmp_proxy_traps_total", "outcome", "forwarded_failure", s.FailedForwards)
	writeMetricHeader(&b, "snmp_proxy_trap_forward_retries_total", "Total trap forwarding retries.", "counter")
	writeMetric(&b, "snmp_proxy_trap_forward_retries_total", s.TrapRetries)
	writeMetricHeader(&b, "snmp_proxy_trap_forward_duration_seconds", "Successful trap forwarding duration.", "summary")
	writeFloatMetric(&b, "snmp_proxy_trap_forward_duration_seconds_sum", s.TrapForwardLatency.Seconds())
	writeMetric(&b, "snmp_proxy_trap_forward_duration_seconds_count", s.ForwardedTraps)
	writeMetricHeader(&b, "snmp_proxy_trap_route_forwards_total", "Trap forwarding outcomes by matched route.", "counter")
	for _, route := range mergeRouteKeys(s.RouteSuccesses, s.RouteFailures) {
		writeRouteMetric(&b, route, "success", s.RouteSuccesses[route])
		writeRouteMetric(&b, route, "failure", s.RouteFailures[route])
	}
	return b.String()
}

func mergeRouteKeys(routeMaps ...map[string]int64) []string {
	seen := make(map[string]struct{})
	for _, routeMap := range routeMaps {
		for route := range routeMap {
			seen[route] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for route := range seen {
		out = append(out, route)
	}
	sort.Strings(out)
	return out
}

func writeMetricHeader(b *strings.Builder, name, help, metricType string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func writeMetric(b *strings.Builder, name string, value int64) {
	fmt.Fprintf(b, "%s %d\n", name, value)
}

func writeFloatMetric(b *strings.Builder, name string, value float64) {
	fmt.Fprintf(b, "%s %g\n", name, value)
}

func writeLabeledMetric(b *strings.Builder, name, labelName, labelValue string, value int64) {
	fmt.Fprintf(b, "%s{%s=%q} %d\n", name, labelName, labelValue, value)
}

func writeRouteMetric(b *strings.Builder, route, outcome string, value int64) {
	fmt.Fprintf(b, "snmp_proxy_trap_route_forwards_total{route=%q,outcome=%q} %d\n", route, outcome, value)
}

func (s *Stats) Log(logger *slog.Logger) {
	snapshot := s.Snapshot()
	avg := time.Duration(0)
	if snapshot.TotalQueries > 0 {
		avg = snapshot.TotalLatency / time.Duration(snapshot.TotalQueries)
	}
	logger.Info("aggregate request statistics",
		"total_query_requests", snapshot.TotalQueries,
		"successful_query_requests", snapshot.SuccessfulQueries,
		"partially_failed_query_requests", snapshot.PartiallyFailed,
		"fully_failed_query_requests", snapshot.FullyFailed,
		"target_count", snapshot.TargetCount,
		"operation_count", snapshot.OperationCount,
		"operation_success_count", snapshot.OperationSuccesses,
		"operation_failure_count", snapshot.OperationFailures,
		"average_latency_ms", avg.Milliseconds(),
		"received_trap_count", snapshot.ReceivedTraps,
		"decoded_trap_count", snapshot.DecodedTraps,
		"rejected_trap_count", snapshot.RejectedTraps,
		"matched_trap_count", snapshot.MatchedTraps,
		"unmatched_trap_count", snapshot.UnmatchedTraps,
		"queued_trap_count", snapshot.QueuedTraps,
		"forwarded_trap_success_count", snapshot.ForwardedTraps,
		"forwarded_trap_failure_count", snapshot.FailedForwards,
		"trap_retry_count", snapshot.TrapRetries,
	)
}
