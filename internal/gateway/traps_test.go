package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func writeRouteFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTrapRouterUsesLongestPrefix(t *testing.T) {
	router, err := LoadTrapRouter(writeRouteFile(t, `{"routes":[{"source_cidr":"10.0.0.0/8","target_url":"https://broad.example/traps"},{"source_cidr":"10.1.0.0/16","target_url":"https://specific.example/traps"}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	target, cidr, ok := router.Match(net.ParseIP("10.1.2.3"))
	if !ok || target != "https://specific.example/traps" || cidr != "10.1.0.0/16" {
		t.Fatalf("unexpected route match: %q %q %v", target, cidr, ok)
	}
}

func TestBuildTrapPayloadNormalizesFields(t *testing.T) {
	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		PDUType: gosnmp.SNMPv2Trap,
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(123)},
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.3"},
		},
	}
	payload, err := buildTrapPayload(packet, &net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 1234}, "10.1.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if payload.TrapOID != ".1.3.6.1.6.3.1.1.5.3" || payload.Uptime != uint32(123) {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestTrapServiceForwardsWithRetry(t *testing.T) {
	var attempts int32
	var got TrapPayload
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	cfg := testConfig()
	cfg.TrapEnabled = true
	cfg.TrapDefaultTargetURL = target.URL
	cfg.TrapForwardRetries = 1
	cfg.TrapForwardWorkers = 1
	cfg.TrapForwardQueueSize = 1
	service, err := NewTrapService(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &Stats{}, target.Client())
	if err != nil {
		t.Fatal(err)
	}
	service.workerCtx, service.cancel = context.WithCancel(context.Background())
	service.wg.Add(1)
	go service.worker()
	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		PDUType:   gosnmp.SNMPv2Trap,
		Community: "public",
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1)},
		},
	}
	service.handlePacket(packet, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	close(service.queue)
	service.wg.Wait()
	service.cancel()
	if atomic.LoadInt32(&attempts) != 2 {
		t.Fatalf("expected retry, got %d attempts", attempts)
	}
	if got.SourceIP != "127.0.0.1" {
		t.Fatalf("unexpected forwarded payload: %+v", got)
	}
}

func TestTrapServiceReceivesTrap(t *testing.T) {
	received := make(chan TrapPayload, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload TrapPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		received <- payload
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	cfg := testConfig()
	cfg.TrapEnabled = true
	cfg.TrapListenAddress = "127.0.0.1:0"
	cfg.TrapDefaultTargetURL = target.URL
	cfg.TrapForwardWorkers = 1
	service, err := NewTrapService(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &Stats{}, target.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	addr := service.conn.LocalAddr().(*net.UDPAddr)
	sender := &gosnmp.GoSNMP{Target: addr.IP.String(), Port: uint16(addr.Port), Community: "public", Version: gosnmp.Version2c, Timeout: time.Second}
	if err := sender.Connect(); err != nil {
		t.Fatal(err)
	}
	defer sender.Conn.Close()
	if _, err := sender.SendTrap(gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1)}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-received:
		if payload.SourceIP != "127.0.0.1" {
			t.Fatalf("unexpected source IP: %+v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for forwarded trap")
	}
}

func TestTrapLogsDoNotLeakCommunity(t *testing.T) {
	var logs bytes.Buffer
	cfg := testConfig()
	cfg.TrapEnabled = true
	cfg.TrapDefaultTargetURL = "https://example.test/traps"
	cfg.TrapAllowedCommunities = []string{"allowed"}
	service, err := NewTrapService(cfg, slog.New(slog.NewJSONHandler(&logs, nil)), &Stats{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.handlePacket(&gosnmp.SnmpPacket{Version: gosnmp.Version2c, PDUType: gosnmp.SNMPv2Trap, Community: "super-secret"}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if bytes.Contains(logs.Bytes(), []byte("super-secret")) {
		t.Fatalf("community leaked in logs: %s", logs.String())
	}
}
