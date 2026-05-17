package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestHTTPSStartupWithGeneratedCertAndMixedQuery(t *testing.T) {
	cfg := testConfig()
	cfg.TLSCertPath = filepath.Join(t.TempDir(), "certs", "server.crt")
	cfg.TLSKeyPath = filepath.Join(t.TempDir(), "certs", "server.key")
	if err := EnsureTLSMaterial(cfg); err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), fakeExecutor{fn: func(_ context.Context, req TargetRequest) []OperationResult {
		return []OperationResult{
			{Type: req.Operations[0].Type, Status: "ok", Values: []VarBind{{OID: ".1", Type: "Integer", Value: 1}}},
			{Type: req.Operations[1].Type, Status: "error", Error: &APIError{Code: "timeout", Message: "request timeout"}},
		}
	}}, "v1", "abc", "now")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	errCh := make(chan error, 1)
	go func() { errCh <- s.HTTPServer().ServeTLS(listener, cfg.TLSCertPath, cfg.TLSKeyPath) }()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	baseURL := "https://" + listener.Addr().String()
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	body := bytes.NewBufferString(`{"requests":[{"target":"127.0.0.1","community":"public","operations":[{"type":"get","oids":[".1"]},{"type":"walk","root_oid":".1"}]}]}`)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/query", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("user", "pass")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || got.Results[0].Operations[0].Status != "ok" || got.Results[0].Operations[1].Status != "error" {
		t.Fatalf("unexpected query response: status=%d body=%+v", resp.StatusCode, got)
	}
}

func TestGoSNMPExecutorAgainstSimulator(t *testing.T) {
	addr, closeSimulator := startSNMPSimulator(t)
	defer closeSimulator()

	retries := 0
	req := TargetRequest{
		Target:    addr.IP.String(),
		Port:      addr.Port,
		Version:   "2c",
		Community: "public",
		TimeoutMS: 1000,
		Retries:   &retries,
		Operations: []Operation{
			{Type: "get", OIDs: []string{".1.3.6.1.2.1.1.1.0"}},
			{Type: "walk", RootOID: ".1.3.6.1.2.1.1"},
		},
	}
	results := (GoSNMPExecutor{MaxVarbinds: 10}).Execute(context.Background(), req)
	if len(results) != 2 || results[0].Status != "ok" || results[1].Status != "ok" {
		t.Fatalf("unexpected simulator results: %+v", results)
	}
	if len(results[0].Values) != 1 || len(results[1].Values) != 2 {
		t.Fatalf("unexpected simulator values: %+v", results)
	}
}

func startSNMPSimulator(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			packet, err := gosnmp.Default.SnmpDecodePacket(buf[:n])
			if err != nil {
				continue
			}
			response := &gosnmp.SnmpPacket{
				Version:   gosnmp.Version2c,
				Community: packet.Community,
				PDUType:   gosnmp.GetResponse,
				RequestID: packet.RequestID,
				Error:     gosnmp.NoError,
				Variables: simulatorResponse(packet),
			}
			payload, err := response.MarshalMsg()
			if err == nil {
				_, _ = conn.WriteToUDP(payload, addr)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), func() { _ = conn.Close() }
}

func simulatorResponse(packet *gosnmp.SnmpPacket) []gosnmp.SnmpPDU {
	if len(packet.Variables) == 0 {
		return nil
	}
	switch packet.PDUType {
	case gosnmp.GetRequest:
		return []gosnmp.SnmpPDU{{Name: packet.Variables[0].Name, Type: gosnmp.OctetString, Value: []byte("router-a")}}
	case gosnmp.GetNextRequest:
		switch packet.Variables[0].Name {
		case ".1.3.6.1.2.1.1":
			return []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("router-a")}}
		case ".1.3.6.1.2.1.1.1.0":
			return []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.2.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9"}}
		default:
			return []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.2.1.0", Type: gosnmp.Integer, Value: 1}}
		}
	default:
		return nil
	}
}
