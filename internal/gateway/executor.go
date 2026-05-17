package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type SNMPExecutor interface {
	Execute(context.Context, TargetRequest) []OperationResult
}

type GoSNMPExecutor struct {
	MaxVarbinds int
}

func (e GoSNMPExecutor) Execute(ctx context.Context, req TargetRequest) []OperationResult {
	client := newGoSNMPClient(req)
	if err := client.Connect(); err != nil {
		apiErr := classifyError(err)
		return errorResults(req.Operations, apiErr)
	}
	defer client.Conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Conn.Close()
		case <-done:
		}
	}()

	out := make([]OperationResult, len(req.Operations))
	for i, op := range req.Operations {
		select {
		case <-ctx.Done():
			out[i] = OperationResult{Type: op.Type, Status: "error", Error: &APIError{Code: "internal_error", Message: "request canceled"}}
			continue
		default:
		}
		result, err := e.executeOperation(client, op)
		if err != nil {
			out[i] = OperationResult{Type: op.Type, Status: "error", Error: classifyError(err)}
			continue
		}
		out[i] = OperationResult{Type: op.Type, Status: "ok", Values: result}
	}
	return out
}

func newGoSNMPClient(req TargetRequest) *gosnmp.GoSNMP {
	client := &gosnmp.GoSNMP{
		Target:  req.Target,
		Port:    uint16(req.Port),
		Timeout: time.Duration(req.TimeoutMS) * time.Millisecond,
		Retries: *req.Retries,
	}
	switch req.Version {
	case "3":
		client.Version = gosnmp.Version3
		client.SecurityModel = gosnmp.UserSecurityModel
		client.MsgFlags = v3MsgFlags(req.V3.SecurityLevel)
		client.ContextName = req.V3.ContextName
		client.ContextEngineID = req.V3.ContextEngineID
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 req.V3.Username,
			AuthenticationProtocol:   v3AuthProtocol(req.V3.AuthProtocol),
			AuthenticationPassphrase: req.V3.AuthPassphrase,
			PrivacyProtocol:          v3PrivProtocol(req.V3.PrivProtocol),
			PrivacyPassphrase:        req.V3.PrivPassphrase,
		}
	default:
		client.Community = req.Community
		client.Version = gosnmp.Version2c
	}
	return client
}

func v3MsgFlags(level string) gosnmp.SnmpV3MsgFlags {
	switch level {
	case "authNoPriv":
		return gosnmp.AuthNoPriv
	case "authPriv":
		return gosnmp.AuthPriv
	default:
		return gosnmp.NoAuthNoPriv
	}
}

func v3AuthProtocol(protocol string) gosnmp.SnmpV3AuthProtocol {
	switch protocol {
	case "md5":
		return gosnmp.MD5
	case "sha":
		return gosnmp.SHA
	case "sha224":
		return gosnmp.SHA224
	case "sha256":
		return gosnmp.SHA256
	case "sha384":
		return gosnmp.SHA384
	case "sha512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

func v3PrivProtocol(protocol string) gosnmp.SnmpV3PrivProtocol {
	switch protocol {
	case "des":
		return gosnmp.DES
	case "aes":
		return gosnmp.AES
	case "aes192":
		return gosnmp.AES192
	case "aes256":
		return gosnmp.AES256
	case "aes192c":
		return gosnmp.AES192C
	case "aes256c":
		return gosnmp.AES256C
	default:
		return gosnmp.NoPriv
	}
}

func (e GoSNMPExecutor) executeOperation(client *gosnmp.GoSNMP, op Operation) ([]VarBind, error) {
	switch op.Type {
	case "get":
		packet, err := client.Get(op.OIDs)
		if err != nil {
			return nil, err
		}
		return convertPDU(packet.Variables, e.MaxVarbinds)
	case "getnext":
		packet, err := client.GetNext(op.OIDs)
		if err != nil {
			return nil, err
		}
		return convertPDU(packet.Variables, e.MaxVarbinds)
	case "getbulk":
		nonRepeaters := uint8(0)
		if op.NonRepeaters != nil {
			nonRepeaters = *op.NonRepeaters
		}
		packet, err := client.GetBulk(op.OIDs, nonRepeaters, *op.MaxRepetitions)
		if err != nil {
			return nil, err
		}
		return convertPDU(packet.Variables, e.MaxVarbinds)
	case "walk":
		var values []VarBind
		err := client.Walk(op.RootOID, func(pdu gosnmp.SnmpPDU) error {
			if len(values) >= e.MaxVarbinds {
				return errResultLimitExceeded
			}
			value, err := convertSinglePDU(pdu)
			if err != nil {
				return err
			}
			values = append(values, value)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unsupported operation")
	}
}

var errResultLimitExceeded = errors.New("result limit exceeded")

func convertPDU(pdus []gosnmp.SnmpPDU, limit int) ([]VarBind, error) {
	if len(pdus) > limit {
		return nil, errResultLimitExceeded
	}
	out := make([]VarBind, len(pdus))
	for i, pdu := range pdus {
		value, err := convertSinglePDU(pdu)
		if err != nil {
			return nil, err
		}
		out[i] = value
	}
	return out, nil
}

func convertSinglePDU(pdu gosnmp.SnmpPDU) (VarBind, error) {
	var value any
	switch v := pdu.Value.(type) {
	case []byte:
		value = string(v)
	default:
		value = v
	}
	return VarBind{
		OID:   NormalizeOID(pdu.Name),
		Type:  pdu.Type.String(),
		Value: value,
	}, nil
}

func errorResults(ops []Operation, apiErr *APIError) []OperationResult {
	out := make([]OperationResult, len(ops))
	for i, op := range ops {
		errCopy := *apiErr
		out[i] = OperationResult{Type: op.Type, Status: "error", Error: &errCopy}
	}
	return out
}

func classifyError(err error) *APIError {
	if errors.Is(err, errResultLimitExceeded) {
		return &APIError{Code: "result_limit_exceeded", Message: "result limit exceeded"}
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return &APIError{Code: "timeout", Message: "request timeout"}
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "no such host"):
		return &APIError{Code: "dns_error", Message: "target resolution failed"}
	case strings.Contains(lower, "connection refused"):
		return &APIError{Code: "connection_error", Message: "connection failed"}
	case strings.Contains(lower, "context canceled"):
		return &APIError{Code: "internal_error", Message: "request canceled"}
	default:
		return &APIError{Code: "snmp_error", Message: "SNMP request failed"}
	}
}
