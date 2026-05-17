package gateway

import (
	"fmt"
	"regexp"
	"strings"
)

var oidPattern = regexp.MustCompile(`^\.?\d+(?:\.\d+)*$`)

func ValidateQuery(req *QueryRequest, cfg Config) error {
	if len(req.Requests) == 0 {
		return fmt.Errorf("requests must contain at least one item")
	}
	if len(req.Requests) > cfg.MaxTargetsPerQuery {
		return fmt.Errorf("requests exceeds maximum target count")
	}
	for i := range req.Requests {
		tr := &req.Requests[i]
		if strings.TrimSpace(tr.Target) == "" {
			return fmt.Errorf("requests[%d].target must not be empty", i)
		}
		if tr.Port == 0 {
			tr.Port = 161
		}
		if tr.Port < 1 || tr.Port > 65535 {
			return fmt.Errorf("requests[%d].port must be between 1 and 65535", i)
		}
		if tr.Version == "" {
			tr.Version = "2c"
		}
		if tr.Version != "2c" {
			return fmt.Errorf("requests[%d].version must be 2c", i)
		}
		if tr.Community == "" {
			return fmt.Errorf("requests[%d].community must not be empty", i)
		}
		if tr.TimeoutMS < 0 {
			return fmt.Errorf("requests[%d].timeout_ms must be greater than 0", i)
		}
		if tr.TimeoutMS == 0 {
			tr.TimeoutMS = int(cfg.DefaultSNMPTimeout.Milliseconds())
		}
		if tr.Retries == nil {
			v := cfg.DefaultSNMPRetries
			tr.Retries = &v
		}
		if *tr.Retries < 0 {
			return fmt.Errorf("requests[%d].retries must be >= 0", i)
		}
		if len(tr.Operations) == 0 {
			return fmt.Errorf("requests[%d].operations must contain at least one item", i)
		}
		if len(tr.Operations) > cfg.MaxOperationsPerTarget {
			return fmt.Errorf("requests[%d].operations exceeds maximum count", i)
		}
		for j := range tr.Operations {
			if err := validateOperation(&tr.Operations[j], cfg); err != nil {
				return fmt.Errorf("requests[%d].operations[%d]: %w", i, j, err)
			}
		}
	}
	return nil
}

func validateOperation(op *Operation, cfg Config) error {
	switch op.Type {
	case "get", "getnext":
		if op.RootOID != "" || op.NonRepeaters != nil || op.MaxRepetitions != nil {
			return fmt.Errorf("unexpected fields for %s", op.Type)
		}
		return validateOIDs(op.OIDs, cfg)
	case "getbulk":
		if op.RootOID != "" {
			return fmt.Errorf("unexpected root_oid for getbulk")
		}
		if err := validateOIDs(op.OIDs, cfg); err != nil {
			return err
		}
		if op.MaxRepetitions == nil {
			v := uint32(10)
			op.MaxRepetitions = &v
		}
		if *op.MaxRepetitions == 0 {
			return fmt.Errorf("max_repetitions must be > 0")
		}
		return nil
	case "walk":
		if len(op.OIDs) > 0 || op.NonRepeaters != nil || op.MaxRepetitions != nil {
			return fmt.Errorf("unexpected fields for walk")
		}
		if !validOID(op.RootOID) {
			return fmt.Errorf("root_oid must be a valid numeric OID")
		}
		op.RootOID = NormalizeOID(op.RootOID)
		return nil
	default:
		return fmt.Errorf("unknown operation type %q", op.Type)
	}
}

func validateOIDs(oids []string, cfg Config) error {
	if len(oids) == 0 {
		return fmt.Errorf("oids must contain at least one item")
	}
	if len(oids) > cfg.MaxOIDsPerOperation {
		return fmt.Errorf("oids exceeds maximum count")
	}
	for i, oid := range oids {
		if !validOID(oid) {
			return fmt.Errorf("oids[%d] must be a valid numeric OID", i)
		}
		oids[i] = NormalizeOID(oid)
	}
	return nil
}

func validOID(v string) bool {
	return oidPattern.MatchString(v)
}

func NormalizeOID(v string) string {
	if strings.HasPrefix(v, ".") {
		return v
	}
	return "." + v
}
