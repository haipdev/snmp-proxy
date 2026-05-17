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
		switch tr.Version {
		case "2c":
			if tr.Community == "" {
				return fmt.Errorf("requests[%d].community must not be empty", i)
			}
			if tr.V3 != nil {
				return fmt.Errorf("requests[%d].v3 is only valid for version 3", i)
			}
		case "3":
			if tr.Community != "" {
				return fmt.Errorf("requests[%d].community is only valid for version 2c", i)
			}
			if err := validateV3Credentials(tr.V3); err != nil {
				return fmt.Errorf("requests[%d].v3: %w", i, err)
			}
		default:
			return fmt.Errorf("requests[%d].version must be 2c or 3", i)
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

func validateV3Credentials(v3 *V3Credentials) error {
	if v3 == nil {
		return fmt.Errorf("must be provided for version 3")
	}
	if strings.TrimSpace(v3.Username) == "" {
		return fmt.Errorf("username must not be empty")
	}
	switch v3.SecurityLevel {
	case "noAuthNoPriv":
		if v3.AuthProtocol != "" || v3.AuthPassphrase != "" || v3.PrivProtocol != "" || v3.PrivPassphrase != "" {
			return fmt.Errorf("authentication and privacy fields are not valid for noAuthNoPriv")
		}
	case "authNoPriv":
		if !validAuthProtocol(v3.AuthProtocol) {
			return fmt.Errorf("auth_protocol must be one of md5, sha, sha224, sha256, sha384, sha512")
		}
		if v3.AuthPassphrase == "" {
			return fmt.Errorf("auth_passphrase must not be empty")
		}
		if v3.PrivProtocol != "" || v3.PrivPassphrase != "" {
			return fmt.Errorf("privacy fields are only valid for authPriv")
		}
	case "authPriv":
		if !validAuthProtocol(v3.AuthProtocol) {
			return fmt.Errorf("auth_protocol must be one of md5, sha, sha224, sha256, sha384, sha512")
		}
		if v3.AuthPassphrase == "" {
			return fmt.Errorf("auth_passphrase must not be empty")
		}
		if !validPrivProtocol(v3.PrivProtocol) {
			return fmt.Errorf("priv_protocol must be one of des, aes, aes192, aes256, aes192c, aes256c")
		}
		if v3.PrivPassphrase == "" {
			return fmt.Errorf("priv_passphrase must not be empty")
		}
	default:
		return fmt.Errorf("security_level must be one of noAuthNoPriv, authNoPriv, authPriv")
	}
	return nil
}

func validAuthProtocol(v string) bool {
	switch v {
	case "md5", "sha", "sha224", "sha256", "sha384", "sha512":
		return true
	default:
		return false
	}
}

func validPrivProtocol(v string) bool {
	switch v {
	case "des", "aes", "aes192", "aes256", "aes192c", "aes256c":
		return true
	default:
		return false
	}
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
