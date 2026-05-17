package gateway

import "testing"

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.BasicAuthUsername = "user"
	cfg.BasicAuthPassword = "pass"
	return cfg
}

func TestValidateQueryNormalizesAndDefaults(t *testing.T) {
	req := QueryRequest{Requests: []TargetRequest{{
		Target:     "127.0.0.1",
		Community:  "public",
		Operations: []Operation{{Type: "getbulk", OIDs: []string{"1.3.6.1.2.1.1.1"}}},
	}}}
	if err := ValidateQuery(&req, testConfig()); err != nil {
		t.Fatal(err)
	}
	got := req.Requests[0]
	if got.Port != 161 || got.Version != "2c" || got.TimeoutMS != 3000 || got.Retries == nil || *got.Retries != 1 {
		t.Fatalf("defaults not applied: %+v", got)
	}
	if got.Operations[0].OIDs[0] != ".1.3.6.1.2.1.1.1" || got.Operations[0].MaxRepetitions == nil || *got.Operations[0].MaxRepetitions != 10 {
		t.Fatalf("operation not normalized: %+v", got.Operations[0])
	}
}

func TestValidateQueryRejectsUnexpectedFields(t *testing.T) {
	req := QueryRequest{Requests: []TargetRequest{{
		Target:     "127.0.0.1",
		Community:  "public",
		Operations: []Operation{{Type: "walk", RootOID: ".1.3.6", OIDs: []string{".1.3"}}},
	}}}
	if err := ValidateQuery(&req, testConfig()); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateQueryAcceptsV3AuthPriv(t *testing.T) {
	req := QueryRequest{Requests: []TargetRequest{{
		Target:  "127.0.0.1",
		Version: "3",
		V3: &V3Credentials{
			Username:       "monitor",
			SecurityLevel:  "authPriv",
			AuthProtocol:   "sha256",
			AuthPassphrase: "auth-secret",
			PrivProtocol:   "aes",
			PrivPassphrase: "priv-secret",
		},
		Operations: []Operation{{Type: "get", OIDs: []string{".1.3.6"}}},
	}}}
	if err := ValidateQuery(&req, testConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateQueryAcceptsV1(t *testing.T) {
	req := QueryRequest{Requests: []TargetRequest{{
		Target:     "127.0.0.1",
		Version:    "1",
		Community:  "public",
		Operations: []Operation{{Type: "getnext", OIDs: []string{".1.3.6"}}},
	}}}
	if err := ValidateQuery(&req, testConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateQueryRejectsV1GetBulk(t *testing.T) {
	req := QueryRequest{Requests: []TargetRequest{{
		Target:     "127.0.0.1",
		Version:    "1",
		Community:  "public",
		Operations: []Operation{{Type: "getbulk", OIDs: []string{".1.3.6"}}},
	}}}
	if err := ValidateQuery(&req, testConfig()); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateQueryRejectsInvalidV3Combination(t *testing.T) {
	req := QueryRequest{Requests: []TargetRequest{{
		Target:  "127.0.0.1",
		Version: "3",
		V3: &V3Credentials{
			Username:      "monitor",
			SecurityLevel: "authNoPriv",
			AuthProtocol:  "sha",
		},
		Operations: []Operation{{Type: "get", OIDs: []string{".1.3.6"}}},
	}}}
	if err := ValidateQuery(&req, testConfig()); err == nil {
		t.Fatal("expected validation error")
	}
}
