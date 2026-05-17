package gateway

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestNewGoSNMPClientBuildsV3Session(t *testing.T) {
	retries := 2
	client := newGoSNMPClient(TargetRequest{
		Target:    "127.0.0.1",
		Port:      161,
		Version:   "3",
		TimeoutMS: 5000,
		Retries:   &retries,
		V3: &V3Credentials{
			Username:       "monitor",
			SecurityLevel:  "authPriv",
			AuthProtocol:   "sha256",
			AuthPassphrase: "auth-secret",
			PrivProtocol:   "aes",
			PrivPassphrase: "priv-secret",
			ContextName:    "ops",
		},
	})

	if client.Version != gosnmp.Version3 || client.SecurityModel != gosnmp.UserSecurityModel || client.MsgFlags != gosnmp.AuthPriv {
		t.Fatalf("unexpected v3 client setup: %+v", client)
	}
	params, ok := client.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		t.Fatalf("security parameters type = %T", client.SecurityParameters)
	}
	if params.UserName != "monitor" || params.AuthenticationProtocol != gosnmp.SHA256 || params.PrivacyProtocol != gosnmp.AES {
		t.Fatalf("unexpected v3 credentials: %+v", params)
	}
	if client.ContextName != "ops" {
		t.Fatalf("context name = %q", client.ContextName)
	}
}
