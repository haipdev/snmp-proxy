package gateway

type QueryRequest struct {
	Requests []TargetRequest `json:"requests"`
}

type TargetRequest struct {
	Target     string      `json:"target"`
	Port       int         `json:"port,omitempty"`
	Version    string      `json:"version,omitempty"`
	Community  string      `json:"community"`
	TimeoutMS  int         `json:"timeout_ms,omitempty"`
	Retries    *int        `json:"retries,omitempty"`
	Operations []Operation `json:"operations"`
}

type Operation struct {
	Type           string   `json:"type"`
	OIDs           []string `json:"oids,omitempty"`
	NonRepeaters   *uint8   `json:"non_repeaters,omitempty"`
	MaxRepetitions *uint32  `json:"max_repetitions,omitempty"`
	RootOID        string   `json:"root_oid,omitempty"`
}

type QueryResponse struct {
	Results []TargetResult `json:"results"`
}

type TargetResult struct {
	Target     string            `json:"target"`
	Port       int               `json:"port"`
	Operations []OperationResult `json:"operations"`
}

type OperationResult struct {
	Type   string    `json:"type"`
	Status string    `json:"status"`
	Values []VarBind `json:"values,omitempty"`
	Error  *APIError `json:"error,omitempty"`
}

type VarBind struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ErrorEnvelope struct {
	Error APIError `json:"error"`
}
