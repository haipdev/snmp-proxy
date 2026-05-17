package gateway

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	TLSEnabled              bool
	ListenAddress           string
	TLSCertPath             string
	TLSKeyPath              string
	TLSHosts                []string
	BasicAuthUsername       string
	BasicAuthPassword       string
	LogDebugTargets         []string
	LogDebugRequests        bool
	DefaultSNMPTimeout      time.Duration
	DefaultSNMPRetries      int
	MaxParallelTargets      int
	MaxTargetsPerQuery      int
	MaxOperationsPerTarget  int
	MaxOIDsPerOperation     int
	MaxVarbindsPerOperation int
	RequestBodyLimitBytes   int64
	RequestStatsInterval    time.Duration
	LogLevel                string
	ReadHeaderTimeout       time.Duration
	ReadTimeout             time.Duration
	WriteTimeout            time.Duration
	IdleTimeout             time.Duration
	ShutdownTimeout         time.Duration
	TrapEnabled             bool
	TrapListenAddress       string
	TrapAllowedCommunities  []string
	TrapRoutesFile          string
	TrapDefaultTargetURL    string
	TrapForwardAuthHeader   string
	TrapForwardTimeout      time.Duration
	TrapForwardRetries      int
	TrapForwardQueueSize    int
	TrapForwardWorkers      int
	TrapMaxPacketBytes      int
}

func DefaultConfig() Config {
	return Config{
		TLSEnabled:              true,
		ListenAddress:           ":8443",
		TLSCertPath:             "certs/server.crt",
		TLSKeyPath:              "certs/server.key",
		TLSHosts:                []string{"localhost", "127.0.0.1"},
		DefaultSNMPTimeout:      3 * time.Second,
		DefaultSNMPRetries:      1,
		MaxParallelTargets:      8,
		MaxTargetsPerQuery:      64,
		MaxOperationsPerTarget:  32,
		MaxOIDsPerOperation:     128,
		MaxVarbindsPerOperation: 10000,
		RequestBodyLimitBytes:   1048576,
		RequestStatsInterval:    time.Minute,
		LogLevel:                "info",
		ReadHeaderTimeout:       5 * time.Second,
		ReadTimeout:             15 * time.Second,
		WriteTimeout:            30 * time.Second,
		IdleTimeout:             60 * time.Second,
		ShutdownTimeout:         10 * time.Second,
		TrapListenAddress:       ":9162",
		TrapForwardTimeout:      5 * time.Second,
		TrapForwardRetries:      3,
		TrapForwardQueueSize:    1024,
		TrapForwardWorkers:      4,
		TrapMaxPacketBytes:      65535,
	}
}

func LoadConfig(args []string, getenv func(string) string) (Config, error) {
	cfg := DefaultConfig()
	if err := applyEnv(&cfg, getenv); err != nil {
		return Config{}, err
	}

	fs := flag.NewFlagSet("snmp-proxy", flag.ContinueOnError)
	fs.BoolVar(&cfg.TLSEnabled, "tls-enabled", cfg.TLSEnabled, "enable TLS")
	fs.StringVar(&cfg.ListenAddress, "listen-address", cfg.ListenAddress, "listen address")
	fs.StringVar(&cfg.TLSCertPath, "tls-cert-path", cfg.TLSCertPath, "TLS certificate path")
	fs.StringVar(&cfg.TLSKeyPath, "tls-key-path", cfg.TLSKeyPath, "TLS key path")
	tlsHosts := strings.Join(cfg.TLSHosts, ",")
	debugTargets := strings.Join(cfg.LogDebugTargets, ",")
	trapCommunities := strings.Join(cfg.TrapAllowedCommunities, ",")
	fs.StringVar(&tlsHosts, "tls-hosts", tlsHosts, "comma-separated certificate SANs")
	fs.StringVar(&cfg.BasicAuthUsername, "basic-auth-username", cfg.BasicAuthUsername, "basic auth username")
	fs.StringVar(&cfg.BasicAuthPassword, "basic-auth-password", cfg.BasicAuthPassword, "basic auth password")
	fs.StringVar(&debugTargets, "log-debug-targets", debugTargets, "comma-separated debug targets")
	fs.BoolVar(&cfg.LogDebugRequests, "log-debug-requests", cfg.LogDebugRequests, "enable sanitized debug request logs")
	fs.DurationVar(&cfg.DefaultSNMPTimeout, "default-snmp-timeout", cfg.DefaultSNMPTimeout, "default SNMP timeout")
	fs.IntVar(&cfg.DefaultSNMPRetries, "default-snmp-retries", cfg.DefaultSNMPRetries, "default SNMP retries")
	fs.IntVar(&cfg.MaxParallelTargets, "max-parallel-targets", cfg.MaxParallelTargets, "max parallel targets per request")
	fs.IntVar(&cfg.MaxTargetsPerQuery, "max-targets-per-query", cfg.MaxTargetsPerQuery, "max targets per query")
	fs.IntVar(&cfg.MaxOperationsPerTarget, "max-operations-per-target", cfg.MaxOperationsPerTarget, "max operations per target")
	fs.IntVar(&cfg.MaxOIDsPerOperation, "max-oids-per-operation", cfg.MaxOIDsPerOperation, "max OIDs per operation")
	fs.IntVar(&cfg.MaxVarbindsPerOperation, "max-varbinds-per-operation", cfg.MaxVarbindsPerOperation, "max varbinds per operation")
	fs.Int64Var(&cfg.RequestBodyLimitBytes, "request-body-limit-bytes", cfg.RequestBodyLimitBytes, "request body size limit")
	fs.DurationVar(&cfg.RequestStatsInterval, "request-stats-interval", cfg.RequestStatsInterval, "request stats interval")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level")
	fs.DurationVar(&cfg.ReadHeaderTimeout, "read-header-timeout", cfg.ReadHeaderTimeout, "HTTP read header timeout")
	fs.DurationVar(&cfg.ReadTimeout, "read-timeout", cfg.ReadTimeout, "HTTP read timeout")
	fs.DurationVar(&cfg.WriteTimeout, "write-timeout", cfg.WriteTimeout, "HTTP write timeout")
	fs.DurationVar(&cfg.IdleTimeout, "idle-timeout", cfg.IdleTimeout, "HTTP idle timeout")
	fs.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", cfg.ShutdownTimeout, "shutdown timeout")
	fs.BoolVar(&cfg.TrapEnabled, "trap-enabled", cfg.TrapEnabled, "enable SNMP trap forwarding")
	fs.StringVar(&cfg.TrapListenAddress, "trap-listen-address", cfg.TrapListenAddress, "trap UDP listen address")
	fs.StringVar(&trapCommunities, "trap-allowed-communities", trapCommunities, "comma-separated allowed trap communities")
	fs.StringVar(&cfg.TrapRoutesFile, "trap-routes-file", cfg.TrapRoutesFile, "trap routes JSON file")
	fs.StringVar(&cfg.TrapDefaultTargetURL, "trap-default-target-url", cfg.TrapDefaultTargetURL, "default trap webhook URL")
	fs.StringVar(&cfg.TrapForwardAuthHeader, "trap-forward-auth-header", cfg.TrapForwardAuthHeader, "trap webhook authorization header value")
	fs.DurationVar(&cfg.TrapForwardTimeout, "trap-forward-timeout", cfg.TrapForwardTimeout, "trap webhook timeout")
	fs.IntVar(&cfg.TrapForwardRetries, "trap-forward-retries", cfg.TrapForwardRetries, "trap webhook retries")
	fs.IntVar(&cfg.TrapForwardQueueSize, "trap-forward-queue-size", cfg.TrapForwardQueueSize, "trap forward queue size")
	fs.IntVar(&cfg.TrapForwardWorkers, "trap-forward-workers", cfg.TrapForwardWorkers, "trap forward workers")
	fs.IntVar(&cfg.TrapMaxPacketBytes, "trap-max-packet-bytes", cfg.TrapMaxPacketBytes, "max trap packet bytes")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg.TLSHosts = splitCSV(tlsHosts)
	cfg.LogDebugTargets = splitCSV(debugTargets)
	cfg.TrapAllowedCommunities = splitCSV(trapCommunities)
	if !cfg.TLSEnabled && cfg.ListenAddress == ":8443" {
		cfg.ListenAddress = ":8080"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config, getenv func(string) string) error {
	var err error
	if v := getenv("SNMP_PROXY_TLS_ENABLED"); v != "" {
		if cfg.TLSEnabled, err = strconv.ParseBool(v); err != nil {
			return fmt.Errorf("invalid SNMP_PROXY_TLS_ENABLED: %w", err)
		}
	}
	if v := getenv("SNMP_PROXY_LISTEN_ADDRESS"); v != "" {
		cfg.ListenAddress = v
	}
	if v := getenv("SNMP_PROXY_TLS_CERT_PATH"); v != "" {
		cfg.TLSCertPath = v
	}
	if v := getenv("SNMP_PROXY_TLS_KEY_PATH"); v != "" {
		cfg.TLSKeyPath = v
	}
	if v := getenv("SNMP_PROXY_TLS_HOSTS"); v != "" {
		cfg.TLSHosts = splitCSV(v)
	}
	if v := getenv("SNMP_PROXY_BASIC_AUTH_USERNAME"); v != "" {
		cfg.BasicAuthUsername = v
	}
	if v := getenv("SNMP_PROXY_BASIC_AUTH_PASSWORD"); v != "" {
		cfg.BasicAuthPassword = v
	}
	if v := getenv("SNMP_PROXY_LOG_DEBUG_TARGETS"); v != "" {
		cfg.LogDebugTargets = splitCSV(v)
	}
	if v := getenv("SNMP_PROXY_LOG_DEBUG_REQUESTS"); v != "" {
		if cfg.LogDebugRequests, err = strconv.ParseBool(v); err != nil {
			return fmt.Errorf("invalid SNMP_PROXY_LOG_DEBUG_REQUESTS: %w", err)
		}
	}
	if v := getenv("SNMP_PROXY_TRAP_ENABLED"); v != "" {
		if cfg.TrapEnabled, err = strconv.ParseBool(v); err != nil {
			return fmt.Errorf("invalid SNMP_PROXY_TRAP_ENABLED: %w", err)
		}
	}
	if v := getenv("SNMP_PROXY_TRAP_LISTEN_ADDRESS"); v != "" {
		cfg.TrapListenAddress = v
	}
	if v := getenv("SNMP_PROXY_TRAP_ALLOWED_COMMUNITIES"); v != "" {
		cfg.TrapAllowedCommunities = splitCSV(v)
	}
	if v := getenv("SNMP_PROXY_TRAP_ROUTES_FILE"); v != "" {
		cfg.TrapRoutesFile = v
	}
	if v := getenv("SNMP_PROXY_TRAP_DEFAULT_TARGET_URL"); v != "" {
		cfg.TrapDefaultTargetURL = v
	}
	if v := getenv("SNMP_PROXY_TRAP_FORWARD_AUTH_HEADER"); v != "" {
		cfg.TrapForwardAuthHeader = v
	}
	durationVars := map[string]*time.Duration{
		"SNMP_PROXY_DEFAULT_SNMP_TIMEOUT":   &cfg.DefaultSNMPTimeout,
		"SNMP_PROXY_REQUEST_STATS_INTERVAL": &cfg.RequestStatsInterval,
		"SNMP_PROXY_READ_HEADER_TIMEOUT":    &cfg.ReadHeaderTimeout,
		"SNMP_PROXY_READ_TIMEOUT":           &cfg.ReadTimeout,
		"SNMP_PROXY_WRITE_TIMEOUT":          &cfg.WriteTimeout,
		"SNMP_PROXY_IDLE_TIMEOUT":           &cfg.IdleTimeout,
		"SNMP_PROXY_SHUTDOWN_TIMEOUT":       &cfg.ShutdownTimeout,
		"SNMP_PROXY_TRAP_FORWARD_TIMEOUT":   &cfg.TrapForwardTimeout,
	}
	for key, target := range durationVars {
		if v := getenv(key); v != "" {
			if *target, err = time.ParseDuration(v); err != nil {
				return fmt.Errorf("invalid %s: %w", key, err)
			}
		}
	}
	intVars := map[string]*int{
		"SNMP_PROXY_DEFAULT_SNMP_RETRIES":       &cfg.DefaultSNMPRetries,
		"SNMP_PROXY_MAX_PARALLEL_TARGETS":       &cfg.MaxParallelTargets,
		"SNMP_PROXY_MAX_TARGETS_PER_QUERY":      &cfg.MaxTargetsPerQuery,
		"SNMP_PROXY_MAX_OPERATIONS_PER_TARGET":  &cfg.MaxOperationsPerTarget,
		"SNMP_PROXY_MAX_OIDS_PER_OPERATION":     &cfg.MaxOIDsPerOperation,
		"SNMP_PROXY_MAX_VARBINDS_PER_OPERATION": &cfg.MaxVarbindsPerOperation,
		"SNMP_PROXY_TRAP_FORWARD_RETRIES":       &cfg.TrapForwardRetries,
		"SNMP_PROXY_TRAP_FORWARD_QUEUE_SIZE":    &cfg.TrapForwardQueueSize,
		"SNMP_PROXY_TRAP_FORWARD_WORKERS":       &cfg.TrapForwardWorkers,
		"SNMP_PROXY_TRAP_MAX_PACKET_BYTES":      &cfg.TrapMaxPacketBytes,
	}
	for key, target := range intVars {
		if v := getenv(key); v != "" {
			if *target, err = strconv.Atoi(v); err != nil {
				return fmt.Errorf("invalid %s: %w", key, err)
			}
		}
	}
	if v := getenv("SNMP_PROXY_REQUEST_BODY_LIMIT_BYTES"); v != "" {
		if cfg.RequestBodyLimitBytes, err = strconv.ParseInt(v, 10, 64); err != nil {
			return fmt.Errorf("invalid SNMP_PROXY_REQUEST_BODY_LIMIT_BYTES: %w", err)
		}
	}
	if v := getenv("SNMP_PROXY_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if !cfg.TLSEnabled && cfg.ListenAddress == ":8443" {
		cfg.ListenAddress = ":8080"
	}
	return nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.ListenAddress) == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if strings.TrimSpace(c.BasicAuthUsername) == "" || strings.TrimSpace(c.BasicAuthPassword) == "" {
		return fmt.Errorf("basic auth username and password are required")
	}
	if c.DefaultSNMPTimeout <= 0 || c.DefaultSNMPRetries < 0 ||
		c.MaxParallelTargets <= 0 || c.MaxTargetsPerQuery <= 0 ||
		c.MaxOperationsPerTarget <= 0 || c.MaxOIDsPerOperation <= 0 ||
		c.MaxVarbindsPerOperation <= 0 || c.RequestBodyLimitBytes <= 0 ||
		c.RequestStatsInterval < 0 || c.ReadHeaderTimeout <= 0 ||
		c.ReadTimeout <= 0 || c.WriteTimeout <= 0 || c.IdleTimeout <= 0 ||
		c.ShutdownTimeout <= 0 || c.TrapForwardTimeout <= 0 ||
		c.TrapForwardRetries < 0 || c.TrapForwardQueueSize <= 0 ||
		c.TrapForwardWorkers <= 0 || c.TrapMaxPacketBytes <= 0 {
		return fmt.Errorf("configuration numeric limits must be positive")
	}
	if c.TrapEnabled && strings.TrimSpace(c.TrapListenAddress) == "" {
		return fmt.Errorf("trap listen address must not be empty")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported log level %q", c.LogLevel)
	}
	return nil
}

func splitCSV(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
