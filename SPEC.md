# snmp-proxy Application Specification

## 1. Purpose

`snmp-proxy` is a stateless network service that exposes a small authenticated HTTP(S) API for executing SNMP v2c read operations against one or more network targets and can receive SNMP v2c traps for forwarding to downstream HTTP(S) services.

The service exists to:

- provide a simple JSON interface for systems that cannot or should not speak SNMP directly;
- execute multiple SNMP operations in one client request;
- receive SNMP traps from network devices and forward normalized JSON events to downstream systems;
- choose the forwarding destination dynamically from the trap sender's source IP;
- preserve target-level and operation-level visibility when some work succeeds and some work fails;
- remain safe to operate in production through bounded concurrency, structured logs, explicit timeouts, and conservative defaults.

## 2. Product Goals

1. Accept JSON query requests over HTTPS by default.
2. Support SNMP v2c `get`, `getnext`, `getbulk`, and `walk`.
3. Allow a single API request to contain multiple targets and multiple ordered operations per target.
4. Return structured results for every accepted target request and operation whenever execution is possible.
5. Receive SNMP v2c traps and forward them as normalized JSON over HTTP(S).
6. Select trap forwarding destinations from source-IP CIDR routing rules.
7. Avoid leaking SNMP communities, HTTP basic-auth credentials, webhook credentials, or TLS private-key material through logs or API responses.
8. Be easy to run locally and predictable to deploy in containers.

## 3. Non-Goals

The initial release does not include:

- SNMP v1 or v3 support;
- SNMP write operations such as `set`;
- SNMP inform support;
- target inventories, scheduling, persistence, historical storage, or dashboards;
- durable trap queues, replay after restart, trap correlation, trap enrichment, or alerting;
- multi-destination trap fan-out or routing rules beyond source-IP CIDR matching;
- multi-tenant authorization, RBAC, or user management;
- certificate issuance or renewal beyond bootstrap self-signed development certificates;
- distributed rate limiting or cross-instance coordination.

## 4. Actors

- **API client**: authenticated system that submits SNMP query requests.
- **Health checker**: unauthenticated runtime or load-balancer probe using `/healthz`.
- **Operator**: configures, deploys, observes, and troubleshoots the service.
- **SNMP target**: remote device or simulator queried by the proxy.
- **Trap sender**: network device that emits SNMP traps to the proxy.
- **Webhook receiver**: downstream HTTP(S) service that receives forwarded trap events.

## 5. High-Level Behavior

1. The service starts from environment variables and command-line flags.
2. HTTPS is enabled by default. If TLS is enabled and both configured certificate files are absent, the service generates a self-signed development certificate and key.
3. API clients authenticate using HTTP Basic Authentication on every endpoint except `/healthz`.
4. A client sends `POST /api/v1/query` with one or more target requests.
5. The proxy validates the full request before starting SNMP work.
6. Accepted target requests execute concurrently up to the configured per-request target limit.
7. Operations for a single target execute in request order.
8. Each operation produces its own success or error result.
9. The response includes all target results in the same order as the input request array.
10. If trap handling is enabled, the service listens for SNMP v2c traps on the configured UDP address.
11. Each received trap is decoded, matched against source-IP CIDR routes, normalized to JSON, and forwarded to the selected HTTP(S) target.
12. The service emits structured logs and periodic aggregate request and trap-forwarding statistics while excluding secrets.

## 6. API

### 6.1 Endpoints

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | `/healthz` | No | Liveness/readiness probe |
| `GET` | `/version` | Yes | Build and version metadata |
| `POST` | `/api/v1/query` | Yes | Execute SNMP queries |

All non-matching routes return `404 Not Found`.

### 6.2 Common HTTP Requirements

- Request and response bodies use `application/json` unless the endpoint has no body.
- Request body size is limited by `SNMP_PROXY_REQUEST_BODY_LIMIT_BYTES`.
- Responses include `X-Request-ID`.
- If the client provides a valid `X-Request-ID`, the service reuses it; otherwise it generates one.
- JSON decode errors and validation errors are client errors and must not start SNMP work.
- Error responses use a consistent envelope:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "requests must contain at least one item"
  }
}
```

### 6.3 Status Codes

| Condition | Status |
| --- | --- |
| Healthy process | `200 OK` |
| Successful version response | `200 OK` |
| Valid query request, including partial or total SNMP execution failures | `200 OK` |
| Missing or invalid authentication | `401 Unauthorized` |
| Wrong HTTP method | `405 Method Not Allowed` |
| Unsupported `Content-Type` for query endpoint | `415 Unsupported Media Type` |
| Body too large | `413 Payload Too Large` |
| Malformed JSON or semantically invalid request | `400 Bad Request` |
| Unexpected internal failure before a valid query can be represented | `500 Internal Server Error` |

SNMP target failures are represented inside the query response body and are not converted into transport-level HTTP failures.

### 6.4 `GET /healthz`

Response:

```json
{
  "status": "ok"
}
```

Requirements:

- unauthenticated;
- returns `200 OK` when the process is able to serve HTTP requests;
- does not perform downstream SNMP checks.

### 6.5 `GET /version`

Response:

```json
{
  "version": "v1.2.3",
  "commit": "abcdef0",
  "build_time": "2026-05-17T12:34:56Z"
}
```

Requirements:

- authenticated;
- fields may use `"unknown"` when build metadata is unavailable;
- must not expose configuration secrets.

### 6.6 `POST /api/v1/query`

#### Request schema

```json
{
  "requests": [
    {
      "target": "192.0.2.10",
      "port": 161,
      "version": "2c",
      "community": "public",
      "timeout_ms": 3000,
      "retries": 1,
      "operations": [
        {
          "type": "get",
          "oids": [".1.3.6.1.2.1.1.3.0"]
        }
      ]
    }
  ]
}
```

#### Target request fields

| Field | Required | Rules | Default |
| --- | --- | --- | --- |
| `target` | Yes | Non-empty hostname or IP literal | none |
| `port` | No | Integer `1..65535` | `161` |
| `version` | No | Must be `"2c"` if present | `"2c"` |
| `community` | Yes | Non-empty string | none |
| `timeout_ms` | No | Integer greater than `0` | configured default timeout |
| `retries` | No | Integer `>= 0` | configured default retries |
| `operations` | Yes | Non-empty array | none |

The request is additionally bounded by configurable service limits:

- maximum target requests per query;
- maximum operations per target request;
- maximum OIDs per non-walk operation;
- maximum returned varbinds per operation.

#### Operation schemas

`get`

```json
{
  "type": "get",
  "oids": [".1.3.6.1.2.1.1.3.0"]
}
```

`getnext`

```json
{
  "type": "getnext",
  "oids": [".1.3.6.1.2.1.1.1"]
}
```

`getbulk`

```json
{
  "type": "getbulk",
  "oids": [".1.3.6.1.2.1.1.1"],
  "non_repeaters": 0,
  "max_repetitions": 10
}
```

`walk`

```json
{
  "type": "walk",
  "root_oid": ".1.3.6.1.2.1.2.2"
}
```

#### Operation validation

| Operation | Required fields | Rules |
| --- | --- | --- |
| `get` | `oids` | non-empty array of valid numeric OIDs |
| `getnext` | `oids` | non-empty array of valid numeric OIDs |
| `getbulk` | `oids` | non-empty array of valid numeric OIDs; `non_repeaters >= 0`; `max_repetitions > 0` |
| `walk` | `root_oid` | valid numeric OID |

Additional rules:

- OIDs may include a leading dot in input.
- Responses normalize OIDs to a leading-dot canonical form.
- Unknown operation types are rejected.
- Fields that do not apply to the operation type are rejected to catch client mistakes early.
- If `getbulk.max_repetitions` is omitted, it defaults to `10`.

#### Query response schema

```json
{
  "results": [
    {
      "target": "192.0.2.10",
      "port": 161,
      "operations": [
        {
          "type": "get",
          "status": "ok",
          "values": [
            {
              "oid": ".1.3.6.1.2.1.1.3.0",
              "type": "TimeTicks",
              "value": 12345
            }
          ]
        },
        {
          "type": "walk",
          "status": "error",
          "error": {
            "code": "timeout",
            "message": "request timeout"
          }
        }
      ]
    }
  ]
}
```

#### Response requirements

- `results` preserve the order of the input `requests`.
- `operations` preserve the order of the input `operations`.
- Each operation result includes:
  - `type`;
  - `status`, either `"ok"` or `"error"`;
  - `values` only when successful;
  - `error` only when unsuccessful.
- A target-level connectivity failure does not remove that target from `results`; each requested operation for that target receives an error result.
- A failed operation does not prevent later operations for the same target from being attempted unless the underlying target session cannot be established at all.
- SNMP values must preserve useful type information. The implementation should expose a stable type name and a JSON-compatible value.
- Error messages returned to clients must be sanitized and must not include community strings or credentials.

#### Standard operation error codes

At minimum:

- `timeout`
- `dns_error`
- `connection_error`
- `unsupported_version`
- `snmp_error`
- `decode_error`
- `result_limit_exceeded`
- `internal_error`

## 7. Trap Ingestion and Forwarding

### 7.1 Trap listener

- Trap handling is disabled by default unless `SNMP_PROXY_TRAP_ENABLED=true`.
- When enabled, the service listens for SNMP v2c traps on the configured UDP address.
- Only SNMP v2c traps are supported in the initial release.
- Trap communities may be restricted by an optional configured allowlist.
- A malformed, unsupported, or disallowed trap is rejected before forwarding and is recorded with a sanitized outcome.

### 7.2 Trap routing

- Each accepted trap is routed from the sender's source IP address.
- Routes are configured as source-IP CIDR to target-URL mappings loaded at startup from `SNMP_PROXY_TRAP_ROUTES_FILE`.
- Matching uses longest-prefix wins so a more specific CIDR overrides a broader CIDR.
- Route definitions are evaluated only after startup validation succeeds.
- If no route matches and no default target URL is configured, the trap is not forwarded and is recorded with outcome code `route_not_found`.
- If `SNMP_PROXY_TRAP_DEFAULT_TARGET_URL` is configured, it is used only when no CIDR route matches.
- Invalid CIDRs, non-HTTP(S) target URLs, unreadable route files, or malformed route definitions cause startup failure.

Example route file:

```json
{
  "routes": [
    {
      "source_cidr": "10.0.0.0/8",
      "target_url": "https://ops-a.example.net/traps"
    },
    {
      "source_cidr": "10.1.0.0/16",
      "target_url": "https://ops-b.example.net/traps"
    }
  ]
}
```

### 7.3 Forwarded trap payload

The proxy forwards normalized JSON payloads:

```json
{
  "received_at": "2026-05-17T12:34:56Z",
  "source_ip": "10.1.2.3",
  "source_port": 54321,
  "version": "2c",
  "matched_source_cidr": "10.1.0.0/16",
  "trap_oid": ".1.3.6.1.6.3.1.1.5.3",
  "uptime": 12345,
  "varbinds": [
    {
      "oid": ".1.3.6.1.2.1.1.3.0",
      "type": "TimeTicks",
      "value": 12345
    }
  ]
}
```

Requirements:

- forwarded payloads must not include raw SNMP community strings;
- OIDs use the same normalized leading-dot form as query responses;
- type names and values follow the same stable JSON-compatible encoding policy as query results;
- the target URL is internal routing state and is not included in the forwarded body.

### 7.4 Forwarding behavior

- Trap forwarding is best-effort and in-memory only; the service remains stateless across restarts.
- A trap that has been decoded and routed is submitted to a bounded in-memory forwarding queue.
- Forward workers send HTTP `POST` requests with `application/json` bodies to the matched target URL.
- Any `2xx` response is considered successful.
- Network failures, timeouts, and `5xx` responses are retryable.
- `4xx` responses are not retried except `429 Too Many Requests`.
- Retries use bounded exponential backoff according to configuration.
- When retries are exhausted, or the queue is full, the trap is dropped with a sanitized failure outcome.
- Forwarding shutdown stops accepting new traps, allows queued work to complete until `SNMP_PROXY_SHUTDOWN_TIMEOUT`, then cancels remaining work.

### 7.5 Standard trap outcome codes

At minimum:

- `decoded`
- `unsupported_version`
- `community_rejected`
- `decode_error`
- `route_not_found`
- `queue_full`
- `forward_timeout`
- `forward_connection_error`
- `forward_http_error`
- `forward_internal_error`

## 8. Execution Model

### 8.1 Request lifecycle

1. authenticate request if required;
2. assign request ID;
3. enforce method, content type, and body-size constraints;
4. parse and validate JSON;
5. create a request-scoped execution context;
6. run target requests concurrently with a semaphore bounded by `SNMP_PROXY_MAX_PARALLEL_TARGETS`;
7. execute operations for each target in declared order;
8. collect ordered results;
9. write response and emit logs/metrics.

### 8.2 Timeouts and retries

- Per-target SNMP settings are resolved from the request first, then configuration defaults.
- `timeout_ms` applies to each SNMP request attempt, not to the entire HTTP request.
- Retries mean additional attempts after the initial attempt.
- HTTP server write timeout must be high enough to accommodate expected SNMP execution time; if the configured values make that impossible, startup should log a warning.

### 8.3 Concurrency

- Concurrency is limited per incoming API request, not globally, by `SNMP_PROXY_MAX_PARALLEL_TARGETS`.
- Operations for the same target request are sequential to preserve deterministic order and avoid target-local contention.
- Duplicate target entries are allowed and are treated as independent target requests.

### 8.4 Cancellation and shutdown

- Client disconnects and HTTP request cancellation propagate to in-flight target work.
- Graceful shutdown stops accepting new HTTP connections and trap packets, allows in-flight requests and queued trap forwards to finish until `SNMP_PROXY_SHUTDOWN_TIMEOUT`, then cancels remaining work.

### 8.5 Resource limits

- The service enforces explicit limits before execution so a syntactically valid request cannot consume unbounded work.
- A `walk` operation stops when it reaches `SNMP_PROXY_MAX_VARBINDS_PER_OPERATION`; when truncated by the limit, it returns `status: "error"` with code `result_limit_exceeded`.
- `get`, `getnext`, and `getbulk` must also fail with `result_limit_exceeded` if a response would exceed the configured per-operation varbind limit.
- Limit violations discovered during request validation return `400 Bad Request`.
- Limit violations discovered during SNMP execution are represented as operation errors in the normal `200 OK` query response.

## 9. Security Requirements

### 9.1 Authentication

- HTTP Basic Authentication is mandatory for `/version` and `/api/v1/query`.
- The service must refuse startup when username or password is missing.
- Authentication comparisons should use constant-time comparison.
- Unauthenticated responses must include a `WWW-Authenticate` challenge.

### 9.2 TLS

- TLS is enabled by default.
- If TLS is enabled:
  - both configured certificate and key files present: use them;
  - both absent: generate development certificate and key;
  - only one present: fail startup;
  - unreadable or invalid files: fail startup.
- Generated private keys must use restrictive filesystem permissions.
- Generated certificates are a bootstrap aid only and are not a replacement for managed production certificates.
- When TLS is disabled, certificate configuration is ignored.

### 9.3 Secret handling

The service must never log:

- SNMP community strings;
- HTTP basic-auth usernames or passwords;
- webhook authorization headers or credentials;
- `Authorization` headers;
- TLS private-key contents.

Sanitized request summaries may include target, operation types, OID counts, timing, and outcome counts. Sanitized trap summaries may include source IP, matched CIDR, trap OID, varbind count, timing, and forwarding outcome.

## 10. Logging and Observability

### 10.1 Structured logging

Logs are JSON objects and include, where applicable:

- timestamp;
- level;
- message;
- request ID;
- target;
- source IP;
- matched source CIDR;
- operation type;
- trap OID;
- duration;
- outcome;
- error code.

### 10.2 Default logging policy

- At `info`, successful query requests do not emit per-request logs.
- Failed query requests emit sanitized summaries.
- Aggregated request statistics are emitted every `SNMP_PROXY_REQUEST_STATS_INTERVAL` unless disabled with `0s`.
- Debug target filtering is controlled by `SNMP_PROXY_LOG_DEBUG_TARGETS`.
- Sanitized debug request/response summaries are emitted only when both the target is selected and `SNMP_PROXY_LOG_DEBUG_REQUESTS=true`.
- Successful trap forwards do not emit per-trap logs at `info`.
- Failed trap receives or forwards emit sanitized summaries.

### 10.3 Aggregate statistics

Periodic stats should include at least:

- total query requests;
- successful query requests;
- partially failed query requests;
- fully failed query requests;
- target count;
- operation count;
- operation success count;
- operation failure count;
- latency summary suitable for operations troubleshooting.

Trap-forwarding stats should include at least:

- received trap count;
- decoded trap count;
- rejected trap count;
- matched trap count;
- unmatched trap count;
- queued trap count;
- forwarded trap success count;
- forwarded trap failure count;
- retry count;
- per-route forwarded and failed counts keyed by matched source CIDR;
- forwarding latency summary suitable for operations troubleshooting.

## 11. Configuration

### 11.1 Precedence

1. command-line flags;
2. environment variables;
3. built-in defaults.

### 11.2 Configuration table

| Variable | Default | Requirement |
| --- | --- | --- |
| `SNMP_PROXY_TLS_ENABLED` | `true` | boolean; controls HTTP vs HTTPS independently of port |
| `SNMP_PROXY_LISTEN_ADDRESS` | `:8443` with TLS, else `:8080` | valid listen address |
| `SNMP_PROXY_TLS_CERT_PATH` | `certs/server.crt` | path |
| `SNMP_PROXY_TLS_KEY_PATH` | `certs/server.key` | path |
| `SNMP_PROXY_TLS_HOSTS` | `localhost,127.0.0.1` | comma-separated SAN list |
| `SNMP_PROXY_BASIC_AUTH_USERNAME` | none | required non-empty string |
| `SNMP_PROXY_BASIC_AUTH_PASSWORD` | none | required non-empty string |
| `SNMP_PROXY_LOG_DEBUG_TARGETS` | empty | comma-separated target list |
| `SNMP_PROXY_LOG_DEBUG_REQUESTS` | `false` | boolean |
| `SNMP_PROXY_DEFAULT_SNMP_TIMEOUT` | `3s` | duration greater than `0` |
| `SNMP_PROXY_DEFAULT_SNMP_RETRIES` | `1` | integer `>= 0` |
| `SNMP_PROXY_MAX_PARALLEL_TARGETS` | `8` | integer greater than `0` |
| `SNMP_PROXY_MAX_TARGETS_PER_QUERY` | `64` | integer greater than `0` |
| `SNMP_PROXY_MAX_OPERATIONS_PER_TARGET` | `32` | integer greater than `0` |
| `SNMP_PROXY_MAX_OIDS_PER_OPERATION` | `128` | integer greater than `0` |
| `SNMP_PROXY_MAX_VARBINDS_PER_OPERATION` | `10000` | integer greater than `0` |
| `SNMP_PROXY_REQUEST_BODY_LIMIT_BYTES` | `1048576` | integer greater than `0` |
| `SNMP_PROXY_REQUEST_STATS_INTERVAL` | `1m` | duration `>= 0` |
| `SNMP_PROXY_LOG_LEVEL` | `info` | one of supported log levels |
| `SNMP_PROXY_READ_HEADER_TIMEOUT` | `5s` | duration greater than `0` |
| `SNMP_PROXY_READ_TIMEOUT` | `15s` | duration greater than `0` |
| `SNMP_PROXY_WRITE_TIMEOUT` | `30s` | duration greater than `0` |
| `SNMP_PROXY_IDLE_TIMEOUT` | `60s` | duration greater than `0` |
| `SNMP_PROXY_SHUTDOWN_TIMEOUT` | `10s` | duration greater than `0` |
| `SNMP_PROXY_TRAP_ENABLED` | `false` | boolean |
| `SNMP_PROXY_TRAP_LISTEN_ADDRESS` | `:9162` | valid UDP listen address |
| `SNMP_PROXY_TRAP_ALLOWED_COMMUNITIES` | empty | optional comma-separated allowlist |
| `SNMP_PROXY_TRAP_ROUTES_FILE` | none | required readable JSON file when traps are enabled unless a default target URL is configured |
| `SNMP_PROXY_TRAP_DEFAULT_TARGET_URL` | none | optional HTTP(S) URL used when no CIDR route matches |
| `SNMP_PROXY_TRAP_FORWARD_AUTH_HEADER` | none | optional outbound webhook authorization header value |
| `SNMP_PROXY_TRAP_FORWARD_TIMEOUT` | `5s` | duration greater than `0` |
| `SNMP_PROXY_TRAP_FORWARD_RETRIES` | `3` | integer `>= 0` |
| `SNMP_PROXY_TRAP_FORWARD_QUEUE_SIZE` | `1024` | integer greater than `0` |
| `SNMP_PROXY_TRAP_FORWARD_WORKERS` | `4` | integer greater than `0` |
| `SNMP_PROXY_TRAP_MAX_PACKET_BYTES` | `65535` | integer greater than `0` |

Invalid configuration causes startup failure with a clear error message that does not include secrets.

## 12. Packaging and Runtime

- Implementation language: Go.
- Service shape: single binary.
- Container image: multi-stage Docker build.
- Runtime user in container: non-root.
- Default exposed ports: `8443` for HTTPS API traffic and `9162/udp` for traps when enabled.
- Service is stateless and horizontally scalable behind a load balancer.

## 13. Testing Requirements

### 13.1 Unit tests

Cover at minimum:

- configuration parsing and precedence;
- TLS bootstrap cases;
- authentication middleware;
- request validation;
- OID normalization;
- operation dispatch;
- response ordering;
- partial-failure shaping;
- concurrency limiting;
- configured request and result limits;
- request cancellation;
- log sanitization;
- HTTP status-code mapping;
- trap route-file parsing;
- CIDR matching and longest-prefix selection;
- unmatched trap behavior;
- trap payload normalization;
- trap queue limits and retry classification.

### 13.2 Integration tests

Cover at minimum:

- successful HTTPS startup with generated certs;
- unauthenticated `/healthz`;
- authentication required on protected routes;
- simulator-backed `get`;
- simulator-backed `walk`;
- mixed success and failure response;
- no community-string leakage in logs.
- trap listener startup;
- simulator-backed trap receipt;
- CIDR-routed webhook delivery;
- forwarding retries for transient webhook failures;
- malformed trap rejection;
- no trap community or webhook-secret leakage in logs.

### 13.3 CI/CD

- GitHub Actions runs tests and builds on pull requests and mainline pushes.
- Release workflow runs manually, resolves a semantic version from a selected bump or explicit override, creates the release tag, runs tests, builds images, and publishes GHCR artifacts.

## 14. Acceptance Criteria

The initial implementation is acceptable when:

1. It starts with HTTPS by default and generates usable local bootstrap certificates when both configured files are missing.
2. It refuses to start without configured basic-auth credentials.
3. `/healthz` is unauthenticated and protected endpoints reject missing credentials.
4. A valid query can execute `get`, `getnext`, `getbulk`, and `walk` against SNMP v2c targets.
5. Multiple targets are processed concurrently up to the configured limit.
6. Multiple operations for one target return in request order.
7. Mixed successful and failed operations return `200 OK` with structured per-operation results.
8. Requests and operation results respect configured resource limits.
9. Invalid requests fail before SNMP work begins and produce deterministic client errors.
10. Logs are structured, contain request IDs, and do not leak configured secrets.
11. When trap handling is enabled, the service receives SNMP v2c traps on the configured UDP listener.
12. Trap forwarding destinations are selected from source-IP CIDR routes using longest-prefix wins.
13. Routed traps are forwarded as normalized JSON to the selected HTTP(S) target with configured retries and timeouts.
14. Unmatched, malformed, rejected, dropped, and failed-forward traps are observable through sanitized logs and aggregate statistics.
15. Unit tests, simulator smoke tests, Docker build, and release automation are present and pass.

## 15. Implementation Decisions Inferred from the initial idea.

The following points were implicit in the source idea and are made explicit here so implementation can proceed without avoidable ambiguity:

- query validation is all-or-nothing at the HTTP request boundary;
- target results and operation results preserve input order even though targets run concurrently;
- query-level HTTP success is separate from SNMP operation success;
- `timeout_ms` is interpreted per SNMP attempt;
- duplicate targets are valid independent work items;
- operation fields are strictly validated rather than silently ignored;
- target-local operations are sequential while target requests are concurrent;
- body-size limits alone are not sufficient; execution and result limits are also required;
- response and logging models use sanitized structured errors instead of raw library errors.
- trap forwarding is best-effort and in-memory only so the service remains stateless;
- trap routing uses sender source-IP CIDRs with longest-prefix wins;
- route configuration is validated at startup before trap reception begins;
- webhook target URLs are routing internals and are not included in forwarded trap payloads.

## 16. Deferred Design Questions

These are intentionally left for a later revision because the initial idea does not determine them and the first implementation can proceed without them:

1. Whether future releases should support SNMP v3 authentication and privacy profiles.
2. Whether response values need a richer canonical encoding for opaque bytes, object identifiers, counters, or IP address types.
3. Whether global concurrency or rate limits are needed in addition to the current per-request limit.
4. Whether readiness should eventually include configurable downstream dependency checks.
5. Whether metrics should be exported through a dedicated endpoint in addition to logs.
6. Whether later trap routing should support trap OID, community, varbind values, or hostname matching.
7. Whether future releases should support multi-destination trap fan-out.
8. Whether durable trap delivery or replay across restarts is needed.
