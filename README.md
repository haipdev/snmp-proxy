# snmp-proxy

`snmp-proxy` is a stateless Go service that exposes a small authenticated JSON API for SNMP v2c operations.

It supports:

- `get`, `getnext`, `getbulk`, and `walk`
- multiple targets per request
- ordered operations per target
- SNMP v2c trap receipt with CIDR-based webhook routing
- HTTPS by default with generated local development certificates
- structured per-operation errors for partial failures

## Run locally

```bash
SNMP_PROXY_BASIC_AUTH_USERNAME=user \
SNMP_PROXY_BASIC_AUTH_PASSWORD=pass \
go run ./cmd/snmp-proxy
```

By default the service listens on `https://localhost:8443`.

## Docker

```bash
docker build -t snmp-proxy .

docker run --rm \
  -e SNMP_PROXY_BASIC_AUTH_USERNAME=user \
  -e SNMP_PROXY_BASIC_AUTH_PASSWORD=pass \
  -p 8443:8443 \
  snmp-proxy
```

## Endpoints

- `GET /healthz` - unauthenticated health check
- `GET /version` - authenticated build metadata
- `POST /api/v1/query` - authenticated SNMP query execution

Example request:

```bash
curl -k -u user:pass https://localhost:8443/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{
    "requests": [
      {
        "target": "192.0.2.10",
        "community": "public",
        "operations": [
          {
            "type": "get",
            "oids": [".1.3.6.1.2.1.1.3.0"]
          }
        ]
      }
    ]
  }'
```

Example response:

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
        }
      ]
    }
  ]
}
```

## Trap forwarding

Enable trap forwarding with a route file:

```json
{
  "routes": [
    {
      "source_cidr": "10.0.0.0/8",
      "target_url": "https://ops.example.net/traps"
    }
  ]
}
```

```bash
SNMP_PROXY_BASIC_AUTH_USERNAME=user \
SNMP_PROXY_BASIC_AUTH_PASSWORD=pass \
SNMP_PROXY_TRAP_ENABLED=true \
SNMP_PROXY_TRAP_ROUTES_FILE=routes.json \
go run ./cmd/snmp-proxy
```

Trap forwarding listens on UDP port `9162` by default. CIDR routing uses longest-prefix wins, and forwarded payloads never include the SNMP community string.


See [SPEC.md](SPEC.md) for the full behavior and configuration contract.

