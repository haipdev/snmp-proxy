# snmp-proxy

`snmp-proxy` is a stateless Go service that exposes a small authenticated JSON API for SNMP v2c read operations.

It supports:

- `get`, `getnext`, `getbulk`, and `walk`
- multiple targets per request
- ordered operations per target
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

See [SPEC.md](SPEC.md) for the full behavior and configuration contract.
