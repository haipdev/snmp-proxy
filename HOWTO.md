# snmp-proxy HOWTO

This guide shows how to call `POST /api/v1/query` for each supported SNMP read operation.

All examples use SNMP v2c for brevity:

```json
{
  "target": "192.0.2.10",
  "community": "public"
}
```

For SNMP v1, add `version: "1"` and keep the community string. SNMP v1 supports `get`, `getnext`, and `walk`, but not `getbulk`.

For SNMP v3, replace `community` with `version: "3"` and a `v3` credential block:

```json
{
  "target": "192.0.2.10",
  "version": "3",
  "v3": {
    "username": "monitor",
    "security_level": "authPriv",
    "auth_protocol": "sha256",
    "auth_passphrase": "auth-secret",
    "priv_protocol": "aes",
    "priv_passphrase": "priv-secret"
  }
}
```

Unless provided, `port` defaults to `161`, `timeout_ms` uses the configured service default, and `retries` uses the configured service default. OIDs may be sent with or without a leading dot; responses always normalize them to a leading-dot form.

## `get`

Use `get` when you already know the exact OID instance you want to read.

Request:

```json
{
  "requests": [
    {
      "target": "192.0.2.10",
      "community": "public",
      "operations": [
        {
          "type": "get",
          "oids": [
            ".1.3.6.1.2.1.1.3.0",
            ".1.3.6.1.2.1.1.5.0"
          ]
        }
      ]
    }
  ]
}
```

Response:

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
            },
            {
              "oid": ".1.3.6.1.2.1.1.5.0",
              "type": "OctetString",
              "value": "switch-a"
            }
          ]
        }
      ]
    }
  ]
}
```

## `getnext`

Use `getnext` when you want the next OID after a known OID. This is useful for stepping through a MIB tree.

Request:

```json
{
  "requests": [
    {
      "target": "192.0.2.10",
      "community": "public",
      "operations": [
        {
          "type": "getnext",
          "oids": [
            ".1.3.6.1.2.1.1.3.0"
          ]
        }
      ]
    }
  ]
}
```

Response:

```json
{
  "results": [
    {
      "target": "192.0.2.10",
      "port": 161,
      "operations": [
        {
          "type": "getnext",
          "status": "ok",
          "values": [
            {
              "oid": ".1.3.6.1.2.1.1.4.0",
              "type": "OctetString",
              "value": "noc@example.net"
            }
          ]
        }
      ]
    }
  ]
}
```

## `getbulk`

Use `getbulk` when you want several following OIDs efficiently, usually for table-like data. If `max_repetitions` is omitted, it defaults to `10`.

Request:

```json
{
  "requests": [
    {
      "target": "192.0.2.10",
      "community": "public",
      "operations": [
        {
          "type": "getbulk",
          "oids": [
            ".1.3.6.1.2.1.2.2.1.2"
          ],
          "non_repeaters": 0,
          "max_repetitions": 3
        }
      ]
    }
  ]
}
```

Response:

```json
{
  "results": [
    {
      "target": "192.0.2.10",
      "port": 161,
      "operations": [
        {
          "type": "getbulk",
          "status": "ok",
          "values": [
            {
              "oid": ".1.3.6.1.2.1.2.2.1.2.1",
              "type": "OctetString",
              "value": "lo"
            },
            {
              "oid": ".1.3.6.1.2.1.2.2.1.2.2",
              "type": "OctetString",
              "value": "eth0"
            },
            {
              "oid": ".1.3.6.1.2.1.2.2.1.2.3",
              "type": "OctetString",
              "value": "eth1"
            }
          ]
        }
      ]
    }
  ]
}
```

## `walk`

Use `walk` when you want every OID under a subtree. `walk` uses `root_oid` instead of `oids`.

Request:

```json
{
  "requests": [
    {
      "target": "192.0.2.10",
      "community": "public",
      "operations": [
        {
          "type": "walk",
          "root_oid": ".1.3.6.1.2.1.2.2.1.2"
        }
      ]
    }
  ]
}
```

Response:

```json
{
  "results": [
    {
      "target": "192.0.2.10",
      "port": 161,
      "operations": [
        {
          "type": "walk",
          "status": "ok",
          "values": [
            {
              "oid": ".1.3.6.1.2.1.2.2.1.2.1",
              "type": "OctetString",
              "value": "lo"
            },
            {
              "oid": ".1.3.6.1.2.1.2.2.1.2.2",
              "type": "OctetString",
              "value": "eth0"
            },
            {
              "oid": ".1.3.6.1.2.1.2.2.1.2.3",
              "type": "OctetString",
              "value": "eth1"
            }
          ]
        }
      ]
    }
  ]
}
```

## Error response example

A query request can still return HTTP `200 OK` when an SNMP operation fails. The failure is represented on that operation:

```json
{
  "results": [
    {
      "target": "192.0.2.10",
      "port": 161,
      "operations": [
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

Common operation error codes include `timeout`, `dns_error`, `connection_error`, `snmp_error`, `decode_error`, `result_limit_exceeded`, and `internal_error`.
