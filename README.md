# IncomUdon Management Service

This repository contains the independently deployed Management Service for
IncomUdon. It connects to a Relay's Private Control Link v1 listener with TLS
1.3 mutual TLS and consumes live, redacted lifecycle events.

## Current P1 scope

The initial service is a non-durable Private Control Link event consumer. It
keeps only connection health and the most recent event timestamp/type in
memory. It does not provide the full Management Plane REST API, SSE replay,
Audit Retrieval, recording orchestration, or service-admission revocation yet.
Those capabilities remain separate increments so the Relay's live media path
never depends on durable management storage.

`GET /healthz` reports process and connection state. `GET /readyz` returns 200
only while the authenticated Private Control Link session is connected. Do not
publish this listener directly; place a future management API behind its own
private mTLS or ingress boundary.

## Configuration

Copy `.env.example` into deployment configuration. The Management Service
requires its own client certificate and private key, plus the CA used to
validate the Relay certificate:

```text
management-pcl/
  client.crt
  client.key
  relay-ca.crt
```

The Relay separately receives its server certificate/key, the trusted client
CA, and `services.csv` mapping this client certificate's lowercase DER
SHA-256 digest to `INCOMUDON_MANAGEMENT_PCL_SERVICE_ID`.

The server certificate must contain the configured
`INCOMUDON_MANAGEMENT_PCL_SERVER_NAME` as a DNS SAN. In the bundled Compose
overlay, the default is `relay`.

## Container publishing

`.github/workflows/publish-image.yml` publishes the image to GitHub Container
Registry on `main` and version tags. Production deployment should pin a
released image tag, for example:

```text
ghcr.io/friedoudon/incomudon-management:v0.1.0
```

The Relay repository provides `compose.management.yaml` to run this image with
the Relay over an internal-only Docker network.

## Development

```bash
go test ./...
go run . \
  -pcl-relay-address 127.0.0.1:9443 \
  -pcl-server-name relay.example.internal \
  -pcl-service-id management-main \
  -pcl-cert-file ./management-pcl/client.crt \
  -pcl-key-file ./management-pcl/client.key \
  -pcl-relay-ca-file ./management-pcl/relay-ca.crt
```