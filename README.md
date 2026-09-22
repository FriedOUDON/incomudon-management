# IncomUdon Management Service

This repository contains the independently deployed Management Service for
IncomUdon. It connects to a Relay's Private Control Link v1 and consumes live,
redacted lifecycle events.

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

## Private Control Link transport

The client selects exactly one Private Control Link transport. It never falls
back automatically between transports.

### Same-host UDS profile

Use `INCOMUDON_MANAGEMENT_PCL_TRANSPORT=uds` and an absolute
`INCOMUDON_MANAGEMENT_PCL_UDS_SOCKET_PATH`. This is the standard profile for
the Relay repository's bundled Compose overlay. TLS material is not used for
this profile: the Relay authenticates the client with Linux `SO_PEERCRED` and a
local UID-to-service-ID policy. The `INCOMUDON_MANAGEMENT_PCL_SERVICE_ID` sent
in `hello` must exactly match that Relay-side mapping.

The socket volume must be shared read-write so the client can connect, but the
Management Service must not have write access to the socket's parent directory.
The bundled overlay runs this service as UID `10002` with supplementary group
`10003`; configure the Relay's `uds-services.csv` accordingly.

### Cross-host mTLS TCP profile

Use `INCOMUDON_MANAGEMENT_PCL_TRANSPORT=mtls-tcp` when the Management Service
is on another host. It requires a Relay address, TLS server name, client
certificate, client private key, and trusted Relay CA. The Relay maps the
verified client certificate to `INCOMUDON_MANAGEMENT_PCL_SERVICE_ID` using its
separate PCL authorization policy.

## Container publishing

`.github/workflows/publish-image.yml` publishes the image to GitHub Container
Registry on `main` and version tags. Production deployment should pin a
released image tag, for example:

```text
ghcr.io/friedoudon/incomudon-management:v0.1.0
```

The Relay repository provides `compose.management.yaml` to run this image with
the Relay through a local UDS volume.

## Development

```bash
# Same-host UDS
go run . \
  -pcl-transport uds \
  -pcl-uds-socket-path /run/incomudon-pcl/relay.sock \
  -pcl-service-id management-main

# Cross-host mTLS TCP
go run . \
  -pcl-transport mtls-tcp \
  -pcl-relay-address 127.0.0.1:9443 \
  -pcl-server-name relay.example.internal \
  -pcl-service-id management-main \
  -pcl-cert-file ./management-pcl/client.crt \
  -pcl-key-file ./management-pcl/client.key \
  -pcl-relay-ca-file ./management-pcl/relay-ca.crt
```
