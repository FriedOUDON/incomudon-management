# IncomUdon Management Service

This repository contains the independently deployed Management Service for
IncomUdon. It connects to a Relay's Private Control Link v1 and consumes live,
redacted lifecycle events.

## Current scope

The service consumes redacted Private Control Link lifecycle events and obtains
a current Relay state snapshot after every authenticated connection. The
following non-durable, read-only Management Plane v1 resources are implemented:

- `GET /v1/health` requires the explicit global `health.read` permission.
- `GET /v1/channels` returns only channels within the caller's `viewer` scope.
- `GET /v1/channels/{channel_id}/participants` requires `viewer` scope for the
  requested channel.

The API never serves a prior connection's state after reconnecting: it returns
`503 Service Unavailable` for state resources until a fresh complete PCL
snapshot has been applied. It does not implement SSE delivery, Audit Retrieval,
recording orchestration, Service Admission grant issuance, or revocation yet.
Those capabilities remain separate increments so the Relay's live media path
never depends on durable management storage.

`GET /healthz` and `GET /readyz` remain local process probes. `readyz` returns
200 only after an authenticated PCL session has applied a current snapshot.
Do not publish this listener directly.

## Management API mTLS and ACLs

The external API is disabled unless `INCOMUDON_MANAGEMENT_API_LISTEN` (or
`-api-listen`) is set. When enabled, it always requires TLS 1.3 mutual TLS and
all of the following configuration values:

- `INCOMUDON_MANAGEMENT_API_CERT_FILE` and
  `INCOMUDON_MANAGEMENT_API_KEY_FILE`: server certificate and private key.
- `INCOMUDON_MANAGEMENT_API_CLIENT_CA_FILE`: trusted client CA bundle.
- `INCOMUDON_MANAGEMENT_API_SERVICES_FILE`: canonical
  `management-services.csv`, which maps each DER certificate SHA-256
  fingerprint to exactly one service and API role.
- `INCOMUDON_MANAGEMENT_API_CHANNEL_ACL_FILE`: canonical
  `management-channel-acl.csv`, which supplies exact channel scopes.
- `INCOMUDON_MANAGEMENT_API_GLOBAL_PERMISSIONS_FILE`: canonical
  `management-global-permissions.csv`, which grants explicit global
  permissions. Version 1 currently defines only `health.read`.

`management-global-permissions.csv` uses this format:

```csv
service_id,permission,enabled
health-monitor-01,health.read,true
```

The API rejects a trusted certificate that is absent from the services CSV or
mapped to a disabled service. A channel-scoped role never implies
`health.read`. Mount all CSV ACL files and the client CA read-only; protect the
server private key with the same or stricter access controls.

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
