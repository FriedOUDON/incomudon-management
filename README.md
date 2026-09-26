# IncomUdon Management Service

This repository contains the independently deployed Management Service for
IncomUdon. It connects to a Relay's Private Control Link v1 and consumes live,
redacted lifecycle events.

## Current scope

The service consumes redacted Private Control Link lifecycle events and obtains
a current Relay state snapshot after every authenticated connection. The
following Management Plane v1 resources are implemented:

- `GET /v1/health` requires the explicit global `health.read` permission.
- `GET /v1/channels` returns only channels within the caller's `viewer` scope.
- `GET /v1/channels/{channel_id}/participants` requires `viewer` scope for the
  requested channel.
- `GET /v1/events` provides non-durable live SSE when explicitly enabled. It
  filters every event by the caller's channel role or global event permission.
- `POST /v1/service-admission-grants` issues a short-lived, self-service
  Ed25519-signed grant from the authenticated caller's exact channel ACL.
- `POST /v1/service-admission-revocations` requires the `admin` API role and
  explicit global `service_admission.revoke` permission. `200` means the Relay
  acknowledged the PCL command; `202` means it remains queued pending that ACK
  in the durable PCL command store and will be retried after reconnect or a
  Management Service restart.

The API never serves a prior connection's state after reconnecting: it returns
`503 Service Unavailable` for state resources until a fresh complete PCL
snapshot has been applied. Live SSE is not state replay: it begins after each
new subscription, ignores `Last-Event-ID`, rejects any `since` parameter, and
may lose events while a client is disconnected. Subscriber queues are bounded;
a stalled subscriber is disconnected rather than delaying the PCL or Relay.
The service does not implement replay SSE, Audit Retrieval, or recording
orchestration. Those capabilities remain separate increments so the Relay's
live media path never depends on durable management storage.

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
  permissions. Version 1 defines `health.read` and `service_admission.revoke`.
- `INCOMUDON_MANAGEMENT_API_EVENT_DELIVERY`: `disabled` (default) or `live`.
  `live` enables non-durable `GET /v1/events`; replay is intentionally not
  supported by this service.
- `INCOMUDON_MANAGEMENT_API_ACL_RELOAD_INTERVAL`: interval from `1s` through
  `1m` (default `5s`). The service atomically adopts a complete replacement of
  all three ACL CSVs only after they all validate. Removed or reduced admission
  scopes queue channel-scoped PCL revocations; disabled services queue
  `service_disabled` revocations. Replace the CSV files atomically rather than
  modifying them in place.

`management-global-permissions.csv` uses this format:

```csv
service_id,permission,enabled
health-monitor-01,health.read,true
management-admin,service_admission.revoke,true
```

The API rejects a trusted certificate that is absent from the services CSV or
mapped to a disabled service. A channel-scoped role never implies
`health.read`. Mount all CSV ACL files and the client CA read-only; protect the
server private key with the same or stricter access controls.

`INCOMUDON_MANAGEMENT_PCL_COMMAND_STORE_FILE` is mandatory durable state for
PCL revocations. Mount its parent directory read-write and persist it across
container restarts; it contains only bounded command metadata, not grants or
private keys. Keep secrets and the command-store volume separate.

## Service Admission signing

Grant issuance is disabled unless all of the following values are configured:

- `INCOMUDON_MANAGEMENT_GRANT_SIGNING_KEY_FILE`: one unencrypted Ed25519
  PKCS#8 `PRIVATE KEY` PEM block, mounted read-only.
- `INCOMUDON_MANAGEMENT_GRANT_KEY_ID`: the published Service Admission signing
  key ID.
- `INCOMUDON_MANAGEMENT_GRANT_ISSUER`: the configured JWS `iss` value.
- `INCOMUDON_MANAGEMENT_GRANT_AUDIENCE`: the Relay's configured JWS `aud`
  value.
- `INCOMUDON_MANAGEMENT_GRANT_TTL_SECONDS`: optional lifetime from `60` through
  `3600`; the default is `300`.

The API derives `svc` from the authenticated Management API client. It derives
the channel, sender, role, permissions, and interrupt priority solely from the
matching `management-channel-acl.csv` row. It never returns the signing key or
logs a compact grant. It retains a bounded in-memory index of unexpired grants
for grant-specific revocation; use a service-scoped revocation after a
Management Service restart or when grant history is unavailable.

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
  -pcl-service-id management-main \
  -pcl-command-store-file ./var/pcl-revocations.json

# Cross-host mTLS TCP
go run . \
  -pcl-transport mtls-tcp \
  -pcl-relay-address 127.0.0.1:9443 \
  -pcl-server-name relay.example.internal \
  -pcl-service-id management-main \
  -pcl-cert-file ./management-pcl/client.crt \
  -pcl-key-file ./management-pcl/client.key \
  -pcl-relay-ca-file ./management-pcl/relay-ca.crt \
  -pcl-command-store-file ./var/pcl-revocations.json
```

## License

The Management Service source is licensed under the [MIT License](LICENSE). Third-party
license texts and distribution notes are in
[`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/).
