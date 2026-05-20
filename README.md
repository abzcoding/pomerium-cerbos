# pomerium-cerbos

An out-of-tree [Pomerium](https://github.com/pomerium/pomerium)
`PolicyEngine` that delegates per-request access decisions to a
[Cerbos](https://cerbos.dev) Policy Decision Point over the native
Cerbos gRPC API.

It plugs into Pomerium's [external policy engine
SPI](https://github.com/pomerium/pomerium/blob/main/docs/external-policy-engine.md)
via init-time registration. Pomerium's built-in AuthZEN engine can already
talk to Cerbos's AuthZEN endpoint, but the native API gives access to
Cerbos's richer attribute model and policy-version semantics, so this
adapter exists for operators who want the full Cerbos request shape.

## Usage

This module is meant to be consumed by a small custom Pomerium binary
that adds a blank import:

```go
// cmd/pomerium-with-cerbos/main.go
package main

import (
    _ "github.com/abzcoding/pomerium-cerbos" // registers the "cerbos" engine
    // …same imports as cmd/pomerium/main.go
)

func main() {
    // …same body as cmd/pomerium/main.go
}
```

Then point Pomerium at the Cerbos PDP:

```yaml
policy_engine: cerbos
external_policy_engine:
  endpoint: localhost:3593         # any cerbos.New() address form
  plaintext: true                  # disable TLS for local/in-cluster PDPs
  # tls_insecure: false            # skip cert verification
  # ca_cert: /etc/cerbos/ca.crt    # trusted CA bundle
  timeout: 2s                      # per-call deadline
  resource_kind: pomerium_route    # cerbos resource.kind
  policy_version: default          # cerbos policy version, optional
  default_roles: ["pomerium_user"] # attached to every principal
runtime_flags:
  external_policy_engine: true
```

The runtime flag is required by Pomerium's SPI for any non-OPA engine.

## Request shape

Each authorize check becomes one Cerbos `IsAllowed` call:

| Cerbos field                        | Source                                                   |
|-------------------------------------|----------------------------------------------------------|
| `principal.id`                      | `Session.UserID` (or `"anonymous"`)                      |
| `principal.roles`                   | `default_roles`                                          |
| `principal.policy_version`          | `policy_version`                                         |
| `principal.attr.session_id`         | `Session.ID`                                             |
| `principal.attr.route_from`         | `Policy.From`                                            |
| `principal.attr.ip`                 | `HTTP.IP`                                                |
| `resource.kind`                     | `resource_kind`                                          |
| `resource.id`                       | `Policy.RouteID()`                                       |
| `resource.attr.{host,path,method,ip}` | from `HTTP`                                            |
| `resource.attr.client_cert_valid`   | `PrecomputedClientCertValid`                             |
| `resource.attr.route_from`          | `Policy.From`                                            |
| `action`                            | HTTP method, mapped to `read`/`create`/`update`/`delete`/`can_access` |

## Pre-checks (run locally)

| Condition                                       | Decision                                              |
|-------------------------------------------------|-------------------------------------------------------|
| `req == nil` or `req.Policy == nil`             | Deny + `ReasonRouteNotFound`                          |
| `req.IsInternal`                                | Allow + `ReasonPomeriumRoute`                         |
| `req.Session.ID == ""` (and route not public)   | Deny + `ReasonUserUnauthenticated` (→ login redirect) |

The PDP is consulted only after these are evaluated. Login/WebAuthn
flows continue to work even when the PDP is unreachable.

## Verdict translation

| PDP response                                 | engine.Decision                            |
|----------------------------------------------|--------------------------------------------|
| `IsAllowed` returns `true`                   | Allow + `criteria.ReasonUserOK`            |
| `IsAllowed` returns `false`                  | Deny + `criteria.ReasonUserUnauthorized`   |
| transport error / context deadline           | `ErrPDPRequest` (orchestrator returns 5xx) |

The engine never silently allows on failure.

## Example resource policy

```yaml
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: pomerium_route
  rules:
    - actions: [read]
      effect: EFFECT_ALLOW
      roles: [pomerium_user]
      condition:
        match:
          expr: R.attr.client_cert_valid == true
    - actions: [create, update, delete]
      effect: EFFECT_ALLOW
      roles: [pomerium_user]
      condition:
        match:
          expr: P.attr.session_id != ""
```

## Development

```bash
go test ./...                                            # unit tests, no daemon required
go test -tags=integration -timeout=120s ./...            # spins up a real Cerbos PDP in Docker
go test -tags=dockercompose -timeout=300s ./...          # full Pomerium + Cerbos + upstream stack
go vet ./...
```

Three layers of tests:

1. **Unit tests** use a hand-rolled stub for the small `cerbosClient`
   interface so they are hermetic and fast.
2. **`integration` tag** spins up a real Cerbos PDP in Docker
   (`ghcr.io/cerbos/cerbos:dev`) via
   `github.com/cerbos/cerbos-sdk-go/testutil` and exercises the engine
   against it.
3. **`dockercompose` tag** builds the custom Pomerium binary
   (`cmd/pomerium-cerbos`), brings up the full stack from
   [`docker/compose.yaml`](docker/compose.yaml) (Cerbos + Pomerium +
   `hashicorp/http-echo` upstream), and verifies that HTTP requests
   routed through Pomerium honour the Cerbos PDP's decisions end to end.

See [`docker/README.md`](docker/README.md) for how to run the demo
stack by hand.

The `go.mod` carries a `replace` directive that points at a sibling
checkout of Pomerium during local development. Remove it before tagging
a release against a published Pomerium version.

## AI usage disclosure

The initial draft of this adapter was written with the help of
[Amp](https://ampcode.com) (Anthropic Claude). All code has been
reviewed and is maintained by a human author. The implementation
follows the public Pomerium external-policy-engine SPI and the public
Cerbos Go SDK.
