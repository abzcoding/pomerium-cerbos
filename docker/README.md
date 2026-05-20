# Demo docker-compose stack

This directory wires up the three things needed to prove the Cerbos
engine end-to-end:

| Service     | Image                          | Role                                    |
|-------------|--------------------------------|-----------------------------------------|
| `cerbos`    | `ghcr.io/cerbos/cerbos:dev`    | Cerbos PDP, policies bind-mounted in    |
| `upstream`  | `hashicorp/http-echo`          | Trivial backend that proves routing     |
| `pomerium`  | `debian:bookworm-slim` + bind-mounted binary | Custom Pomerium with the plugin baked in (glibc required for embedded envoy) |

The Pomerium binary is bind-mounted from the host rather than baked
into a custom image so this folder remains buildable without a
Dockerfile.

## Run it

From the repository root:

```bash
CGO_ENABLED=0 go build -o docker/pomerium-cerbos ./cmd/pomerium-cerbos
docker compose -f docker/compose.yaml up --wait
```

Send a request through the proxy:

```bash
# allow.localhost is permitted by the Cerbos policy
curl -i -H 'Host: allow.localhost' http://127.0.0.1:9080/
# expect: 200 OK, body "hello-from-upstream"

# deny.localhost is rejected by the default-deny rule
curl -i -H 'Host: deny.localhost' http://127.0.0.1:9080/
# expect: 403 Forbidden

# /forbidden is rejected on any host
curl -i -H 'Host: allow.localhost' http://127.0.0.1:9080/forbidden
# expect: 403 Forbidden
```

Tear down:

```bash
docker compose -f docker/compose.yaml down -v
```

## Automated test

The same flow is exercised by [docker_compose_test.go](../docker_compose_test.go),
gated by the `dockercompose` build tag:

```bash
go test -tags=dockercompose -run TestDockerCompose -v -timeout=300s ./...
```

It builds the binary, brings up the stack, asserts the allow / deny /
path-forbidden cases, and tears the stack back down.

## Files

- `compose.yaml` — service definitions and bind mounts.
- `pomerium-config.yaml` — minimal Pomerium config with
  `policy_engine: cerbos`, two public routes, and the runtime flag
  required by the SPI.
- `cerbos-policies/pomerium_route.yaml` — resource policy that pattern-
  matches on the `host` and `path` attributes the adapter forwards.

Do not use the secrets in `pomerium-config.yaml` for anything outside
this demo: they are checked-in fixed values to keep the test
deterministic.
