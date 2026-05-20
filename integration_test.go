//go:build integration

// To run:
//   go test -tags=integration -run TestIntegration ./...
//
// Requires a working Docker daemon. The test pulls
// ghcr.io/cerbos/cerbos:dev on first run.

package cerbos

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	cerbossdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

// policyYAML is the Cerbos resource policy backing this test. It maps
// the canonical action vocabulary produced by canonicalAction() onto
// real RBAC + ABAC rules so we can prove the full request shape lands
// at the PDP intact.
const policyYAML = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: pomerium_route
  rules:
    - actions: ["read"]
      effect: EFFECT_ALLOW
      roles: ["viewer", "editor"]
      condition:
        match:
          expr: R.attr.client_cert_valid == true
    - actions: ["create", "update", "delete"]
      effect: EFFECT_ALLOW
      roles: ["editor"]
    - actions: ["*"]
      effect: EFFECT_DENY
      roles: ["*"]
      condition:
        match:
          expr: P.attr.session_id == "blocked"
`

// launchPDP spins up a real Cerbos PDP container backed by an on-disk
// policy directory populated with policyYAML, and returns a ready
// CerbosServerInstance plus its connection address.
func launchPDP(t *testing.T) (*testutil.CerbosServerInstance, string) {
	t.Helper()

	policyDir := t.TempDir()
	require.NoError(t,
		os.WriteFile(filepath.Join(policyDir, "pomerium_route.yaml"), []byte(policyYAML), 0o644),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srv, err := testutil.LaunchCerbosServer(ctx, testutil.LaunchConf{
		PolicyDir: policyDir,
		Cmd: []string{
			"server",
			"--set=storage.driver=disk",
			"--set=storage.disk.directory=/policies",
			"--set=storage.disk.watchForChanges=false",
		},
		Env: []string{"CERBOS_LOG_LEVEL=warn"},
	})
	require.NoError(t, err, "launch cerbos")
	t.Cleanup(func() { _ = srv.Stop() })

	require.NoError(t, srv.WaitForReady(ctx))
	return srv, "passthrough:///" + srv.GRPCAddr()
}

func newRealEngine(t *testing.T, addr string, cfg Config) *Engine {
	t.Helper()
	cfg.Endpoint = addr
	cfg.Plaintext = true
	cfg = cfg.withDefaults()

	client, err := cerbossdk.New(cfg.Endpoint, cfg.clientOptions()...)
	require.NoError(t, err, "new cerbos client")
	return newWithClient(cfg, client)
}

func TestIntegration_CerbosPDP(t *testing.T) {
	_, addr := launchPDP(t)

	policy := newPolicy(t)

	t.Run("viewer can read on a route with a valid cert", func(t *testing.T) {
		eng := newRealEngine(t, addr, Config{DefaultRoles: []string{"viewer"}})
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Allow.Value, "expected allow")
		assert.True(t, dec.Allow.Reasons.Has(criteria.ReasonUserOK))
	})

	t.Run("viewer denied when client cert is invalid", func(t *testing.T) {
		invalid := false
		eng := newRealEngine(t, addr, Config{DefaultRoles: []string{"viewer"}})
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy:                     policy,
			PrecomputedClientCertValid: &invalid,
			HTTP:                       evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
			Session:                    evaluator.RequestSession{ID: "s1", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value, "expected deny")
		assert.True(t, dec.Deny.Reasons.Has(criteria.ReasonUserUnauthorized))
	})

	t.Run("viewer cannot create", func(t *testing.T) {
		eng := newRealEngine(t, addr, Config{DefaultRoles: []string{"viewer"}})
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodPost, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value, "expected deny for viewer POST")
	})

	t.Run("editor can delete", func(t *testing.T) {
		eng := newRealEngine(t, addr, Config{DefaultRoles: []string{"editor"}})
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodDelete, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Allow.Value, "expected allow for editor DELETE")
	})

	t.Run("blocked session_id denies regardless of role", func(t *testing.T) {
		eng := newRealEngine(t, addr, Config{DefaultRoles: []string{"editor"}})
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "blocked", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value, "expected deny for blocked session")
	})

	t.Run("pre-check: nil request short-circuits without calling PDP", func(t *testing.T) {
		eng := newRealEngine(t, addr, Config{})
		dec, err := eng.Evaluate(t.Context(), nil)
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value)
		assert.True(t, dec.Deny.Reasons.Has(criteria.ReasonRouteNotFound))
	})

	t.Run("pre-check: missing session on private route", func(t *testing.T) {
		eng := newRealEngine(t, addr, Config{DefaultRoles: []string{"viewer"}})
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy: policy,
			HTTP:   evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value)
		assert.True(t, dec.Deny.Reasons.Has(criteria.ReasonUserUnauthenticated))
	})
}
