package cerbos

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

func TestBuildPrincipal(t *testing.T) {
	t.Parallel()

	cfg := Config{}.withDefaults()

	t.Run("authenticated user", func(t *testing.T) {
		p := buildPrincipal(&evaluator.Request{
			Policy:  newPolicy(t),
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
			HTTP:    evaluator.RequestHTTP{IP: "1.2.3.4"},
		}, cfg)
		require.NotNil(t, p.Obj)
		assert.Equal(t, "u1", p.Obj.Id)

		attrs := p.Obj.Attr
		require.NotNil(t, attrs)
		assert.Equal(t, "s1", attrs["session_id"].GetStringValue())
		assert.Equal(t, "https://from.example.com", attrs["route_from"].GetStringValue())
		assert.Equal(t, "1.2.3.4", attrs["ip"].GetStringValue())
	})

	t.Run("anonymous user", func(t *testing.T) {
		p := buildPrincipal(&evaluator.Request{Policy: newPolicy(t)}, cfg)
		assert.Equal(t, anonymousPrincipalID, p.Obj.Id)
		_, hasSession := p.Obj.Attr["session_id"]
		assert.False(t, hasSession)
	})

	t.Run("default roles attached", func(t *testing.T) {
		c := Config{DefaultRoles: []string{"viewer", "tenant_a"}}.withDefaults()
		p := buildPrincipal(&evaluator.Request{Policy: newPolicy(t)}, c)
		assert.Equal(t, []string{"viewer", "tenant_a"}, p.Obj.Roles)
	})

	t.Run("policy version forwarded", func(t *testing.T) {
		c := Config{PolicyVersion: "2024-01"}.withDefaults()
		p := buildPrincipal(&evaluator.Request{Policy: newPolicy(t)}, c)
		assert.Equal(t, "2024-01", p.Obj.PolicyVersion)
	})
}

func TestBuildResource(t *testing.T) {
	t.Parallel()

	cfg := Config{}.withDefaults()

	t.Run("populates HTTP attributes", func(t *testing.T) {
		policy := newPolicy(t)
		wantID, err := policy.RouteID()
		require.NoError(t, err)

		r := buildResource(&evaluator.Request{
			Policy: policy,
			HTTP: evaluator.RequestHTTP{
				Method: "GET",
				Host:   "from.example.com",
				Path:   "/x",
				IP:     "1.2.3.4",
			},
		}, cfg)
		assert.Equal(t, DefaultResourceKind, r.Obj.Kind)
		assert.Equal(t, wantID, r.Obj.Id)

		attrs := r.Obj.Attr
		require.NotNil(t, attrs)
		assert.Equal(t, "from.example.com", attrs["host"].GetStringValue())
		assert.Equal(t, "/x", attrs["path"].GetStringValue())
		assert.Equal(t, "GET", attrs["method"].GetStringValue())
		assert.Equal(t, "1.2.3.4", attrs["ip"].GetStringValue())
		assert.True(t, attrs["client_cert_valid"].GetBoolValue())
		assert.Equal(t, "https://from.example.com", attrs["route_from"].GetStringValue())
	})

	t.Run("missing policy uses unknown id", func(t *testing.T) {
		r := buildResource(&evaluator.Request{}, cfg)
		assert.Equal(t, "unknown", r.Obj.Id)
	})

	t.Run("forwards precomputed client cert validity", func(t *testing.T) {
		invalid := false
		r := buildResource(&evaluator.Request{
			Policy:                     newPolicy(t),
			PrecomputedClientCertValid: &invalid,
		}, cfg)
		assert.False(t, r.Obj.Attr["client_cert_valid"].GetBoolValue())
	})

	t.Run("uses configured resource kind", func(t *testing.T) {
		c := Config{ResourceKind: "route"}.withDefaults()
		r := buildResource(&evaluator.Request{Policy: newPolicy(t)}, c)
		assert.Equal(t, "route", r.Obj.Kind)
	})
}

func TestCanonicalAction(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		http.MethodGet:     "read",
		http.MethodHead:    "read",
		http.MethodOptions: "read",
		http.MethodPost:    "create",
		http.MethodPut:     "update",
		http.MethodPatch:   "update",
		http.MethodDelete:  "delete",
		"WEIRDVERB":        DefaultAction,
		"":                 DefaultAction,
		"get":              "read", // case-insensitive
	}
	for method, want := range cases {
		t.Run(method+"->"+want, func(t *testing.T) {
			assert.Equal(t, want, canonicalAction(method))
		})
	}
}

func TestPrincipalRoles_DefensiveCopy(t *testing.T) {
	t.Parallel()
	original := []string{"viewer"}
	cfg := Config{DefaultRoles: original}
	got := principalRoles(cfg)
	got[0] = "mutated"
	assert.Equal(t, "viewer", cfg.DefaultRoles[0], "principalRoles must not share storage with Config")
}
