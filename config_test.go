package cerbos

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_WithDefaults(t *testing.T) {
	t.Parallel()

	t.Run("zero value gets defaults", func(t *testing.T) {
		c := Config{}.withDefaults()
		assert.Equal(t, DefaultTimeout, c.Timeout)
		assert.Equal(t, DefaultResourceKind, c.ResourceKind)
	})

	t.Run("explicit values preserved", func(t *testing.T) {
		c := Config{
			Timeout:      7 * time.Second,
			ResourceKind: "route",
		}.withDefaults()
		assert.Equal(t, 7*time.Second, c.Timeout)
		assert.Equal(t, "route", c.ResourceKind)
	})

	t.Run("negative timeout reset to default", func(t *testing.T) {
		c := Config{Timeout: -1 * time.Second}.withDefaults()
		assert.Equal(t, DefaultTimeout, c.Timeout)
	})
}

func TestConfig_ClientOptions(t *testing.T) {
	t.Parallel()

	// We can only assert the option count; the SDK Opt type is opaque.
	cases := []struct {
		name string
		cfg  Config
		want int
	}{
		{"none", Config{}, 0},
		{"plaintext", Config{Plaintext: true}, 1},
		{"tls insecure", Config{TLSInsecure: true}, 1},
		{"ca cert", Config{CACertPath: "/x"}, 1},
		{"all", Config{Plaintext: true, TLSInsecure: true, CACertPath: "/x"}, 3},
	}
	for i := range cases {
		c := &cases[i]
		t.Run(c.name, func(t *testing.T) {
			assert.Len(t, c.cfg.clientOptions(), c.want)
		})
	}
}

func TestDecodeConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil yields empty Config", func(t *testing.T) {
		c, err := decodeConfig(nil)
		require.NoError(t, err)
		assert.Equal(t, &Config{}, c)
	})

	t.Run("typed Config value", func(t *testing.T) {
		in := Config{Endpoint: "host:1", Plaintext: true}
		c, err := decodeConfig(in)
		require.NoError(t, err)
		assert.Equal(t, &in, c)
	})

	t.Run("typed Config pointer", func(t *testing.T) {
		in := &Config{Endpoint: "host:2"}
		c, err := decodeConfig(in)
		require.NoError(t, err)
		assert.Equal(t, in, c)
		// must be a copy, not the same pointer
		c.Endpoint = "mutated"
		assert.Equal(t, "host:2", in.Endpoint)
	})

	t.Run("nil typed pointer", func(t *testing.T) {
		var in *Config
		c, err := decodeConfig(in)
		require.NoError(t, err)
		assert.Equal(t, &Config{}, c)
	})

	t.Run("map shape", func(t *testing.T) {
		c, err := decodeConfig(map[string]any{
			"endpoint":       "host:3",
			"plaintext":      true,
			"resource_kind":  "route",
			"default_roles":  []any{"viewer"},
			"policy_version": "2024",
		})
		require.NoError(t, err)
		assert.Equal(t, "host:3", c.Endpoint)
		assert.True(t, c.Plaintext)
		assert.Equal(t, "route", c.ResourceKind)
		assert.Equal(t, []string{"viewer"}, c.DefaultRoles)
		assert.Equal(t, "2024", c.PolicyVersion)
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := decodeConfig(123)
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})

	t.Run("invalid map element type", func(t *testing.T) {
		// timeout expects a duration string or number; passing an object
		// triggers a JSON unmarshal error.
		_, err := decodeConfig(map[string]any{
			"timeout": map[string]any{"nope": true},
		})
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})
}
