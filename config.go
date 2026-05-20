package cerbos

import (
	"encoding/json"
	"fmt"
	"time"

	cerbossdk "github.com/cerbos/cerbos-sdk-go/cerbos"
)

// Default values used by New when the operator leaves fields unset.
const (
	DefaultTimeout      = 2 * time.Second
	DefaultResourceKind = "pomerium_route"
	DefaultSubjectKind  = "user"
	DefaultAction       = "can_access"

	anonymousPrincipalID = "anonymous"
)

// Config configures the Cerbos engine.
//
// It is the shape Pomerium's config layer unmarshals the
// external_policy_engine YAML block into. JSON and mapstructure tags
// match Pomerium's existing options conventions so the same struct can
// be consumed either way.
type Config struct {
	// Endpoint is the address of the Cerbos PDP, in any form the SDK
	// understands ("host:port", "unix:/path/to/sock", "passthrough:///…").
	Endpoint string `json:"endpoint" mapstructure:"endpoint"`

	// Plaintext disables TLS on the gRPC connection. Use only when the
	// PDP lives in the same network segment as Pomerium.
	Plaintext bool `json:"plaintext" mapstructure:"plaintext"`

	// TLSInsecure skips PDP certificate verification. Equivalent to
	// passing cerbos.WithTLSInsecure() to the SDK.
	TLSInsecure bool `json:"tls_insecure" mapstructure:"tls_insecure"`

	// CACertPath, when set, is loaded as the PDP's trusted CA bundle.
	CACertPath string `json:"ca_cert" mapstructure:"ca_cert"`

	// Timeout bounds each evaluation call's gRPC context. Defaults to
	// DefaultTimeout. It is applied to outbound calls by the engine via
	// context.WithTimeout.
	Timeout time.Duration `json:"timeout" mapstructure:"timeout"`

	// ResourceKind is the Cerbos resource.kind sent with every check.
	// Defaults to DefaultResourceKind. Operators override it to match
	// the kind used in their resource policies.
	ResourceKind string `json:"resource_kind" mapstructure:"resource_kind"`

	// PolicyVersion is the Cerbos policy version. Empty leaves the SDK
	// to send "default" (the Cerbos PDP's own default).
	PolicyVersion string `json:"policy_version" mapstructure:"policy_version"`

	// DefaultRoles is attached to every principal in addition to any
	// roles inferred from the session. Useful when the PDP requires at
	// least one role on every principal.
	DefaultRoles []string `json:"default_roles" mapstructure:"default_roles"`
}

// withDefaults returns a copy of c with zero-valued fields populated
// from the package defaults.
func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.ResourceKind == "" {
		c.ResourceKind = DefaultResourceKind
	}
	return c
}

// clientOptions converts the connection-related fields on Config into
// the SDK option slice consumed by cerbos.New.
func (c Config) clientOptions() []cerbossdk.Opt {
	opts := make([]cerbossdk.Opt, 0, 3)
	if c.Plaintext {
		opts = append(opts, cerbossdk.WithPlaintext())
	}
	if c.TLSInsecure {
		opts = append(opts, cerbossdk.WithTLSInsecure())
	}
	if c.CACertPath != "" {
		opts = append(opts, cerbossdk.WithTLSCACert(c.CACertPath))
	}
	return opts
}

// decodeConfig converts an opaque engine config blob into a *Config.
//
// Supported shapes:
//   - nil               → defaults only (caller still gets ErrMissingEndpoint)
//   - *Config / Config  → used directly
//   - map[string]any    → JSON-round-tripped into Config (matches mapstructure)
func decodeConfig(raw any) (*Config, error) {
	switch v := raw.(type) {
	case nil:
		c := Config{}
		return &c, nil
	case *Config:
		if v == nil {
			c := Config{}
			return &c, nil
		}
		c := *v
		return &c, nil
	case Config:
		c := v
		return &c, nil
	case map[string]any:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("%w: marshal: %w", ErrInvalidConfig, err)
		}
		c := Config{}
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("%w: unmarshal: %w", ErrInvalidConfig, err)
		}
		return &c, nil
	default:
		return nil, fmt.Errorf("%w: unsupported config type %T", ErrInvalidConfig, raw)
	}
}
