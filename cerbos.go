// Package cerbos implements a Pomerium PolicyEngine that delegates
// per-request access decisions to a Cerbos Policy Decision Point over
// the Cerbos gRPC API.
//
// It is an out-of-tree adapter: it registers itself with the Pomerium
// engine registry at import time, so a custom Pomerium binary picks it
// up via a blank import alongside the standard build. Operators select
// it by setting:
//
//	policy_engine: cerbos
//	external_policy_engine:
//	  endpoint: localhost:3593
//	  plaintext: true
//	runtime_flags:
//	  external_policy_engine: true
//
// See README.md for the full integration guide.
package cerbos

import (
	"context"
	"errors"
	"fmt"

	cerbossdk "github.com/cerbos/cerbos-sdk-go/cerbos"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/engine"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

// Kind is the engine kind registered with Pomerium.
const Kind engine.Kind = "cerbos"

// Sentinel errors returned by the package.
var (
	// ErrMissingEndpoint indicates that Config.Endpoint was not set.
	ErrMissingEndpoint = errors.New("cerbos: endpoint is required")
	// ErrInvalidConfig indicates an unsupported or malformed engine
	// config blob.
	ErrInvalidConfig = errors.New("cerbos: invalid configuration")
	// ErrPDPRequest indicates a transport-level failure talking to the
	// Cerbos PDP. The orchestrator translates this into a 5xx response;
	// the engine never silently denies on transport failures.
	ErrPDPRequest = errors.New("cerbos: PDP request failed")
)

// cerbosClient is the small subset of the Cerbos Go SDK the engine
// depends on. Defining it locally keeps the engine testable without a
// running PDP: tests inject a fake implementation, production code uses
// *cerbossdk.GRPCClient.
type cerbosClient interface {
	IsAllowed(
		ctx context.Context,
		principal *cerbossdk.Principal,
		resource *cerbossdk.Resource,
		action string,
	) (bool, error)
}

// Engine is a Pomerium PolicyEngine backed by a Cerbos PDP.
type Engine struct {
	cfg    Config
	client cerbosClient
}

// Compile-time assertion that *Engine satisfies engine.PolicyEngine.
var _ engine.PolicyEngine = (*Engine)(nil)

// New creates a new Engine using a real Cerbos gRPC client built from
// cfg. Defaults are applied to cfg before the client is constructed.
//
// New does not block on PDP availability; the underlying connection is
// lazily established by the SDK on first use.
func New(cfg Config) (*Engine, error) {
	cfg = cfg.withDefaults()
	if cfg.Endpoint == "" {
		return nil, ErrMissingEndpoint
	}
	client, err := cerbossdk.New(cfg.Endpoint, cfg.clientOptions()...)
	if err != nil {
		return nil, fmt.Errorf("cerbos: new client: %w", err)
	}
	return newWithClient(cfg, client), nil
}

// newWithClient is the test seam used to inject a fake cerbosClient.
// Defaults are NOT re-applied: callers (New and the tests) pass an
// already-defaulted Config.
func newWithClient(cfg Config, client cerbosClient) *Engine {
	return &Engine{cfg: cfg, client: client}
}

// Evaluate runs the orchestrator-mandated local pre-checks and, when
// none apply, delegates the access decision to the Cerbos PDP.
func (e *Engine) Evaluate(ctx context.Context, req *evaluator.Request) (*engine.Decision, error) {
	if dec, ok := preCheck(req); ok {
		return dec, nil
	}
	return e.callPDP(ctx, req)
}

// Close is a no-op. The underlying SDK client manages its own gRPC
// connection lifecycle and exposes no Close method.
func (e *Engine) Close() error { return nil }

// callPDP performs the single-resource IsAllowed call against the
// configured PDP and translates the boolean verdict into the Pomerium
// engine.Decision shape.
func (e *Engine) callPDP(ctx context.Context, req *evaluator.Request) (*engine.Decision, error) {
	principal := buildPrincipal(req, e.cfg)
	resource := buildResource(req, e.cfg)
	action := canonicalAction(req.HTTP.Method)

	if e.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.cfg.Timeout)
		defer cancel()
	}

	allowed, err := e.client.IsAllowed(ctx, principal, resource, action)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPDPRequest, err)
	}
	if allowed {
		return allow(criteria.ReasonUserOK), nil
	}
	return deny(criteria.ReasonUserUnauthorized), nil
}

// preCheck returns a Decision and true when the request can be answered
// without consulting the PDP. The reasons it emits drive Pomerium's
// special-case flows (route-not-found, internal route, login redirect),
// which the engine cannot delegate away.
func preCheck(req *evaluator.Request) (*engine.Decision, bool) {
	switch {
	case req == nil:
		return deny(criteria.ReasonRouteNotFound), true
	case req.IsInternal:
		return allow(criteria.ReasonPomeriumRoute), true
	case req.Policy == nil:
		return deny(criteria.ReasonRouteNotFound), true
	case req.Session.ID == "" && !req.Policy.AllowPublicUnauthenticatedAccess:
		return deny(criteria.ReasonUserUnauthenticated), true
	}
	return nil, false
}

func allow(reasons ...criteria.Reason) *engine.Decision {
	return &engine.Decision{
		Allow: evaluator.NewRuleResult(true, reasons...),
		Deny:  evaluator.NewRuleResult(false),
	}
}

func deny(reasons ...criteria.Reason) *engine.Decision {
	return &engine.Decision{
		Allow: evaluator.NewRuleResult(false),
		Deny:  evaluator.NewRuleResult(true, reasons...),
	}
}

func init() {
	engine.Register(Kind, true, factory)
}

// factory is the registry callback that builds a Cerbos engine from a
// raw FactoryConfig blob.
func factory(cfg engine.FactoryConfig) (engine.PolicyEngine, error) {
	c, err := decodeConfig(cfg.EngineConfig)
	if err != nil {
		return nil, err
	}
	return New(*c)
}
