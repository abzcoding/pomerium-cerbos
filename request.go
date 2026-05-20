package cerbos

import (
	"net/http"
	"strings"

	cerbossdk "github.com/cerbos/cerbos-sdk-go/cerbos"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

// buildPrincipal constructs a Cerbos principal from a Pomerium request.
//
// The principal ID is the session UserID. Anonymous (public-route)
// requests use a fixed sentinel so PDP policies can pattern-match on it
// instead of having to handle empty IDs.
//
// Session, route, and HTTP context are attached as attributes so the
// PDP can reach them from rules without Pomerium needing to know in
// advance what each policy will use.
func buildPrincipal(req *evaluator.Request, cfg Config) *cerbossdk.Principal {
	id := req.Session.UserID
	if id == "" {
		id = anonymousPrincipalID
	}

	roles := principalRoles(cfg)
	p := cerbossdk.NewPrincipal(id, roles...)
	if cfg.PolicyVersion != "" {
		p = p.WithPolicyVersion(cfg.PolicyVersion)
	}

	attrs := principalAttributes(req)
	if len(attrs) > 0 {
		p = p.WithAttributes(attrs)
	}
	return p
}

// principalRoles returns the slice of roles to attach to every
// principal. Currently this is the operator-configured DefaultRoles
// list; future versions may merge session-derived roles here.
func principalRoles(cfg Config) []string {
	if len(cfg.DefaultRoles) == 0 {
		return nil
	}
	// Defensive copy: cerbossdk.NewPrincipal stores the slice header,
	// and we do not want later mutations of cfg.DefaultRoles to leak
	// into in-flight requests.
	roles := make([]string, len(cfg.DefaultRoles))
	copy(roles, cfg.DefaultRoles)
	return roles
}

// principalAttributes extracts session and route metadata into the
// attribute map sent on the principal.
func principalAttributes(req *evaluator.Request) map[string]any {
	attrs := map[string]any{}
	if req.Session.ID != "" {
		attrs["session_id"] = req.Session.ID
	}
	if req.Policy != nil && req.Policy.From != "" {
		attrs["route_from"] = req.Policy.From
	}
	if req.HTTP.IP != "" {
		attrs["ip"] = req.HTTP.IP
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

// buildResource constructs a Cerbos resource describing the route the
// principal is attempting to access.
func buildResource(req *evaluator.Request, cfg Config) *cerbossdk.Resource {
	id := resourceID(req)
	r := cerbossdk.NewResource(cfg.ResourceKind, id)
	if cfg.PolicyVersion != "" {
		r = r.WithPolicyVersion(cfg.PolicyVersion)
	}
	r = r.WithAttributes(resourceAttributes(req))
	return r
}

// resourceID returns the Pomerium RouteID, or "unknown" when no route
// is associated (the orchestrator should have already rejected those
// requests via the route-not-found pre-check, so this is a defensive
// fallback for direct use of buildResource in tests).
func resourceID(req *evaluator.Request) string {
	if req.Policy == nil {
		return "unknown"
	}
	id, err := req.Policy.RouteID()
	if err != nil || id == "" {
		return "unknown"
	}
	return id
}

// resourceAttributes packs the HTTP context and route metadata into
// the resource's attribute map. These are the fields PDP policies are
// most likely to condition on.
func resourceAttributes(req *evaluator.Request) map[string]any {
	attrs := map[string]any{
		"host":              req.HTTP.Host,
		"path":              req.HTTP.Path,
		"method":            req.HTTP.Method,
		"ip":                req.HTTP.IP,
		"client_cert_valid": clientCertValid(req),
	}
	if req.Policy != nil && req.Policy.From != "" {
		attrs["route_from"] = req.Policy.From
	}
	return attrs
}

// canonicalAction maps an HTTP method onto a CRUD-style action name
// that aligns with the action vocabulary commonly used in Cerbos
// resource policies. Unknown methods become DefaultAction so policies
// don't have to enumerate every verb.
func canonicalAction(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "read"
	case http.MethodPost:
		return "create"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	case "":
		return DefaultAction
	default:
		return DefaultAction
	}
}

// clientCertValid returns the precomputed client-certificate validity,
// defaulting to true when the orchestrator has not stored a value
// (routes without a client-cert requirement leave it nil, matching
// OPA's "no requirement → no failure" behaviour).
func clientCertValid(req *evaluator.Request) bool {
	if req.PrecomputedClientCertValid == nil {
		return true
	}
	return *req.PrecomputedClientCertValid
}
