// Package userpolicy implements opt-in per-user zero-trust routing policy.
package userpolicy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/features/routing"
)

var ErrAccessDenied = errors.New("user routing policy denied access")

// Action describes what a policy does after a user matches.
type Action string

const (
	ActionRoute Action = "route"
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	ActionDeny  Action = "deny"
)

// Policy is an ordered per-user routing rule.
type Policy struct {
	Name        string   `json:"name,omitempty"`
	User        string   `json:"user,omitempty"`
	Users       []string `json:"users,omitempty"`
	OutboundTag string   `json:"outboundTag,omitempty"`
	BalancerTag string   `json:"balancerTag,omitempty"`
	Action      Action   `json:"action,omitempty"`
}

// Config is the JSON-compatible user policy block.
type Config struct {
	Policies           []Policy `json:"policies,omitempty"`
	DefaultDeny        bool     `json:"defaultDeny,omitempty"`
	DefaultOutboundTag string   `json:"defaultOutboundTag,omitempty"`
	BlockTag           string   `json:"blockTag,omitempty"`
}

// Decision is a deterministic policy evaluation result.
type Decision struct {
	Allowed     bool
	Denied      bool
	Matched     bool
	User        string
	Action      Action
	OutboundTag string
	BalancerTag string
	BlockTag    string
	Reason      string
	PolicyName  string
}

// Table evaluates users against ordered policies.
type Table struct {
	policies           []Policy
	defaultDeny        bool
	defaultOutboundTag string
	blockTag           string
}

// NewTable validates a policy configuration and builds an immutable table.
func NewTable(config Config) (*Table, error) {
	table := &Table{
		policies:           make([]Policy, 0, len(config.Policies)),
		defaultDeny:        config.DefaultDeny,
		defaultOutboundTag: strings.TrimSpace(config.DefaultOutboundTag),
		blockTag:           strings.TrimSpace(config.BlockTag),
	}
	if table.defaultDeny && table.blockTag == "" {
		table.blockTag = "blocked"
	}

	for index, policy := range config.Policies {
		normalized, err := normalizePolicy(policy, table.blockTag)
		if err != nil {
			return nil, fmt.Errorf("userPolicies[%d]: %w", index, err)
		}
		table.policies = append(table.policies, normalized)
	}
	return table, nil
}

func normalizePolicy(policy Policy, defaultBlockTag string) (Policy, error) {
	users := make([]string, 0, len(policy.Users)+1)
	if strings.TrimSpace(policy.User) != "" {
		users = append(users, strings.TrimSpace(policy.User))
	}
	for _, user := range policy.Users {
		user = strings.TrimSpace(user)
		if user != "" {
			users = append(users, user)
		}
	}
	policy.Users = users

	switch strings.ToLower(strings.TrimSpace(string(policy.Action))) {
	case "", string(ActionRoute):
		policy.Action = ActionRoute
	case string(ActionAllow):
		policy.Action = ActionAllow
	case string(ActionBlock):
		policy.Action = ActionBlock
	case string(ActionDeny):
		policy.Action = ActionDeny
	default:
		return Policy{}, fmt.Errorf("unknown action %q", policy.Action)
	}

	if len(policy.Users) == 0 {
		return Policy{}, errors.New("policy requires user or users")
	}

	if policy.Action == ActionBlock || policy.Action == ActionDeny {
		if policy.OutboundTag == "" {
			policy.OutboundTag = defaultBlockTag
		}
		return policy, nil
	}

	if policy.Action == ActionRoute && policy.OutboundTag == "" && policy.BalancerTag == "" {
		return Policy{}, errors.New("route policy requires outboundTag or balancerTag")
	}
	return policy, nil
}

// Decide evaluates the policy table for user.
func (t *Table) Decide(user string) Decision {
	if t == nil {
		return Decision{Allowed: true, User: user, Reason: "policy table is nil"}
	}

	for _, policy := range t.policies {
		if !matchesUser(policy.Users, user) {
			continue
		}

		decision := Decision{
			Matched:     true,
			User:        user,
			Action:      policy.Action,
			OutboundTag: policy.OutboundTag,
			BalancerTag: policy.BalancerTag,
			PolicyName:  policy.Name,
		}
		if policy.Action == ActionBlock || policy.Action == ActionDeny {
			decision.Denied = true
			decision.Allowed = false
			decision.BlockTag = policy.OutboundTag
			decision.Reason = "matched blocking user policy"
			return decision
		}
		if policy.OutboundTag != "" {
			decision.Allowed = true
			decision.Reason = "matched routing user policy"
			return decision
		}
		decision.Allowed = true
		decision.Reason = "matched advisory allow policy"
		return decision
	}

	if t.defaultOutboundTag != "" {
		return Decision{
			Allowed:     true,
			User:        user,
			Action:      ActionRoute,
			OutboundTag: t.defaultOutboundTag,
			Reason:      "default user policy",
		}
	}
	if t.defaultDeny {
		return Decision{
			Denied:   true,
			User:     user,
			Action:   ActionDeny,
			BlockTag: t.blockTag,
			Reason:   "zero-trust default deny",
		}
	}
	return Decision{Allowed: true, User: user, Reason: "no user policy matched"}
}

// Route returns the fixed outbound tag for user or ErrAccessDenied.
func (t *Table) Route(user string) (string, error) {
	decision := t.Decide(user)
	if decision.Denied {
		return "", fmt.Errorf("%w: user=%q reason=%s", ErrAccessDenied, user, decision.Reason)
	}
	if decision.OutboundTag == "" {
		return "", common.ErrNoClue
	}
	return decision.OutboundTag, nil
}

func matchesUser(patterns []string, user string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if user != "" && pattern == user {
			return true
		}
	}
	return false
}

// Router applies a Table before delegating to the wrapped router.
type Router struct {
	base  routing.Router
	table *Table
}

// NewRouter wraps base with per-user policy enforcement.
func NewRouter(base routing.Router, table *Table) *Router {
	return &Router{base: base, table: table}
}

// PickRoute implements routing.Router.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	user := ""
	if ctx != nil {
		user = ctx.GetUser()
	}
	decision := r.table.Decide(user)
	if decision.Denied {
		return nil, fmt.Errorf("%w: %s", ErrAccessDenied, decision.Reason)
	}
	if decision.OutboundTag != "" && decision.BalancerTag == "" {
		return &fixedRoute{Context: ctx, outboundTag: decision.OutboundTag}, nil
	}
	if r.base == nil {
		if decision.BalancerTag != "" {
			return nil, errors.New("userpolicy: balancer policy requires base router")
		}
		return nil, common.ErrNoClue
	}
	return r.base.PickRoute(ctx)
}

// Type implements common.HasType.
func (r *Router) Type() interface{} {
	return routing.RouterType()
}

// Start implements common.Runnable.
func (r *Router) Start() error {
	if starter, ok := r.base.(interface{ Start() error }); ok {
		return starter.Start()
	}
	return nil
}

// Close implements common.Closable.
func (r *Router) Close() error {
	if closer, ok := r.base.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

type fixedRoute struct {
	routing.Context
	outboundTag string
}

func (r *fixedRoute) GetOutboundTag() string {
	return r.outboundTag
}

func (r *fixedRoute) GetOutboundGroupTags() []string {
	return nil
}

var _ routing.Router = (*Router)(nil)
