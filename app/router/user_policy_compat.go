package router

import (
	"github.com/v2fly/v2ray-core/v5/app/router/userpolicy"
	"github.com/v2fly/v2ray-core/v5/common/net"
)

// RulesFromUserPolicyConfig expands per-user zero-trust policies into
// ordinary routing rules understood by older V2Ray cores and configuration
// tooling.
func RulesFromUserPolicyConfig(config userpolicy.Config) ([]*RoutingRule, error) {
	if _, err := userpolicy.NewTable(config); err != nil {
		return nil, err
	}

	rules := make([]*RoutingRule, 0, len(config.Policies)+1)
	for _, policy := range config.Policies {
		rule := &RoutingRule{}
		users := make([]string, 0, len(policy.Users)+1)
		if policy.User != "" {
			users = append(users, policy.User)
		}
		users = append(users, policy.Users...)

		catchAll := false
		for _, user := range users {
			if user == "*" {
				catchAll = true
				break
			}
			rule.UserEmail = append(rule.UserEmail, user)
		}
		if catchAll {
			rule.UserEmail = nil
			rule.Networks = []net.Network{net.Network_TCP, net.Network_UDP}
		}

		action := policy.Action
		if action == "" {
			action = userpolicy.ActionRoute
		}
		switch action {
		case userpolicy.ActionBlock, userpolicy.ActionDeny:
			tag := policy.OutboundTag
			if tag == "" {
				tag = config.BlockTag
			}
			if tag == "" {
				tag = "blocked"
			}
			rule.TargetTag = &RoutingRule_Tag{Tag: tag}
		default:
			if policy.BalancerTag != "" {
				rule.TargetTag = &RoutingRule_BalancingTag{BalancingTag: policy.BalancerTag}
			} else {
				rule.TargetTag = &RoutingRule_Tag{Tag: policy.OutboundTag}
			}
		}
		rules = append(rules, rule)
	}

	if config.DefaultOutboundTag != "" {
		rules = append(rules, &RoutingRule{
			Networks:  []net.Network{net.Network_TCP, net.Network_UDP},
			TargetTag: &RoutingRule_Tag{Tag: config.DefaultOutboundTag},
		})
	} else if config.DefaultDeny {
		blockTag := config.BlockTag
		if blockTag == "" {
			blockTag = "blocked"
		}
		rules = append(rules, &RoutingRule{
			Networks:  []net.Network{net.Network_TCP, net.Network_UDP},
			TargetTag: &RoutingRule_Tag{Tag: blockTag},
		})
	}

	return rules, nil
}
