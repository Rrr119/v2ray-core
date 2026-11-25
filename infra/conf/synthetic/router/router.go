package router

//go:generate go run github.com/v2fly/v2ray-core/v5/common/errors/errorgen

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/v2fly/v2ray-core/v5/app/router"
	"github.com/v2fly/v2ray-core/v5/app/router/userpolicy"
	"github.com/v2fly/v2ray-core/v5/common/platform"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v5/infra/conf/geodata"
	rule2 "github.com/v2fly/v2ray-core/v5/infra/conf/rule"
)

type RouterRulesConfig struct { // nolint: revive
	RuleList       []json.RawMessage `json:"rules"`
	DomainStrategy string            `json:"domainStrategy"`
}

// StrategyConfig represents a strategy config
type StrategyConfig struct {
	Type     string           `json:"type"`
	Settings *json.RawMessage `json:"settings"`
}

type BalancingRule struct {
	Tag         string               `json:"tag"`
	Selectors   cfgcommon.StringList `json:"selector"`
	Strategy    StrategyConfig       `json:"strategy"`
	FallbackTag string               `json:"fallbackTag"`
}

// Build builds the balancing rule
func (r *BalancingRule) Build() (*router.BalancingRule, error) {
	if r.Tag == "" {
		return nil, newError("empty balancer tag")
	}
	if len(r.Selectors) == 0 {
		return nil, newError("empty selector list")
	}

	var strategy string
	switch strings.ToLower(r.Strategy.Type) {
	case strategyRandom, "":
		r.Strategy.Type = strategyRandom
		strategy = strategyRandom
	case strategyLeastLoad:
		strategy = strategyLeastLoad
	case strategyLeastPing:
		strategy = "leastping"
	default:
		return nil, newError("unknown balancing strategy: " + r.Strategy.Type)
	}

	settings := []byte("{}")
	if r.Strategy.Settings != nil {
		settings = ([]byte)(*r.Strategy.Settings)
	}
	rawConfig, err := strategyConfigLoader.LoadWithID(settings, r.Strategy.Type)
	if err != nil {
		return nil, newError("failed to parse to strategy config.").Base(err)
	}
	var ts proto.Message
	if builder, ok := rawConfig.(cfgcommon.Buildable); ok {
		ts, err = builder.Build()
		if err != nil {
			return nil, err
		}
	}

	return &router.BalancingRule{
		Strategy:         strategy,
		StrategySettings: serial.ToTypedMessage(ts),
		FallbackTag:      r.FallbackTag,
		OutboundSelector: r.Selectors,
		Tag:              r.Tag,
	}, nil
}

type RouterConfig struct { // nolint: revive
	Settings       *RouterRulesConfig `json:"settings"` // Deprecated
	RuleList       []json.RawMessage  `json:"rules"`
	DomainStrategy *string            `json:"domainStrategy"`
	Balancers      []*BalancingRule   `json:"balancers"`

	UserPolicies []userpolicy.Policy `json:"userPolicies"`
	UserPolicy   *userpolicy.Config  `json:"userPolicy"`
	ZeroTrust    *ZeroTrustConfig    `json:"zeroTrust"`

	DomainMatcher string `json:"domainMatcher"`

	cfgctx context.Context
}

// ZeroTrustConfig configures the fallback decision when no user policy matches.
type ZeroTrustConfig struct {
	DefaultDeny        bool   `json:"defaultDeny"`
	BlockTag           string `json:"blockTag"`
	DefaultOutboundTag string `json:"defaultOutboundTag"`
}

// UnmarshalJSON accepts both `true` and the expanded policy object.
func (z *ZeroTrustConfig) UnmarshalJSON(data []byte) error {
	if string(data) == "true" {
		z.DefaultDeny = true
		z.BlockTag = "blocked"
		return nil
	}
	if string(data) == "false" || string(data) == "null" {
		*z = ZeroTrustConfig{}
		return nil
	}
	type plain ZeroTrustConfig
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*z = ZeroTrustConfig(decoded)
	return nil
}

func (c *RouterConfig) getDomainStrategy() router.DomainStrategy {
	ds := ""
	if c.DomainStrategy != nil {
		ds = *c.DomainStrategy
	} else if c.Settings != nil {
		ds = c.Settings.DomainStrategy
	}

	switch strings.ToLower(ds) {
	case "alwaysip", "always_ip", "always-ip":
		return router.DomainStrategy_UseIp
	case "ipifnonmatch", "ip_if_non_match", "ip-if-non-match":
		return router.DomainStrategy_IpIfNonMatch
	case "ipondemand", "ip_on_demand", "ip-on-demand":
		return router.DomainStrategy_IpOnDemand
	default:
		return router.DomainStrategy_AsIs
	}
}

func (c *RouterConfig) BuildV5(ctx context.Context) (*router.Config, error) {
	c.cfgctx = ctx
	return c.Build()
}

func (c *RouterConfig) Build() (*router.Config, error) {
	config := new(router.Config)
	config.DomainStrategy = c.getDomainStrategy()

	policyConfig := userpolicy.Config{Policies: append([]userpolicy.Policy(nil), c.UserPolicies...)}
	if c.UserPolicy != nil {
		policyConfig.Policies = append(policyConfig.Policies, c.UserPolicy.Policies...)
		policyConfig.DefaultDeny = policyConfig.DefaultDeny || c.UserPolicy.DefaultDeny
		if policyConfig.DefaultOutboundTag == "" {
			policyConfig.DefaultOutboundTag = c.UserPolicy.DefaultOutboundTag
		}
		if policyConfig.BlockTag == "" {
			policyConfig.BlockTag = c.UserPolicy.BlockTag
		}
	}
	if c.ZeroTrust != nil {
		policyConfig.DefaultDeny = policyConfig.DefaultDeny || c.ZeroTrust.DefaultDeny
		if c.ZeroTrust.BlockTag != "" {
			policyConfig.BlockTag = c.ZeroTrust.BlockTag
		}
		if c.ZeroTrust.DefaultOutboundTag != "" {
			policyConfig.DefaultOutboundTag = c.ZeroTrust.DefaultOutboundTag
		}
	}
	policyRules, err := router.RulesFromUserPolicyConfig(policyConfig)
	if err != nil {
		return nil, err
	}
	config.Rule = append(config.Rule, policyRules...)

	if c.cfgctx == nil {
		c.cfgctx = cfgcommon.NewConfigureLoadingContext(context.Background())

		geoloadername := platform.NewEnvFlag("v2ray.conf.geoloader").GetValue(func() string {
			return "standard"
		})

		if loader, err := geodata.GetGeoDataLoader(geoloadername); err == nil {
			cfgcommon.SetGeoDataLoader(c.cfgctx, loader)
		} else {
			return nil, newError("unable to create geo data loader ").Base(err)
		}
	}

	var rawRuleList []json.RawMessage
	if c != nil {
		rawRuleList = c.RuleList
		if c.Settings != nil {
			c.RuleList = append(c.RuleList, c.Settings.RuleList...)
			rawRuleList = c.RuleList
		}
	}

	for _, rawRule := range rawRuleList {
		rule, err := rule2.ParseRule(c.cfgctx, rawRule)
		if err != nil {
			return nil, err
		}

		if rule.DomainMatcher == "" {
			rule.DomainMatcher = c.DomainMatcher
		}

		config.Rule = append(config.Rule, rule)
	}
	for _, rawBalancer := range c.Balancers {
		balancer, err := rawBalancer.Build()
		if err != nil {
			return nil, err
		}
		config.BalancingRule = append(config.BalancingRule, balancer)
	}
	return config, nil
}
