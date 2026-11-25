package router_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/v2fly/v2ray-core/v5/app/router"
	"github.com/v2fly/v2ray-core/v5/app/router/userpolicy"
	"github.com/v2fly/v2ray-core/v5/common"
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/session"
	routing_session "github.com/v2fly/v2ray-core/v5/features/routing/session"
)

func TestUserPoliciesDriveCoreRouter(t *testing.T) {
	rules, err := router.RulesFromUserPolicyConfig(userpolicy.Config{
		Policies: []userpolicy.Policy{
			{User: "alice@example.com", OutboundTag: "direct"},
			{Users: []string{"bob@example.com"}, OutboundTag: "safe-proxy"},
			{User: "mallory@example.com", Action: userpolicy.ActionBlock},
		},
		DefaultDeny: true,
		BlockTag:    "blocked",
	})
	require.NoError(t, err)

	coreRouter := new(router.Router)
	require.NoError(t, coreRouter.Init(context.Background(), &router.Config{Rule: rules}, nil, nil, nil))

	cases := []struct {
		user string
		tag  string
	}{
		{"alice@example.com", "direct"},
		{"bob@example.com", "safe-proxy"},
		{"mallory@example.com", "blocked"},
		{"stranger@example.com", "blocked"},
	}

	for _, tc := range cases {
		t.Run(tc.user, func(t *testing.T) {
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
				User: &protocol.MemoryUser{Email: tc.user},
			})
			ctx = session.ContextWithOutbound(ctx, &session.Outbound{
				Target: v2net.TCPDestination(v2net.DomainAddress("example.com"), 443),
			})
			route, err := coreRouter.PickRoute(routing_session.AsRoutingContext(ctx))
			require.NoError(t, err)
			require.Equal(t, tc.tag, route.GetOutboundTag())
		})
	}
}

func TestUserPoliciesPreserveExistingUserRuleSemantics(t *testing.T) {
	rule := &router.RoutingRule{
		UserEmail: []string{"legacy@example.com"},
		TargetTag: &router.RoutingRule_Tag{Tag: "legacy-out"},
	}
	coreRouter := new(router.Router)
	require.NoError(t, coreRouter.Init(context.Background(), &router.Config{Rule: []*router.RoutingRule{rule}}, nil, nil, nil))

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		User: &protocol.MemoryUser{Email: "legacy@example.com"},
	})
	ctx = session.ContextWithOutbound(ctx, &session.Outbound{
		Target: v2net.TCPDestination(v2net.DomainAddress("example.com"), 443),
	})
	route, err := coreRouter.PickRoute(routing_session.AsRoutingContext(ctx))
	require.NoError(t, err)
	require.Equal(t, "legacy-out", route.GetOutboundTag())

	unknownCtx := session.ContextWithInbound(context.Background(), &session.Inbound{
		User: &protocol.MemoryUser{Email: "other@example.com"},
	})
	unknownCtx = session.ContextWithOutbound(unknownCtx, &session.Outbound{
		Target: v2net.TCPDestination(v2net.DomainAddress("example.com"), 443),
	})
	_, err = coreRouter.PickRoute(routing_session.AsRoutingContext(unknownCtx))
	require.ErrorIs(t, err, common.ErrNoClue)
}
