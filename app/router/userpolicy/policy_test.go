package userpolicy_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/v2fly/v2ray-core/v5/app/router/userpolicy"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/features/routing"
)

type testRoutingContext struct {
	user string
}

func (c testRoutingContext) GetUser() string                { return c.user }
func (testRoutingContext) GetInboundTag() string            { return "in" }
func (testRoutingContext) GetSourceIPs() []net.IP           { return nil }
func (testRoutingContext) GetSourcePort() net.Port          { return 0 }
func (testRoutingContext) GetTargetIPs() []net.IP           { return nil }
func (testRoutingContext) GetTargetPort() net.Port          { return 0 }
func (testRoutingContext) GetTargetDomain() string          { return "example.com" }
func (testRoutingContext) GetNetwork() net.Network          { return net.Network_TCP }
func (testRoutingContext) GetProtocol() string              { return "https" }
func (testRoutingContext) GetAttributes() map[string]string { return nil }
func (testRoutingContext) GetSkipDNSResolve() bool          { return false }

type baseRouter struct {
	called bool
	tag    string
}

func (r *baseRouter) PickRoute(routing.Context) (routing.Route, error) {
	r.called = true
	return nil, common.ErrNoClue
}

func (r *baseRouter) Type() interface{} { return routing.RouterType() }
func (r *baseRouter) Start() error      { return nil }
func (r *baseRouter) Close() error      { return nil }

func TestTableZeroTrustDecisions(t *testing.T) {
	table, err := userpolicy.NewTable(userpolicy.Config{
		Policies: []userpolicy.Policy{
			{User: "alice@example.com", OutboundTag: "direct"},
			{Users: []string{"bots@example.com"}, OutboundTag: "bot-out"},
			{User: "denied@example.com", Action: userpolicy.ActionDeny},
		},
		DefaultDeny: true,
	})
	require.NoError(t, err)

	tag, err := table.Route("alice@example.com")
	require.NoError(t, err)
	require.Equal(t, "direct", tag)

	tag, err = table.Route("bots@example.com")
	require.NoError(t, err)
	require.Equal(t, "bot-out", tag)

	_, err = table.Route("denied@example.com")
	require.ErrorIs(t, err, userpolicy.ErrAccessDenied)

	_, err = table.Route("unknown@example.com")
	require.ErrorIs(t, err, userpolicy.ErrAccessDenied)
}

func TestPolicyRouterOverridesAndDenies(t *testing.T) {
	table, err := userpolicy.NewTable(userpolicy.Config{
		Policies: []userpolicy.Policy{
			{User: "alice@example.com", OutboundTag: "direct"},
			{User: "mallory@example.com", Action: userpolicy.ActionBlock},
		},
		DefaultDeny: true,
	})
	require.NoError(t, err)

	base := new(baseRouter)
	router := userpolicy.NewRouter(base, table)

	route, err := router.PickRoute(testRoutingContext{user: "alice@example.com"})
	require.NoError(t, err)
	require.Equal(t, "direct", route.GetOutboundTag())
	require.False(t, base.called)

	_, err = router.PickRoute(testRoutingContext{user: "mallory@example.com"})
	require.ErrorIs(t, err, userpolicy.ErrAccessDenied)

	_, err = router.PickRoute(testRoutingContext{user: "stranger@example.com"})
	require.ErrorIs(t, err, userpolicy.ErrAccessDenied)
}

func TestPolicyRouterDelegatesUnmatchedWhenNotDefaultDeny(t *testing.T) {
	table, err := userpolicy.NewTable(userpolicy.Config{
		Policies: []userpolicy.Policy{{User: "alice@example.com", Action: userpolicy.ActionAllow}},
	})
	require.NoError(t, err)

	base := new(baseRouter)
	policyRouter := userpolicy.NewRouter(base, table)
	_, err = policyRouter.PickRoute(testRoutingContext{user: "alice@example.com"})
	require.ErrorIs(t, err, common.ErrNoClue)
	require.True(t, base.called)
}

func TestInvalidPolicy(t *testing.T) {
	_, err := userpolicy.NewTable(userpolicy.Config{
		Policies: []userpolicy.Policy{{User: "alice@example.com"}},
	})
	require.Error(t, err)

	_, err = userpolicy.NewTable(userpolicy.Config{
		Policies: []userpolicy.Policy{{Users: []string{"alice@example.com"}, Action: "mystery"}},
	})
	require.Error(t, err)
}
