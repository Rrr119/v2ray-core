package router_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	routerconf "github.com/v2fly/v2ray-core/v5/infra/conf/synthetic/router"
)

func TestUserPolicyJSONCompatibility(t *testing.T) {
	const raw = `{
		"domainStrategy": "AsIs",
		"userPolicies": [
			{"user": "alice@example.com", "outboundTag": "direct"},
			{"users": ["bob@example.com"], "outboundTag": "safe-proxy"},
			{"user": "mallory@example.com", "action": "block"}
		],
		"zeroTrust": {"defaultDeny": true, "blockTag": "blocked"},
		"rules": [
			{"type": "field", "domain": ["example.org"], "outboundTag": "legacy"}
		]
	}`

	var config routerconf.RouterConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &config))
	built, err := config.Build()
	require.NoError(t, err)
	require.Len(t, built.Rule, 5)

	require.Equal(t, []string{"alice@example.com"}, built.Rule[0].UserEmail)
	require.Equal(t, "direct", built.Rule[0].GetTag())
	require.Equal(t, []string{"bob@example.com"}, built.Rule[1].UserEmail)
	require.Equal(t, "safe-proxy", built.Rule[1].GetTag())
	require.Equal(t, "blocked", built.Rule[2].GetTag())
	require.Equal(t, "blocked", built.Rule[3].GetTag())
	require.Empty(t, built.Rule[3].UserEmail)
	require.Equal(t, "legacy", built.Rule[4].GetTag())
}

func TestLegacyRouterJSONRemainsValid(t *testing.T) {
	const raw = `{
		"domainStrategy": "IPIfNonMatch",
		"rules": [
			{"type": "field", "user": ["legacy@example.com"], "outboundTag": "legacy"}
		]
	}`

	var config routerconf.RouterConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &config))
	built, err := config.Build()
	require.NoError(t, err)
	require.Len(t, built.Rule, 1)
	require.Equal(t, []string{"legacy@example.com"}, built.Rule[0].UserEmail)
	require.Equal(t, "legacy", built.Rule[0].GetTag())
}

func TestZeroTrustBoolShorthand(t *testing.T) {
	var config routerconf.RouterConfig
	require.NoError(t, json.Unmarshal([]byte(`{
		"userPolicies": [{"user": "alice@example.com", "outboundTag": "direct"}],
		"zeroTrust": true
	}`), &config))
	built, err := config.Build()
	require.NoError(t, err)
	require.Len(t, built.Rule, 2)
	require.Empty(t, built.Rule[1].UserEmail)
	require.Equal(t, "blocked", built.Rule[1].GetTag())
}

func TestUserPolicyJSONRejectsInvalidRoute(t *testing.T) {
	var config routerconf.RouterConfig
	require.NoError(t, json.Unmarshal([]byte(`{
		"userPolicies": [{"user": "alice@example.com"}]
	}`), &config))
	_, err := config.Build()
	require.Error(t, err)
}
