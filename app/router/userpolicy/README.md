# Per-User Zero-Trust Routing

User policies expand into ordinary V2Ray routing rules, so existing router
matching and outbound behavior remain compatible.

```json
{
  "routing": {
    "userPolicies": [
      { "user": "alice@example.com", "outboundTag": "direct" },
      { "users": ["bob@example.com", "ci@example.com"], "outboundTag": "safe-proxy" },
      { "user": "mallory@example.com", "action": "block" }
    ],
    "zeroTrust": {
      "defaultDeny": true,
      "blockTag": "blocked"
    }
  }
}
```

The standalone `Table` provides deterministic allow/deny decisions, and
`NewRouter` wraps an existing `routing.Router` for embedding use cases.
